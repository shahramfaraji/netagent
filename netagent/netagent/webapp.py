"""Optional local web UI/API for netagent. Operational endpoints are token-gated."""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .collector import ConfigStore, fetch
from .credentials import Credential
from .discovery import discover, expand_targets
from .models import load_inventory
from .evidence import load_evidence
from .reporting import build_json_report, render_json_report
from .stig_assessment import DeviceContext, evaluate_rule_levels, load_approved_rules, load_waivers

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "web" / "static"
DATA_DIR = Path(os.environ.get("NETAGENT_DATA_DIR", str(PROJECT_ROOT / "data"))).resolve()
APP = FastAPI(title="netagent", version="0.1.0", docs_url="/api/docs", redoc_url=None)
APP.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class DiscoverRequest(BaseModel):
    cidr: str = Field(min_length=1, max_length=64)


class BackupRequest(BaseModel):
    inventory: str = Field(min_length=1, max_length=128)
    device: str = Field(min_length=1, max_length=63)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)
    secret: str = Field(default="", max_length=512)


class AssessRequest(BaseModel):
    inventory: str = Field(min_length=1, max_length=128)
    device: str = Field(min_length=1, max_length=63)


def _inventory_path(key: str) -> Path:
    """Only allow inventory JSON files inside the project examples/root."""
    if not key or Path(key).is_absolute() or ".." in Path(key).parts:
        raise HTTPException(status_code=400, detail="Invalid inventory selection")
    candidate = (PROJECT_ROOT / key).resolve()
    allowed_roots = [(PROJECT_ROOT / "examples").resolve(), PROJECT_ROOT.resolve()]
    if not any(candidate == root or root in candidate.parents for root in allowed_roots):
        raise HTTPException(status_code=400, detail="Inventory must be inside the project")
    if candidate.suffix.lower() != ".json" or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Inventory file not found")
    if candidate.name not in {"inventory.json", "mikrotik-inventory.json"} and not candidate.name.endswith("-inventory.json"):
        raise HTTPException(status_code=400, detail="Unsupported inventory file")
    return candidate


def _inventory_options() -> list[dict[str, str]]:
    candidates = [PROJECT_ROOT / "inventory.json", *(PROJECT_ROOT / "examples").glob("*inventory*.json")]
    options = []
    for path in candidates:
        if path.is_file():
            options.append({"id": path.relative_to(PROJECT_ROOT).as_posix(),
                            "label": path.relative_to(PROJECT_ROOT).as_posix()})
    return sorted(options, key=lambda item: item["id"])


def _require_operator_token(x_netagent_token: str | None = Header(default=None)) -> None:
    expected = os.environ.get("NETAGENT_WEB_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Operational API disabled: set NETAGENT_WEB_TOKEN before starting the web server")
    if not x_netagent_token or not hmac.compare_digest(x_netagent_token, expected):
        raise HTTPException(status_code=401, detail="Operator token is missing or invalid")


@APP.get("/", include_in_schema=False)
def index() -> HTMLResponse:
    page = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    page = page.replace("</head>", '<link rel="stylesheet" href="/static/style.css"></head>')
    script_tag = "<" + 'script src="/static/app.js" defer>' + "<" + "/script>"
    page = page.replace("</body>", script_tag + "</body>")
    return HTMLResponse(page)


@APP.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "netagent-web", "version": "0.1.0"}


@APP.get("/api/inventories")
def inventories() -> dict[str, Any]:
    return {"items": _inventory_options()}


@APP.get("/api/summary")
def summary(inventory: str = Query(default="examples/inventory.json")) -> dict[str, Any]:
    path = _inventory_path(inventory)
    try:
        devices = load_inventory(path)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Could not load inventory: {type(exc).__name__}") from None

    device_rows = []
    config_root = DATA_DIR / "configs"
    for device in devices:
        latest = config_root / device.hostname / "latest.cfg"
        versions = list((config_root / device.hostname).glob("*.cfg")) if (config_root / device.hostname).is_dir() else []
        device_rows.append({
            "hostname": device.hostname,
            "host": device.host,
            "platform": device.platform,
            "role": device.role,
            "port": device.port,
            "has_backup": latest.is_file(),
            "backup_modified": latest.stat().st_mtime if latest.is_file() else None,
            "backup_bytes": latest.stat().st_size if latest.is_file() else 0,
            "version_count": len(versions),
        })
    return {
        "inventory": inventory,
        "device_count": len(device_rows),
        "backup_count": sum(1 for row in device_rows if row["has_backup"]),
        "devices": device_rows,
    }


@APP.get("/api/reports")
def reports() -> dict[str, Any]:
    roots = [PROJECT_ROOT / "reports", DATA_DIR / "reports", DATA_DIR / "assessments"]
    items = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".md", ".html", ".json"}:
                continue
            try:
                relative = path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
            except ValueError:
                # A custom DATA_DIR can live outside the repository; expose only a basename ID.
                relative = f"external:{path.name}"
            if relative in seen:
                continue
            seen.add(relative)
            items.append({"id": relative, "name": path.name, "format": path.suffix[1:].lower(),
                          "modified": path.stat().st_mtime, "bytes": path.stat().st_size})
    return {"items": sorted(items, key=lambda item: item["modified"], reverse=True)[:200]}


@APP.get("/api/reports/content")
def report_content(path: str = Query(min_length=1, max_length=512)) -> dict[str, str]:
    # Only report extensions, and only within the approved report directories.
    if Path(path).is_absolute() or ".." in Path(path).parts or Path(path).suffix.lower() not in {".md", ".html", ".json"}:
        raise HTTPException(status_code=400, detail="Invalid report path")
    candidate = (PROJECT_ROOT / path).resolve()
    roots = [(PROJECT_ROOT / "reports").resolve(), (DATA_DIR / "reports").resolve(),
             (DATA_DIR / "assessments").resolve()]
    if not any(root == candidate or root in candidate.parents for root in roots):
        raise HTTPException(status_code=400, detail="Path is outside report directories")
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        content = candidate.read_text(encoding="utf-8")
    except OSError:
        raise HTTPException(status_code=500, detail="Report could not be read") from None
    return {"name": candidate.name, "content": content[:500_000]}


@APP.post("/api/discover", dependencies=[Depends(_require_operator_token)])
def run_discovery(request: DiscoverRequest) -> dict[str, Any]:
    try:
        # Enforce netagent's existing maximum target count before starting a scan.
        expand_targets(request.cidr)
        ipaddress.ip_network(request.cidr, strict=False)
        hosts = discover(request.cidr)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return {
        "count": len(hosts),
        "hosts": [{
            "ip": host.ip, "hostname": host.hostname, "open_ports": host.open_ports,
            "os_guess": host.os_guess, "role_guess": host.guessed_role, "services": host.services,
        } for host in hosts],
    }


@APP.post("/api/assess", dependencies=[Depends(_require_operator_token)])
def run_assessment(request: AssessRequest) -> dict[str, Any]:
    """Assess one selected device using its saved config and approved rules only."""
    inventory_path = _inventory_path(request.inventory)
    try:
        devices = load_inventory(inventory_path)
        matches = [device for device in devices if device.hostname == request.device]
        if not matches:
            raise HTTPException(status_code=404, detail="Device not found in selected inventory")
        device_record = matches[0]
        if device_record.platform != "cisco_ios":
            raise HTTPException(status_code=400, detail="Standard/Pro STIG assessment is currently supported only for Cisco IOS devices")

        config_path = DATA_DIR / "configs" / device_record.hostname / "latest.cfg"
        if not config_path.is_file():
            raise HTTPException(status_code=409, detail="No saved configuration for this device. Run read-only backup first.")
        config = config_path.read_text(encoding="utf-8", errors="replace")
        evidence_dir = DATA_DIR / "evidence" / device_record.hostname
        evidence = load_evidence(evidence_dir)
        # The latest saved configuration is authoritative for the config-based checks.
        evidence["show_running_config"] = config
        show_version = evidence.get("show_version")

        rules = load_approved_rules(PROJECT_ROOT / "rules" / "cisco_ios")
        rules = [rule for rule in rules if rule.target_platform == device_record.platform]
        if not rules:
            raise HTTPException(
                status_code=409,
                detail="No approved executable Cisco IOS rules are available. Draft rules are intentionally not executed; approve rules after Standard/Pro classification and review.",
            )
        context = DeviceContext(
            hostname=device_record.hostname,
            platform=device_record.platform,
            show_version=show_version,
        )
        waivers_path = PROJECT_ROOT / "rules" / "cisco_ios" / "waivers.json"
        waivers = load_waivers(waivers_path if waivers_path.is_file() else None)
        rows = [evaluate_rule_levels(rule, context, config, evidence, waivers=waivers, level="pro") for rule in rules]
        catalog_path = PROJECT_ROOT / "standards" / "disa-cisco-ios-switch" / "Y26M04" / "catalog.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8")) if catalog_path.is_file() else {}
        generated_at = datetime.now(timezone.utc).isoformat()
        report = build_json_report(
            context,
            rows,
            catalog_version=catalog.get("catalog_version", "unknown"),
            run_metadata={
                "generated_at": generated_at,
                "level": "pro",
                "inventory": request.inventory,
                "config_source": str(config_path.relative_to(PROJECT_ROOT)).replace("\\", "/"),
                "approved_rule_count": len(rules),
                "evidence_dir": str(evidence_dir.relative_to(PROJECT_ROOT)).replace("\\", "/"),
            },
        )
        report_dir = DATA_DIR / "assessments"
        report_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_path = report_dir / f"{device_record.hostname}-{stamp}.json"
        report_path.write_text(render_json_report(report), encoding="utf-8")
        return {
            "ok": True,
            "device": device_record.hostname,
            "report": report_path.name,
            "report_path": report_path.relative_to(PROJECT_ROOT).as_posix(),
            "verdict": report["verdict"],
            "row_count": len(report["rows"]),
            "approved_rule_count": len(rules),
        }
    except HTTPException:
        raise
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Assessment failed ({type(exc).__name__}); check local server console") from None


@APP.post("/api/backup", dependencies=[Depends(_require_operator_token)])
def run_backup(request: BackupRequest) -> dict[str, Any]:
    inventory_path = _inventory_path(request.inventory)
    try:
        devices = load_inventory(inventory_path)
        matches = [device for device in devices if device.hostname == request.device]
        if not matches:
            raise HTTPException(status_code=404, detail="Device not found in selected inventory")
        device = matches[0]
        credential = Credential(request.username, request.password, request.secret)
        output = fetch(device, credential)
        store = ConfigStore(DATA_DIR / "configs")
        changed, _ = store.save(device.hostname, output["config"])
        artifacts = {key: value for key, value in output.items() if key.startswith("routeros_")}
        if artifacts:
            store.save_artifacts(device.hostname, artifacts)
        if "neighbors" in output:
            neighbor_dir = DATA_DIR / "neighbors"
            neighbor_dir.mkdir(parents=True, exist_ok=True)
            (neighbor_dir / f"{device.hostname}.txt").write_text(output["neighbors"], encoding="utf-8")
        return {
            "ok": True,
            "device": device.hostname,
            "changed": changed,
            "artifact_count": len(artifacts),
            "neighbors_collected": "neighbors" in output,
        }
    except HTTPException:
        raise
    except (ValueError, RuntimeError, OSError) as exc:
        # Do not return exception messages: transport libraries can include sensitive details.
        raise HTTPException(status_code=502, detail=f"Backup failed ({type(exc).__name__}); check the local server console") from None

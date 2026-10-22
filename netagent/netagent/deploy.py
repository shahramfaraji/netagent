"""Guarded, single-device Cisco IOS config deployment.

Live writes are intentionally limited to an interactive operator-approved flow.
The default CLI path is read-only. Every write is preceded by a local versioned
snapshot and a device-side flash snapshot so configure-replace rollback is possible.
"""
from __future__ import annotations

import difflib
import hashlib
import logging
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .collector import SHOW_CONFIG, ConfigStore, normalize
from .credentials import Credential, quiet_transport_logs, redact
from .deps import ensure_netmiko
from .models import Device

log = logging.getLogger(__name__)

_SUPPORTED_APPLY_PLATFORM = "cisco_ios"
_CONFIG_ERROR = re.compile(
    r"(?im)(?:^|\n)\s*(?:%\s*(?:invalid input|incomplete command|ambiguous command|error|failed)|"
    r"error:|fatal:|command rejected|failed)"
)
_SECRET_LINE = re.compile(
    r"(?i)^.*\b(?:password|secret|community|key|string|token)\b.*$"
)
_FORBIDDEN_COMMAND = re.compile(
    r"(?i)^\s*(?:(?:do\s+)?(?:configure\s+(?:replace|terminal)|copy\s+|write(?:\s+memory)?\b|"
    r"reload\b|delete\s+|erase\b|format\b)|end\s*$|exit\s*$|show(?:\s+|$)|enable\s*$)"
)
_REMOTE_BACKUP_RE = re.compile(r"^flash:netagent-[0-9a-f]{12}-(?:preapply|prerollback)\.cfg$")


@dataclass(frozen=True)
class ApplyPreview:
    hostname: str
    platform: str
    diff: str
    candidate_sha256: str
    candidate_lines: int
    current_config_sha256: str
    has_changes: bool
    local_backup: str = ""
    device_backup: str = ""

    @property
    def changed(self) -> bool:
        return self.has_changes


def clean_candidate(text: str) -> list[str]:
    """Validate a config snippet before it can reach a device."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("candidate config is empty")
    if len(text.encode("utf-8")) > 64 * 1024:
        raise ValueError("candidate config exceeds the 64 KiB limit")
    text = text.replace("\r\n", "\n")
    if any(ord(char) < 32 and char != "\n" for char in text):
        raise ValueError("candidate config contains an invalid control character")
    lines = [line.rstrip() for line in text.split("\n")]
    lines = [line for line in lines if line.strip() and not line.lstrip().startswith("!")]
    if not lines:
        raise ValueError("candidate config has no commands")
    if len(lines) > 500:
        raise ValueError("candidate config exceeds the 500-command limit")
    for line in lines:
        if "\x00" in line or "\r" in line or "\n" in line:
            raise ValueError("candidate config contains an invalid control character")
        if _FORBIDDEN_COMMAND.match(line):
            raise ValueError(f"candidate contains a forbidden exec/destructive command: {line.split()[0]}")
    return lines


def redact_config(config: str) -> str:
    """Mask common inline secret-bearing config lines before showing a diff."""
    return "\n".join("*** sensitive config line redacted ***" if _SECRET_LINE.match(line) else line
                     for line in config.splitlines())


def _diff(candidate: str) -> str:
    """Show the submitted snippet, not a misleading simulated full-config diff."""
    safe_candidate = redact_config(candidate)
    return "".join(difflib.unified_diff(
        [], safe_candidate.splitlines(True),
        fromfile="no commands", tofile="candidate commands",
    ))


def _make_preview(device: Device, current: str, candidate: str, lines: list[str]) -> ApplyPreview:
    normalized_candidate = candidate
    has_changes = normalize(current) != normalized_candidate
    return ApplyPreview(
        hostname=device.hostname,
        platform=device.platform,
        diff=_diff(candidate),
        candidate_sha256=hashlib.sha256(normalized_candidate.encode("utf-8")).hexdigest(),
        candidate_lines=len(lines),
        current_config_sha256=hashlib.sha256(normalize(current).encode("utf-8")).hexdigest(),
        has_changes=has_changes,
    )


def _params(device: Device, cred: Credential) -> dict:
    return {
        "device_type": device.platform,
        "host": device.host,
        "port": device.port,
        "username": cred.username,
        "password": cred.password,
        "secret": cred.secret,
        "timeout": 30,
        "auth_timeout": 30,
        "fast_cli": False,
    }


def _default_connector(**params):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        if not ensure_netmiko():
            raise RuntimeError("netmiko not installed: pip install 'netagent[ssh]'") from exc
        from netmiko import ConnectHandler
    return ConnectHandler(**params)


def _enable_if_needed(conn, device: Device, cred: Credential) -> None:
    if cred.secret and device.platform.startswith("cisco"):
        conn.enable()


def _check_platform(device: Device) -> None:
    if device.platform != _SUPPORTED_APPLY_PLATFORM:
        raise RuntimeError(
            f"transactional apply is currently supported only for {_SUPPORTED_APPLY_PLATFORM}; "
            f"{device.platform} is read-only"
        )


def _remote_name(kind: str) -> str:
    return f"flash:netagent-{uuid.uuid4().hex[:12]}-{kind}.cfg"


def _check_rollback_support(conn) -> None:
    """Verify the platform exposes configure-replace before any write can happen."""
    output = _checked_output(conn.send_command("configure replace ?", read_timeout=30),
                             "rollback capability check")
    if not re.search(r"(?i)(flash:|nvram:|\bfilename\b|\burl\b)", output):
        raise RuntimeError("device does not advertise configure-replace rollback support; no config was changed")


def _checked_output(output: str, operation: str) -> str:
    if _CONFIG_ERROR.search(output or ""):
        raise RuntimeError(f"device reported an error during {operation}")
    return output or ""


def _verify_device_snapshot(conn, remote_path: str) -> None:
    if not _REMOTE_BACKUP_RE.fullmatch(remote_path):
        raise ValueError("invalid backup path")
    listing = _checked_output(conn.send_command(f"dir {remote_path}", read_timeout=30), "backup verification")
    if remote_path.split(":", 1)[1].split("/", 1)[-1] not in listing:
        raise RuntimeError("device backup file was not found; config was not changed")


def _copy_running_config(conn, remote_path: str) -> None:
    """Create and verify a unique device-side pre-change snapshot."""
    if not _REMOTE_BACKUP_RE.fullmatch(remote_path):
        raise ValueError("invalid generated backup path")
    response = conn.send_command_timing(
        f"copy running-config {remote_path}", read_timeout=90,
        strip_prompt=False, strip_command=False,
    )
    output = response
    for _ in range(3):
        if re.search(r"(?i)(copied|copy complete|\[ok\])", response):
            break
        if not re.search(r"(?i)(destination filename|\[confirm\]|proceed\?)", response):
            break
        response = conn.send_command_timing(
            "\n", read_timeout=90, strip_prompt=False, strip_command=False,
        )
        output += response
    _checked_output(output, "device backup")
    if not re.search(r"(?i)(copied|copy complete|\[ok\])", output):
        raise RuntimeError("device backup could not be confirmed; config was not changed")
    _verify_device_snapshot(conn, remote_path)


def _replace_running_config(conn, remote_path: str, operation: str) -> None:
    if not _REMOTE_BACKUP_RE.fullmatch(remote_path):
        raise ValueError("invalid backup path")
    output = conn.send_command_timing(
        f"configure replace {remote_path} force", read_timeout=180,
        strip_prompt=False, strip_command=False,
    )
    _checked_output(output, operation)
    success_pattern = (
        r"(?i)(configure replace completed|configuration replaced|total bytes copied|"
        r"replace complete|rollback done|total number of passes:\s*\d+)"
    )
    if not re.search(success_pattern, output):
        raise RuntimeError(f"device did not confirm {operation}")


def preview_config(device: Device, candidate_text: str, cred: Credential,
                   connector: Callable | None = None) -> ApplyPreview:
    """Read-only preview against the current running config."""
    lines = clean_candidate(candidate_text)
    _check_platform(device)
    connector = connector or _default_connector
    try:
        with quiet_transport_logs(), connector(**_params(device, cred)) as conn:
            _enable_if_needed(conn, device, cred)
            current = conn.send_command(SHOW_CONFIG[device.platform], read_timeout=120)
    except Exception as exc:
        raise RuntimeError(redact(f"{device.hostname}: {type(exc).__name__}: {exc}", cred)) from None
    candidate = "\n".join(lines) + "\n"
    return _make_preview(device, current, candidate, lines)


def apply_config(device: Device, candidate_text: str, cred: Credential, store: ConfigStore,
                 approve: Callable[[ApplyPreview], bool], connector: Callable | None = None) -> str:
    """Apply a reviewed snippet after approval and verified local/device backups."""
    if approve is None:
        raise RuntimeError("an interactive human approval callback is required")
    lines = clean_candidate(candidate_text)
    _check_platform(device)
    connector = connector or _default_connector
    candidate = "\n".join(lines) + "\n"
    remote_backup = _remote_name("preapply")
    try:
        with quiet_transport_logs(), connector(**_params(device, cred)) as conn:
            _enable_if_needed(conn, device, cred)
            current = conn.send_command(SHOW_CONFIG[device.platform], read_timeout=120)
            _check_rollback_support(conn)
            preview = _make_preview(device, current, candidate, lines)
            if not preview.changed:
                return "No changes detected; device was not modified."

            local_backup = store.backup(device.hostname, current)
            _copy_running_config(conn, remote_backup)
            reviewed_preview = replace(preview, local_backup=local_backup.name, device_backup=remote_backup)
            if not approve(reviewed_preview):
                return (
                    f"Approval declined; config was not modified; verified backups retained: "
                    f"local {local_backup.name}, device {remote_backup}"
                )
            try:
                output = conn.send_config_set(lines, error_pattern=_CONFIG_ERROR.pattern, read_timeout=120)
                _checked_output(output, "config apply")
                after = conn.send_command(SHOW_CONFIG[device.platform], read_timeout=120)
                store.save(device.hostname, after)
                store.record_deployment(device.hostname, {
                    "status": "applied",
                    "platform": device.platform,
                    "remote_backup": remote_backup,
                    "local_backup": local_backup.name,
                    "candidate_sha256": preview.candidate_sha256,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                })
            except Exception:
                try:
                    _replace_running_config(conn, remote_backup, "automatic rollback")
                    restored = conn.send_command(SHOW_CONFIG[device.platform], read_timeout=120)
                    store.save(device.hostname, restored)
                except Exception:
                    try:
                        store.record_deployment(device.hostname, {
                            "status": "rollback_failed",
                            "platform": device.platform,
                            "remote_backup": remote_backup,
                            "local_backup": local_backup.name,
                            "candidate_sha256": preview.candidate_sha256,
                            "completed_at": datetime.now(timezone.utc).isoformat(),
                        })
                    except Exception:
                        pass
                    raise RuntimeError(
                        f"config apply failed and automatic rollback could not be confirmed; "
                        f"local backup: {local_backup.name}; device backup: {remote_backup}"
                    ) from None
                try:
                    store.record_deployment(device.hostname, {
                        "status": "failed_rolled_back",
                        "platform": device.platform,
                        "remote_backup": remote_backup,
                        "local_backup": local_backup.name,
                        "candidate_sha256": preview.candidate_sha256,
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                    })
                except Exception:
                    pass
                raise RuntimeError(
                    f"config apply or verification failed; automatic rollback completed; "
                    f"local backup: {local_backup.name}; device backup: {remote_backup}"
                ) from None
            log.info("config applied to %s; remote rollback snapshot %s", device.hostname, remote_backup)
            return (
                f"Applied to {device.hostname}; pre-change backup: {remote_backup}; "
                f"local snapshot: {local_backup.name}"
            )
    except RuntimeError as exc:
        raise RuntimeError(redact(f"{device.hostname}: {exc}", cred)) from None
    except Exception as exc:
        raise RuntimeError(redact(f"{device.hostname}: {type(exc).__name__}: {exc}", cred)) from None


def rollback_config(device: Device, cred: Credential, store: ConfigStore,
                    approve: Callable[[str, str, str, str], bool], connector: Callable | None = None) -> str:
    """Restore the latest successful deployment snapshot after separate approval."""
    if approve is None:
        raise RuntimeError("an interactive human approval callback is required")
    _check_platform(device)
    manifest = store.load_deployment(device.hostname)
    if manifest.get("status") not in ("applied", "rollback_failed"):
        raise RuntimeError("there is no unrolled-back deployment for this device")
    target = manifest.get("remote_backup", "")
    if not isinstance(target, str) or not _REMOTE_BACKUP_RE.fullmatch(target) or not target.endswith("-preapply.cfg"):
        raise RuntimeError("deployment record has an invalid rollback snapshot path")
    connector = connector or _default_connector
    recovery_backup = _remote_name("prerollback")
    try:
        with quiet_transport_logs(), connector(**_params(device, cred)) as conn:
            _enable_if_needed(conn, device, cred)
            current = conn.send_command(SHOW_CONFIG[device.platform], read_timeout=120)
            _check_rollback_support(conn)
            _verify_device_snapshot(conn, target)
            local_backup = store.backup(device.hostname, current)
            _copy_running_config(conn, recovery_backup)
            if not approve(device.hostname, target, local_backup.name, recovery_backup):
                return (
                    f"Approval declined; config was not modified; verified recovery backups retained: "
                    f"local {local_backup.name}, device {recovery_backup}"
                )
            try:
                _replace_running_config(conn, target, "rollback")
                after = conn.send_command(SHOW_CONFIG[device.platform], read_timeout=120)
                store.save(device.hostname, after)
                manifest["status"] = "rolled_back"
                manifest["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
                manifest["recovery_backup"] = recovery_backup
                manifest["rollback_local_backup"] = local_backup.name
                store.record_deployment(device.hostname, manifest)
            except Exception:
                try:
                    _replace_running_config(conn, recovery_backup, "rollback recovery")
                    restored = conn.send_command(SHOW_CONFIG[device.platform], read_timeout=120)
                    store.save(device.hostname, restored)
                    manifest["status"] = "applied"
                    manifest["recovery_backup"] = recovery_backup
                    manifest["rollback_local_backup"] = local_backup.name
                    store.record_deployment(device.hostname, manifest)
                except Exception:
                    manifest["status"] = "rollback_failed"
                    manifest["recovery_backup"] = recovery_backup
                    manifest["rollback_local_backup"] = local_backup.name
                    try:
                        store.record_deployment(device.hostname, manifest)
                    except Exception:
                        pass
                    raise RuntimeError(
                        f"rollback and recovery could not be confirmed; preserve device access and restore manually; "
                        f"recovery snapshot: {recovery_backup}; local snapshot: {local_backup.name}"
                    ) from None
                raise RuntimeError(
                    f"rollback failed or could not be verified; pre-rollback config was restored; "
                    f"recovery snapshot: {recovery_backup}"
                ) from None
            log.info("config rollback completed for %s", device.hostname)
            return f"Rolled back {device.hostname}; pre-rollback recovery snapshot: {recovery_backup}"
    except RuntimeError as exc:
        raise RuntimeError(redact(f"{device.hostname}: {exc}", cred)) from None
    except Exception as exc:
        raise RuntimeError(redact(f"{device.hostname}: {type(exc).__name__}: {exc}", cred)) from None

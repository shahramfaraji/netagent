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
from enum import Enum
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .collector import SHOW_CONFIG, ConfigStore, normalize
from .credentials import Credential, quiet_transport_logs, redact
from .deps import ensure_netmiko
from .models import Device
from .ssh import connection_params

log = logging.getLogger(__name__)

_SUPPORTED_APPLY_PLATFORM = "cisco_ios"
_CONFIG_ERROR = re.compile(
    r"(?im)(?:^|\n)\s*(?:%\s*(?:invalid input|incomplete command|ambiguous command|error|failed)|"
    r"error:|fatal:|command rejected|failed)"
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)(\b(?:enable\s+)?secret\s+(?:\d+\s+)?)(\S+)"),
    re.compile(r"(?i)(\bpassword\s+(?:\d+\s+)?)(\S+)"),
    re.compile(r"(?i)(\b(?:snmp-server\s+community|community)\s+)(\S+)"),
    re.compile(r"(?i)(\b(?:tacacs-server|radius-server)\s+key\s+)(?:\d+\s+)?(\S+)"),
    re.compile(r"(?i)(\bkey-string\s+)(?:\d+\s+)?(\S+)"),
    re.compile(r"(?i)(\btoken\s+)(\S+)"),
)
_FORBIDDEN_COMMAND = re.compile(
    r"(?i)^\s*(?:(?:do\s+)?(?:configure\s+(?:replace|terminal)|copy\s+|write(?:\s+memory)?\b|"
    r"reload\b|delete\s+|erase\b|format\b)|end\s*$|exit\s*$|show(?:\s+|$)|enable\s*$)"
)
_MANAGEMENT_RISK_PATTERNS = (
    re.compile(r"(?i)^\s*(?:shutdown|no\s+shutdown)\s*$"),
    re.compile(r"(?i)^\s*(?:no\s+)?(?:ip\s+access-group|ipv6\s+traffic-filter)\b"),
    re.compile(r"(?i)^\s*(?:no\s+)?(?:access-class|transport\s+input|transport\s+output)\b"),
    re.compile(r"(?i)^\s*(?:no\s+)?(?:username|aaa\s+|enable\s+(?:secret|password)|line\s+vty\b)"),
    re.compile(r"(?i)^\s*(?:ip\s+route|ipv6\s+route|no\s+ip\s+routing|ip\s+default-gateway)\b"),
    re.compile(r"(?i)^\s*(?:no\s+)?(?:vrf\s+forwarding|ip\s+ssh|crypto\s+key|snmp-server\s+community)\b"),
)


class ApprovalStatus(str, Enum):
    APPROVED = "approved"
    DECLINED = "declined"


@dataclass(frozen=True)
class ApprovalResult:
    status: ApprovalStatus
    risk_confirmed: bool = False

    @property
    def approved(self) -> bool:
        return self.status is ApprovalStatus.APPROVED


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
    risky_commands: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return self.has_changes


def clean_candidate(text: str, allow_risky_commands: tuple[str, ...] | list[str] = (),
                    enforce_risk_allowlist: bool = False) -> list[str]:
    """Validate a config snippet before it can reach a device.

    Optionally require exact-line allowlist entries for management-risk commands.
    """
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
    allowlist = {item.strip().lower() for item in allow_risky_commands if item.strip()}
    if enforce_risk_allowlist:
        for line in lines:
            if _is_management_risk(line) and line.strip().lower() not in allowlist:
                raise ValueError("candidate contains a management-risk command requiring an exact allowlist entry")
    return lines


def _is_management_risk(line: str) -> bool:
    return any(pattern.search(line) for pattern in _MANAGEMENT_RISK_PATTERNS)


def _risky_commands(lines: list[str]) -> tuple[str, ...]:
    return tuple(line.strip() for line in lines if _is_management_risk(line))


def redact_config(config: str) -> str:
    """Redact secret values while preserving the non-sensitive command context."""
    redacted = []
    for line in config.splitlines():
        safe_line = line
        for pattern in _SECRET_VALUE_PATTERNS:
            safe_line = pattern.sub(lambda match: match.group(1) + "***", safe_line)
        redacted.append(safe_line)
    return "\n".join(redacted)


def _diff(candidate: str) -> str:
    """Show the submitted snippet, not a misleading simulated full-config diff."""
    safe_candidate = redact_config(candidate)
    return "".join(difflib.unified_diff(
        [], safe_candidate.splitlines(True),
        fromfile="no commands", tofile="candidate commands",
    ))


def _context_commands(config: str) -> dict[str, set[str]]:
    """Map each top-level IOS stanza to its indented commands."""
    contexts: dict[str, set[str]] = {"": set()}
    context = ""
    for raw_line in normalize(config).splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("!"):
            continue
        if raw_line[:1].isspace():
            contexts.setdefault(context, set()).add(raw_line.strip())
        else:
            context = raw_line.strip()
            contexts.setdefault(context, set())
            contexts[""].add(context)
    return contexts


def _candidate_present(current: str, lines: list[str]) -> bool:
    """True only when every candidate command exists in its own IOS context."""
    actual = _context_commands(current)
    expected: dict[str, set[str]] = {"": set()}
    context = ""
    for raw_line in lines:
        if raw_line[:1].isspace():
            expected.setdefault(context, set()).add(raw_line.strip())
        else:
            context = raw_line.strip()
            expected.setdefault(context, set())
            expected[""].add(context)
    return all(commands <= actual.get(ctx, set()) for ctx, commands in expected.items())


def _make_preview(device: Device, current: str, candidate: str, lines: list[str]) -> ApplyPreview:
    normalized_candidate = candidate
    has_changes = not _candidate_present(current, lines)
    return ApplyPreview(
        hostname=device.hostname,
        platform=device.platform,
        diff=_diff(candidate),
        candidate_sha256=hashlib.sha256(normalized_candidate.encode("utf-8")).hexdigest(),
        candidate_lines=len(lines),
        current_config_sha256=hashlib.sha256(normalize(current).encode("utf-8")).hexdigest(),
        has_changes=has_changes,
        risky_commands=_risky_commands(lines),
    )


def _params(device: Device, cred: Credential, known_hosts: str | Path | None = None) -> dict:
    """Compatibility wrapper around the shared strict SSH parameter builder."""
    return connection_params(device, cred, timeout=30, known_hosts=known_hosts)


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


def _check_rollback_support(conn, require_revert_timer: bool = False) -> None:
    """Conservative feature probe; IOS/IOS-XE support varies (TODO(verify-on-device))."""
    output = _checked_output(conn.send_command("configure replace ?", read_timeout=30),
                             "rollback capability check")
    if not re.search(r"(?i)(flash:|nvram:|\bfilename\b|\burl\b)", output):
        raise RuntimeError("device does not advertise configure-replace rollback support; no config was changed")
    if require_revert_timer:
        # IOS/IOS-XE support and syntax vary. This is a read-only capability probe;
        # confirm the returned help text against the target software before enabling live apply.
        revert = _checked_output(conn.send_command("configure revert ?", read_timeout=30),
                                 "configuration-revert timer capability check")
        if not re.search(r"(?i)\btimer\b", revert):
            raise RuntimeError("device does not advertise configure-revert timer support; no config was changed (TODO(verify-on-device))")


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


def _start_safety_timer(conn) -> None:
    """Arm a five-minute IOS configuration-revert timer (TODO(verify-on-device))."""
    output = _checked_output(conn.send_command_timing("configure revert timer 5", read_timeout=30,
                                strip_prompt=False, strip_command=False), "arming configuration-revert timer")
    if not re.search(r"(?i)(timer|revert|minutes|configuration)", output):
        raise RuntimeError("device did not confirm configuration-revert timer activation (TODO(verify-on-device))")


def _confirm_safety_timer(conn) -> None:
    output = _checked_output(conn.send_command_timing("configure confirm", read_timeout=30,
                                strip_prompt=False, strip_command=False), "confirming configuration-revert timer")
    if not re.search(r"(?i)(configuration confirmed|confirmed successfully|confirm successful|revert timer.*(?:cancel|clear))", output):
        raise RuntimeError("device did not positively confirm cancellation of the configuration-revert timer (TODO(verify-on-device))")


def _candidate_observed_hash(config: str, lines: list[str]) -> str:
    """Hash only candidate commands as observed in their matching contexts."""
    actual = _context_commands(config)
    context = ""
    observed = []
    for raw_line in lines:
        if raw_line[:1].isspace():
            command = raw_line.strip()
            if command not in actual.get(context, set()):
                raise RuntimeError(f"post-apply verification could not find candidate command in context: {command}")
            observed.append((" " + command) if context else command)
        else:
            context = raw_line.strip()
            if context not in actual.get("", set()):
                raise RuntimeError(f"post-apply verification could not find candidate context: {context}")
            observed.append(context)
    return hashlib.sha256(("\n".join(observed) + "\n").encode("utf-8")).hexdigest()


def _verify_new_connection(device: Device, cred: Credential, connector: Callable,
                           lines: list[str], expected_hash: str,
                           finalize: Callable[[str], None]) -> None:
    """Verify candidate state over a fresh SSH session, finalize, then cancel timer."""
    with quiet_transport_logs(), connector(**_params(device, cred)) as verify_conn:
        _enable_if_needed(verify_conn, device, cred)
        verify_conn.find_prompt()
        observed = verify_conn.send_command(SHOW_CONFIG[device.platform], read_timeout=120)
        observed_hash = _candidate_observed_hash(observed, lines)
        if observed_hash != expected_hash:
            raise RuntimeError("new-connection candidate hash verification failed")
        finalize(observed)
        _confirm_safety_timer(verify_conn)


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
                 approve: Callable[[ApplyPreview], bool | ApprovalResult], connector: Callable | None = None,
                 allow_risky_commands: tuple[str, ...] | list[str] = ()) -> str:
    """Apply a reviewed snippet after approval and verified local/device backups."""
    if approve is None:
        raise RuntimeError("an interactive human approval callback is required")
    lines = clean_candidate(candidate_text, allow_risky_commands, enforce_risk_allowlist=True)
    _check_platform(device)
    connector = connector or _default_connector
    candidate = "\n".join(lines) + "\n"
    remote_backup = _remote_name("preapply")
    try:
        with quiet_transport_logs(), connector(**_params(device, cred)) as conn:
            _enable_if_needed(conn, device, cred)
            current = conn.send_command(SHOW_CONFIG[device.platform], read_timeout=120)
            preview = _make_preview(device, current, candidate, lines)
            if not preview.changed:
                return "No changes detected; device was not modified."
            _check_rollback_support(conn, require_revert_timer=True)

            local_backup = store.backup(device.hostname, current)
            _copy_running_config(conn, remote_backup)
            reviewed_preview = replace(preview, local_backup=local_backup.name, device_backup=remote_backup)
            approval = approve(reviewed_preview)
            approved = approval.approved if isinstance(approval, ApprovalResult) else bool(approval)
            if not approved:
                store.record_deployment(device.hostname, {
                    "status": "declined", "platform": device.platform,
                    "remote_backup": remote_backup, "local_backup": local_backup.name,
                    "candidate_sha256": preview.candidate_sha256,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                })
                return (
                    f"Approval declined; config was not modified; verified backups retained: "
                    f"local {local_backup.name}, device {remote_backup}"
                )
            if preview.risky_commands and not (isinstance(approval, ApprovalResult) and approval.risk_confirmed):
                raise RuntimeError("management-risk commands require separate explicit risk confirmation")
            store.record_deployment(device.hostname, {
                "status": "applying", "platform": device.platform,
                "remote_backup": remote_backup, "local_backup": local_backup.name,
                "candidate_sha256": preview.candidate_sha256,
                "started_at": datetime.now(timezone.utc).isoformat(),
            })
            try:
                _start_safety_timer(conn)
                output = conn.send_config_set(lines, error_pattern=_CONFIG_ERROR.pattern, read_timeout=120)
                _checked_output(output, "config apply")
                expected_hash = _candidate_observed_hash(candidate, lines)
                def finalize(observed: str) -> None:
                    store.save(device.hostname, observed)
                    store.record_deployment(device.hostname, {
                        "status": "applied", "platform": device.platform,
                        "remote_backup": remote_backup, "local_backup": local_backup.name,
                        "candidate_sha256": preview.candidate_sha256,
                        "verified_candidate_sha256": expected_hash,
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                    })
                _verify_new_connection(device, cred, connector, lines, expected_hash, finalize)
            except BaseException as apply_exc:
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
                        f"config apply/verification failed and automatic rollback could not be confirmed; "
                        f"local backup: {local_backup.name}; device backup: {remote_backup}"
                    ) from apply_exc
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
                ) from apply_exc
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

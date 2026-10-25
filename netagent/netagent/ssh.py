"""Shared SSH host-key verification and explicit trust-on-first-use support."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Callable

from .credentials import Credential
from .models import Device


def known_hosts_path(path: str | Path | None = None) -> Path:
    """Return the configured known_hosts path, creating an empty file if needed."""
    configured = path or os.environ.get("NETAGENT_KNOWN_HOSTS")
    target = Path(configured).expanduser() if configured else (
        Path(__file__).resolve().parent.parent / "data" / "known_hosts"
    )
    target = target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.touch(mode=0o600)
    if os.name != "nt":
        target.chmod(0o600)
    return target


def connection_params(
    device: Device,
    cred: Credential,
    timeout: int = 30,
    known_hosts: str | Path | None = None,
) -> dict:
    """Build Netmiko parameters that reject unknown or changed SSH host keys."""
    key_file = known_hosts_path(known_hosts)
    return {
        "device_type": device.platform,
        "host": device.host,
        "port": device.port,
        "username": cred.username,
        "password": cred.password,
        "secret": cred.secret,
        "timeout": timeout,
        "auth_timeout": timeout,
        "fast_cli": False,
        "ssh_strict": True,
        "system_host_keys": False,
        "alt_host_keys": True,
        "alt_key_file": str(key_file),
    }


def trust_host_key(
    device: Device,
    known_hosts: str | Path | None = None,
    *,
    input_fn: Callable[[str], str] | None = None,
    output_fn: Callable[[str], None] | None = None,
) -> str:
    """Interactively pin an SSH host key after exact fingerprint confirmation.

    This function reads only the SSH server's public key; it does not authenticate
    or issue device commands. A changed key is rejected and never overwritten.
    """
    import paramiko

    prompt = input_fn or input
    output = output_fn or print
    path = known_hosts_path(known_hosts)
    host_token = device.host if device.port == 22 else f"[{device.host}]:{device.port}"

    keys = paramiko.HostKeys()
    if path.stat().st_size:
        keys.load(str(path))
    existing = keys.lookup(host_token)

    transport = paramiko.Transport((device.host, device.port))
    try:
        transport.start_client(timeout=10)
        server_key = transport.get_remote_server_key()
    except Exception as exc:
        raise RuntimeError(f"could not read SSH host key for {device.hostname}: {type(exc).__name__}") from None
    finally:
        transport.close()

    if existing:
        known_key = existing.get(server_key.get_name())
        if known_key is not None and known_key.asbytes() == server_key.asbytes():
            return f"Host key already trusted for {device.hostname}."
        raise RuntimeError(f"SSH host key mismatch for {device.hostname}; refusing to replace the trusted key")

    digest = base64.b64encode(hashlib.sha256(server_key.asbytes()).digest()).decode("ascii").rstrip("=")
    fingerprint = f"SHA256:{digest}"
    output(f"SSH host: {device.hostname} ({device.host}:{device.port})")
    output(f"Host-key fingerprint: {fingerprint}")
    output("Verify this fingerprint through an independent trusted channel before accepting it.")
    try:
        answer = prompt("Type the exact fingerprint to trust this host key: ").strip()
    except (EOFError, KeyboardInterrupt):
        raise RuntimeError("host key was not trusted; interactive confirmation was not completed") from None
    if answer != fingerprint:
        raise RuntimeError("host key was not trusted; fingerprint confirmation did not match")

    keys.add(host_token, server_key.get_name(), server_key)
    keys.save(str(path))
    if os.name != "nt":
        path.chmod(0o600)
    return f"Trusted SSH host key for {device.hostname} in {path}."

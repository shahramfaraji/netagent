"""Credentials are prompted at runtime or read from env vars. Never written to disk or logs."""
from __future__ import annotations

import getpass
import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Credential:
    username: str
    password: str = field(repr=False)
    secret: str = field(default="", repr=False)

    def __str__(self) -> str:  # never leak secrets via str/log
        return f"Credential(username={self.username!r}, password=***)"


def get_credential(prompt: bool = True) -> Credential:
    user = os.environ.get("NETAGENT_USERNAME")
    pwd = os.environ.get("NETAGENT_PASSWORD")
    secret = os.environ.get("NETAGENT_SECRET", "")
    if user and pwd:
        return Credential(user, pwd, secret)
    if not prompt:
        raise RuntimeError("credentials not provided (set NETAGENT_USERNAME/NETAGENT_PASSWORD or allow prompt)")
    user = user or input("SSH username: ").strip()
    pwd = getpass.getpass("SSH password: ")
    secret = getpass.getpass("Enable secret (optional): ")
    if not user or not pwd:
        raise RuntimeError("username and password are required")
    return Credential(user, pwd, secret)


def redact(text: str, cred: Credential) -> str:
    for value in (cred.password, cred.secret):
        if value:
            text = text.replace(value, "***")
    return text

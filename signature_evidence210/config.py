"""Environment-driven configuration for the TSA service."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_POLICY_OID = "1.3.6.1.4.1.99999.210.1"


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive, got {value}")
    return value


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    default_policy_oid: str = DEFAULT_POLICY_OID
    accepted_policies: frozenset = field(
        default_factory=lambda: frozenset({DEFAULT_POLICY_OID})
    )
    max_request_bytes: int = 64 * 1024
    max_concurrency: int = 4
    sign_timeout_seconds: float = 10.0

    @property
    def db_path(self) -> Path:
        return self.data_dir / "tsa.db"

    @property
    def ca_key_path(self) -> Path:
        return self.data_dir / "ca.key"

    @property
    def ca_cert_path(self) -> Path:
        return self.data_dir / "ca.pem"

    @property
    def tsa_key_path(self) -> Path:
        return self.data_dir / "tsa.key"

    @property
    def tsa_cert_path(self) -> Path:
        return self.data_dir / "tsa.pem"

    @property
    def openssl_cnf_path(self) -> Path:
        return self.data_dir / "openssl-tsa.cnf"

    @property
    def serial_file_path(self) -> Path:
        return self.data_dir / "tsaserial"


def load_settings() -> Settings:
    data_dir = Path(os.environ.get("TSA_DATA_DIR", "data")).resolve()
    default_policy = os.environ.get("TSA_POLICY_OID", DEFAULT_POLICY_OID).strip()
    extra = os.environ.get("TSA_ACCEPTED_POLICIES", "")
    accepted = {default_policy}
    for item in extra.split(","):
        item = item.strip()
        if item:
            accepted.add(item)
    return Settings(
        data_dir=data_dir,
        default_policy_oid=default_policy,
        accepted_policies=frozenset(accepted),
        max_request_bytes=_int_env("TSA_MAX_REQUEST_BYTES", 64 * 1024),
        max_concurrency=_int_env("TSA_MAX_CONCURRENCY", 4),
        sign_timeout_seconds=float(_int_env("TSA_SIGN_TIMEOUT", 10)),
    )

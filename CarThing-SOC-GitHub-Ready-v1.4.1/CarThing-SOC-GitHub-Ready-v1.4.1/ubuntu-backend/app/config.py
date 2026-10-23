"""Environment-only configuration; no secrets are bundled with this project."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=False)


def _csv(name: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in os.getenv(name, "").split(",") if x.strip())


def _number(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(os.getenv(name, str(default)))))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    api_key: str = field(default_factory=lambda: os.getenv("CARTHING_API_KEY", ""))
    host: str = field(default_factory=lambda: os.getenv("CARTHING_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _number("CARTHING_PORT", 8765, 1, 65535))
    cache_seconds: int = field(default_factory=lambda: _number("CACHE_SECONDS", 10, 1, 120))
    cors_origins: tuple[str, ...] = field(default_factory=lambda: _csv("CORS_ORIGINS"))
    monitored_containers: tuple[str, ...] = field(default_factory=lambda: _csv("MONITORED_CONTAINERS"))
    disk_path: str = field(default_factory=lambda: os.getenv("DISK_PATH", "/"))
    wazuh_mode: str = field(default_factory=lambda: os.getenv("WAZUH_MODE", "off").lower())
    wazuh_alerts_file: str = field(default_factory=lambda: os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json"))
    wazuh_docker_container: str = field(default_factory=lambda: os.getenv("WAZUH_DOCKER_CONTAINER", "single-node-wazuh.manager-1"))
    wazuh_indexer_url: str = field(default_factory=lambda: os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200"))
    wazuh_indexer_user: str = field(default_factory=lambda: os.getenv("WAZUH_INDEXER_USER", ""))
    wazuh_indexer_password: str = field(default_factory=lambda: os.getenv("WAZUH_INDEXER_PASSWORD", ""))
    wazuh_ca_bundle: str = field(default_factory=lambda: os.getenv("WAZUH_CA_BUNDLE", ""))
    alert_window_hours: int = field(default_factory=lambda: _number("ALERT_WINDOW_HOURS", 24, 1, 168))
    auth_log_path: str = field(default_factory=lambda: os.getenv("AUTH_LOG_PATH", ""))

    def validate(self) -> None:
        if len(self.api_key) < 24 or self.api_key == "CHANGE_ME":
            raise ValueError("Set a random CARTHING_API_KEY of at least 24 characters (run scripts/setup.sh).")
        if self.wazuh_mode not in {"off", "file", "indexer", "docker"}:
            raise ValueError("WAZUH_MODE must be one of: off, file, indexer, docker")
        if self.wazuh_mode == "docker" and not self.wazuh_docker_container.strip():
            raise ValueError("Set WAZUH_DOCKER_CONTAINER to the Wazuh Manager container name")
        if self.wazuh_mode == "indexer":
            if not self.wazuh_indexer_url.startswith("https://"):
                raise ValueError("WAZUH_INDEXER_URL must use HTTPS")
            if not self.wazuh_indexer_user or not self.wazuh_indexer_password:
                raise ValueError("Set WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD")
        if any(not o.startswith(("http://", "https://")) or o == "*" for o in self.cors_origins):
            raise ValueError("CORS_ORIGINS must contain full http(s) origins, never *")

"""Read-only local host, Docker, Tailscale and Wazuh collectors.

All collectors return a status instead of fabricating data when a service is missing.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psutil
import requests

from .config import Settings

UTC = timezone.utc


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def server_status(settings: Settings) -> dict[str, Any]:
    try:
        # A short interval gives an actual sampled CPU percentage, even on first request.
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage(settings.disk_path)
        return {
            "status": "ok", "hostname": socket.gethostname(),
            "cpu_percent": round(cpu, 1), "ram_percent": round(mem.percent, 1),
            "ram_used_gb": round(mem.used / 1024**3, 2),
            "ram_total_gb": round(mem.total / 1024**3, 2),
            "disk_percent": round(disk.percent, 1),
            "disk_free_gb": round(disk.free / 1024**3, 2),
            "uptime_seconds": max(0, round(datetime.now(UTC).timestamp() - psutil.boot_time())),
            "disk_path": settings.disk_path,
        }
    except (OSError, ValueError) as exc:
        return {"status": "error", "message": f"Host metrics unavailable: {type(exc).__name__}"}


def docker_status(settings: Settings) -> dict[str, Any]:
    try:
        import docker
        client = docker.from_env(timeout=3)
        try:
            # Docker access grants significant host-level privilege. No mutations performed.
            listed = client.containers.list(all=True)
            selected = settings.monitored_containers
            by_name = {c.name: c for c in listed}
            names = list(selected) if selected else sorted(by_name)[:30]
            containers = []
            for name in names:
                c = by_name.get(name)
                if c is None:
                    containers.append({"name": name, "state": "missing", "health": "unknown"})
                    continue
                try:
                    # Inspect just the listed/selected containers to obtain Health if present.
                    details = client.api.inspect_container(c.id)
                    state = details.get("State", {})
                    containers.append({
                        "name": name,
                        "state": state.get("Status", c.status),
                        "health": state.get("Health", {}).get("Status", "not_configured"),
                    })
                except Exception:
                    containers.append({"name": name, "state": c.status, "health": "unknown"})
            return {"status": "ok", "containers": containers,
                    "running": sum(x["state"] == "running" for x in containers),
                    "total": len(containers), "limited_to": 30 if not selected else None}
        finally:
            client.close()
    except Exception:
        return {"status": "unavailable", "message": "Docker socket unavailable or access denied. See README."}


def tailscale_status(_: Settings) -> dict[str, Any]:
    try:
        proc = subprocess.run(["tailscale", "status", "--json"], capture_output=True,
                              text=True, timeout=4, check=False)
        if proc.returncode != 0:
            return {"status": "unavailable", "message": "Tailscale is not running or is not accessible."}
        data = json.loads(proc.stdout)
        state = data.get("BackendState", "Unknown")
        self_node = data.get("Self") or {}
        return {"status": "ok", "backend_state": state,
                "connected": state == "Running" and self_node.get("Online", True),
                "tailscale_ips": (self_node.get("TailscaleIPs") or [])[:2],
                "peer_count": len(data.get("Peer") or {})}
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError):
        return {"status": "unavailable", "message": "Tailscale CLI missing or status unavailable."}


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    except ValueError:
        return None


def _normalize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Expose a small, allowlisted investigation view; never return raw Wazuh JSON."""
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    if not isinstance(rule, dict): rule = {}
    if not isinstance(agent, dict): agent = {}
    if not isinstance(data, dict): data = {}
    win = data.get("win") or {}
    if not isinstance(win, dict): win = {}
    ed = win.get("eventdata") or {}
    system = win.get("system") or {}
    if not isinstance(ed, dict): ed = {}
    if not isinstance(system, dict): system = {}
    mitre = rule.get("mitre") or {}
    if not isinstance(mitre, dict): mitre = {}
    ids = mitre.get("id") or []
    if not isinstance(ids, list): ids = [ids]

    def safe(value: Any, limit: int = 80) -> str:
        if not isinstance(value, (str, int, float)): return ""
        return str(value).replace("\n", " ").replace("\r", " ")[:limit]

    try:
        level = int(rule.get("level", 0))
    except (ValueError, TypeError):
        level = 0
    severity = ("critical" if level >= 12 else "high" if level >= 8 else
                "medium" if level >= 4 else "low")
    return {
        "id": safe(alert.get("id"), 100),
        "timestamp": safe(alert.get("timestamp"), 60),
        "level": level,
        "severity": severity,
        "description": safe(rule.get("description", "Unknown event"), 220),
        "rule_id": safe(rule.get("id"), 40),
        "agent": safe(agent.get("name", "Unknown"), 100),
        "source_ip": safe(data.get("srcip") or data.get("src_ip") or ed.get("ipAddress") or alert.get("srcip"), 80),
        "event_id": safe(system.get("eventID") or data.get("event_id"), 20),
        "username": safe(ed.get("targetUserName") or ed.get("TargetUserName") or data.get("dstuser") or data.get("srcuser") or data.get("user"), 64),
        "logon_type": safe(ed.get("logonType") or ed.get("LogonType"), 16),
        "failure_reason": safe(ed.get("failureReason") or ed.get("FailureReason") or ed.get("status") or ed.get("Status"), 120),
        "workstation": safe(ed.get("workstationName") or system.get("computer"), 64),
        "mitre_ids": [safe(x, 25) for x in ids[:6]],
    }


def _parse_jsonl_tail(raw: bytes, read_limit: int = 2 * 1024 * 1024) -> list[dict[str, Any]]:
    """Parse up to 2 MB and 2,000 most recent JSONL records, newest first."""
    if len(raw) > read_limit:
        raw = raw[-read_limit:]
        # First line may have been truncated to the middle of a JSON object.
        raw = raw.partition(b"\n")[2]
    entries = []
    for line in reversed(raw.splitlines()[-2000:]):
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                entries.append(obj)
        except (ValueError, UnicodeDecodeError):
            continue
    return entries


def _tail_json_lines(path: str, read_limit: int = 2 * 1024 * 1024) -> list[dict[str, Any]]:
    with open(path, "rb") as f:
        f.seek(0, 2)
        offset = max(0, f.tell() - read_limit)
        f.seek(offset)
        raw = f.read(read_limit)
    if offset:
        raw = raw.partition(b"\n")[2]
    return _parse_jsonl_tail(raw, read_limit)


def _file_alerts(settings: Settings, limit: int) -> list[dict[str, Any]]:
    raw = _tail_json_lines(settings.wazuh_alerts_file)
    cutoff = datetime.now(UTC) - timedelta(hours=settings.alert_window_hours)
    fresh = [x for x in raw if (dt := _parse_time(x.get("timestamp"))) and dt >= cutoff]
    fresh.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    return [_normalize_alert(x) for x in fresh[:limit]]


def _docker_alerts(settings: Settings, limit: int) -> list[dict[str, Any]]:
    """Read the manager's last 2,000 JSON alert lines over the Docker socket.

    No shell is invoked. The server-side Docker daemon is privileged, so the
    backend must remain private and read-only at its HTTP/API layer.
    """
    try:
        import docker
        client = docker.from_env(timeout=5)
        try:
            manager = client.containers.get(settings.wazuh_docker_container)
            result = manager.exec_run(
                ["tail", "-n", "2000", settings.wazuh_alerts_file],
                stdout=True, stderr=True,
            )
            if result.exit_code != 0:
                raise OSError("Wazuh manager alert file could not be read")
            raw = result.output or b""
            if not isinstance(raw, bytes):
                raise OSError("Unexpected Docker response")
            cutoff = datetime.now(UTC) - timedelta(hours=settings.alert_window_hours)
            recent = [a for a in _parse_jsonl_tail(raw)
                      if (dt := _parse_time(a.get("timestamp"))) and dt >= cutoff]
            recent.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
            return [_normalize_alert(x) for x in recent[:limit]]
        finally:
            client.close()
    except Exception as exc:
        # Keep Docker paths, exceptions, and host details out of the API response.
        raise OSError("Wazuh Docker collector unavailable") from exc


def _indexer_alerts(settings: Settings, limit: int) -> list[dict[str, Any]]:
    # Wazuh security alerts are stored in the indexer, *not* the manager's /agents API.
    query = {
        "size": limit, "track_total_hits": False,
        "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "_source": ["id", "timestamp", "rule.level", "rule.id", "rule.description",
                    "agent.name", "data.srcip", "data.src_ip", "srcip",
                    "data.win.eventdata.targetUserName", "data.win.eventdata.TargetUserName",
                    "data.win.eventdata.ipAddress", "data.win.eventdata.logonType",
                    "data.win.eventdata.failureReason", "data.win.eventdata.status",
                    "data.win.eventdata.workstationName", "data.win.system.eventID",
                    "data.win.system.computer", "data.dstuser", "data.srcuser", "data.user",
                    "rule.mitre.id"],
        "query": {"range": {"timestamp": {"gte": f"now-{settings.alert_window_hours}h", "lte": "now"}}},
    }
    verify: str | bool = settings.wazuh_ca_bundle or True
    url = settings.wazuh_indexer_url.rstrip("/") + "/wazuh-alerts-*/_search"
    r = requests.post(url, json=query, timeout=6,
                      auth=(settings.wazuh_indexer_user, settings.wazuh_indexer_password),
                      verify=verify)
    r.raise_for_status()
    data = r.json()
    return [_normalize_alert(x["_source"]) for x in data.get("hits", {}).get("hits", [])
            if isinstance(x.get("_source"), dict)]


def wazuh_alerts(settings: Settings, limit: int = 15) -> dict[str, Any]:
    limit = max(1, min(50, limit))
    if settings.wazuh_mode == "off":
        return {"status": "disabled", "source": None, "window_hours": settings.alert_window_hours,
                "returned": 0, "severity_in_returned": {}, "alerts": [],
                "message": "Configure WAZUH_MODE=docker, file, or indexer to enable alerts."}
    try:
        if settings.wazuh_mode == "file":
            alerts = _file_alerts(settings, limit)
        elif settings.wazuh_mode == "docker":
            alerts = _docker_alerts(settings, limit)
        else:
            alerts = _indexer_alerts(settings, limit)
        counts = Counter(a["severity"] for a in alerts)
        return {"status": "ok", "source": settings.wazuh_mode,
                "window_hours": settings.alert_window_hours,
                "returned": len(alerts), "severity_in_returned": {
                    k: counts.get(k, 0) for k in ("critical", "high", "medium", "low")},
                "alerts": alerts, "message": "Counts describe returned alerts only, not all alerts in the time window."}
    except (OSError, requests.RequestException, ValueError, KeyError):
        # Deliberately avoid returning paths, user names, secrets, or raw network errors.
        return {"status": "unavailable", "source": settings.wazuh_mode,
                "window_hours": settings.alert_window_hours, "returned": 0,
                "severity_in_returned": {}, "alerts": [],
                "message": "Wazuh alerts unavailable: check Docker manager name/socket permissions, local file permissions, or indexer settings."}


_AUTH_FAILURE = re.compile(r"Failed password|authentication failure|Invalid user|FAILED LOGIN", re.I)


def auth_failures(settings: Settings) -> dict[str, Any]:
    if not settings.auth_log_path:
        return {"status": "disabled", "recent_failures": None,
                "message": "Set AUTH_LOG_PATH to a readable Ubuntu auth log to enable."}
    try:
        # This is a snapshot of the last 1000 lines, NOT a 24-hour count.
        with open(settings.auth_log_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            off = max(0, size - 262144)
            f.seek(off)
            raw = f.read(262144)
        lines = raw.decode("utf-8", errors="replace").splitlines()
        if off: lines = lines[1:]
        matches = [line for line in lines[-1000:] if _AUTH_FAILURE.search(line)]
        return {"status": "ok", "recent_failures": len(matches),
                "sample_window": "last 1000 readable log lines",
                "recent_events": [line[:220] for line in matches[-5:]]}
    except OSError:
        return {"status": "unavailable", "recent_failures": None,
                "message": "Auth log does not exist or is not readable."}

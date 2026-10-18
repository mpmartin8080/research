"""Normalised honeypot events. OpenCanary emits one JSON object per line; we map it to
a stable schema carrying the honeypot, experiment arm and service, so active and
passive arms can be compared downstream."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from honeyforge.canary.modules import LOGTYPES
from honeyforge.spec.models import HoneypotSpec


class Event(BaseModel):
    ts: datetime
    honeypot: str
    arm: str
    service: str | None
    logtype: int
    kind: str
    src_host: str | None
    src_port: int | None
    dst_port: int | None
    data: dict[str, Any]
    # Set by attribution (phase 8) when contact can be tied to a specific signal tag.
    signal_tag: str | None = None

    @property
    def is_interaction(self) -> bool:
        return self.logtype >= 2000


def _ts(raw: dict[str, Any]) -> datetime:
    value = raw.get("utc_time")
    if value:
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_line(line: str, spec: HoneypotSpec) -> Event | None:
    """Parse one OpenCanary log line; returns None for non-JSON lines (twistd chatter)."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict) or "logtype" not in raw:
        return None

    by_port = {s.listen_port: s.name for s in spec.services}
    logtype = _int(raw.get("logtype")) or 0
    dst_port = _int(raw.get("dst_port"))
    data = raw.get("logdata")
    return Event(
        ts=_ts(raw),
        honeypot=spec.name,
        arm=spec.experiment_arm,
        service=by_port.get(dst_port) if dst_port is not None else None,
        logtype=logtype,
        kind=LOGTYPES.get(logtype, f"unknown.{logtype}"),
        src_host=raw.get("src_host") or None,
        src_port=_int(raw.get("src_port")),
        dst_port=dst_port,
        data=data if isinstance(data, dict) else {"msg": data},
    )

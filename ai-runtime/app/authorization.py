from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def parse_instant(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def port_intervals(value: Any) -> list[tuple[int, int]]:
    if value is None:
        return []

    tokens = value if isinstance(value, list) else re.split(r"[,\s]+", str(value))
    intervals: list[tuple[int, int]] = []
    for token in tokens:
        text = str(token).strip()
        if not text:
            continue

        match = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", text)
        if not match:
            continue
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if 1 <= start <= end <= 65535:
            intervals.append((start, end))
    return intervals


def requested_ports(parameters: dict[str, Any]) -> list[int]:
    value = parameters.get("ports", parameters.get("port"))
    ports: list[int] = []
    for start, end in port_intervals(value):
        if end - start > 1024:
            # Java 执行器会对大范围做最终的配额和边界校验。
            ports.extend((start, end))
        else:
            ports.extend(range(start, end + 1))
    return ports[:4096]


def ports_allowed(requested: list[int], allowed: list[tuple[int, int]]) -> bool:
    if not requested:
        return True
    if not allowed:
        return False
    return all(
        any(start <= port <= end for start, end in allowed) for port in requested
    )

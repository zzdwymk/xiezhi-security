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
    if isinstance(value, bool):
        raise ValueError("端口值格式无效")
    if isinstance(value, list):
        if not value or any(isinstance(item, bool) or not isinstance(item, int) for item in value):
            raise ValueError("端口数组只能包含整数且不能为空")
        tokens: list[Any] = value
    elif isinstance(value, (str, int)):
        text_value = str(value).strip()
        if not text_value:
            raise ValueError("端口值不能为空")
        tokens = re.split(r"[,\s]+", text_value)
    else:
        raise ValueError("端口值格式无效")
    intervals: list[tuple[int, int]] = []
    for token in tokens:
        text = str(token).strip()
        if not text:
            raise ValueError("端口 token 不能为空")

        match = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", text)
        if not match:
            raise ValueError(f"非法端口 token: {text[:40]}")
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if not 1 <= start <= end <= 65535:
            raise ValueError("端口必须位于 1-65535 且范围起点不能大于终点")
        intervals.append((start, end))
    return _merge_intervals(intervals)


def _merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def requested_port_intervals(parameters: dict[str, Any]) -> list[tuple[int, int]]:
    has_ports = "ports" in parameters
    has_port = "port" in parameters
    if has_ports and has_port:
        raise ValueError("不能同时提供 port 和 ports")
    if not has_ports and not has_port:
        return []
    return port_intervals(parameters["ports"] if has_ports else parameters["port"])


def requested_ports(parameters: dict[str, Any]) -> list[int]:
    ports: list[int] = []
    for start, end in requested_port_intervals(parameters):
        if end - start > 4095:
            raise ValueError("请求端口范围过大，不能展开为单端口列表")
        ports.extend(range(start, end + 1))
    return ports[:4096]


def ports_allowed(
    requested: list[int] | list[tuple[int, int]], allowed: list[tuple[int, int]]
) -> bool:
    if not requested:
        return True
    if not allowed:
        return False
    requested_intervals = (
        [(int(item), int(item)) for item in requested]
        if isinstance(requested[0], int)
        else [(int(item[0]), int(item[1])) for item in requested]
    )
    authorized = _merge_intervals(allowed)
    return all(
        any(allowed_start <= start and end <= allowed_end for allowed_start, allowed_end in authorized)
        for start, end in requested_intervals
    )

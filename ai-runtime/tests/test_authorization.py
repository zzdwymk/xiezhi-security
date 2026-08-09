from datetime import timezone

import pytest

from app.authorization import (
    parse_instant,
    port_intervals,
    ports_allowed,
    requested_port_intervals,
    requested_ports,
)


def test_parse_instant_normalizes_naive_datetime_to_utc():
    parsed = parse_instant("2026-07-31T09:30:00")

    assert parsed is not None
    assert parsed.tzinfo == timezone.utc


def test_port_intervals_normalizes_disjoint_and_adjacent_ranges():
    assert port_intervals("443, 80-81 82,8000-8010") == [
        (80, 82),
        (443, 443),
        (8000, 8010),
    ]
    assert port_intervals("1-65535") == [(1, 65535)]
    assert port_intervals([443, 80, 81]) == [(80, 81), (443, 443)]


@pytest.mark.parametrize(
    "value",
    [
        "80,bad",
        "",
        "   ",
        "0",
        "65536",
        "443-80",
        "80-",
        [],
        [80, True],
        [80, 443.0],
        True,
        False,
        80.0,
    ],
)
def test_port_intervals_rejects_the_entire_invalid_specification(value):
    with pytest.raises(ValueError):
        port_intervals(value)


def test_requested_port_intervals_distinguishes_absent_from_invalid():
    assert requested_port_intervals({}) == []
    assert requested_port_intervals({"ports": "1-65535"}) == [(1, 65535)]

    for parameters in (
        {"ports": ""},
        {"ports": []},
        {"port": True},
        {"port": 80, "ports": "443"},
    ):
        with pytest.raises(ValueError):
            requested_port_intervals(parameters)


def test_requested_ports_refuses_to_lossily_expand_large_ranges():
    assert requested_ports({"ports": "80-82"}) == [80, 81, 82]
    with pytest.raises(ValueError):
        requested_ports({"ports": "1-65535"})


def test_ports_allowed_requires_complete_interval_containment():
    allowed = port_intervals("80-82,443,8000-8010")

    assert ports_allowed([(80, 82), (443, 443), (8005, 8008)], allowed)
    assert not ports_allowed([(80, 83)], allowed)
    assert not ports_allowed([(1, 65535)], [(1, 1), (65535, 65535)])
    assert ports_allowed([(1, 65535)], [(1, 65535)])
    assert not ports_allowed([(80, 80)], [])

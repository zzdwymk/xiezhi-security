from datetime import timezone

from app.authorization import (
    parse_instant,
    port_intervals,
    ports_allowed,
    requested_ports,
)


def test_parse_instant_normalizes_naive_datetime_to_utc():
    parsed = parse_instant("2026-07-31T09:30:00")

    assert parsed is not None
    assert parsed.tzinfo == timezone.utc


def test_port_intervals_ignores_malformed_and_out_of_range_values():
    assert port_intervals("80, 443 8000-8010 invalid 0 65536") == [
        (80, 80),
        (443, 443),
        (8000, 8010),
    ]


def test_requested_ports_keeps_large_ranges_bounded():
    assert requested_ports({"ports": "1-65535"}) == [1, 65535]


def test_ports_allowed_requires_every_requested_port_to_be_authorized():
    allowed = [(80, 80), (443, 443), (8000, 8010)]

    assert ports_allowed([80, 443, 8005], allowed)
    assert not ports_allowed([80, 8080], allowed)

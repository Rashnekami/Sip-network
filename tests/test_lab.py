"""Roda o motor em cada pcap do laboratório (tests/lab.py): tudo o que é esperado tem de ser detectado e nenhum outro
diagnóstico pode aparecer (alarme falso), nem mesmo informativo."""
import pytest

from sip_network import analyze_bytes

from lab import SCENARIOS


def evaluate(scenario, result):
    codes = {d.code for d in result.diagnostics}
    missing = sorted(set(scenario.expect) - codes)
    false_alarms = sorted(codes - set(scenario.expect) - set(scenario.allow))
    extra = scenario.check(result) if scenario.check else []
    return missing, false_alarms, extra


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.id for s in SCENARIOS])
def test_lab_scenario(scenario):
    result = analyze_bytes(scenario.pcap(), scenario.filename)
    missing, false_alarms, extra = evaluate(scenario, result)
    assert not missing, f"não detectou {missing}"
    assert not false_alarms, f"alarme falso {false_alarms}"
    assert not extra, extra


def test_lab_ids_are_unique():
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids))


def test_corrupt_timestamp_does_not_hang():
    """A single packet with a bogus timestamp years away used to make the traffic timeline loop over every second."""
    import time

    from pcapgen import pcap, udp_frame
    from lab import by_id
    frames = by_id()["limpo01_chamada_normal_g711"].build()
    frames.append((frames[-1][0] + 10 * 365 * 86400, udp_frame("10.0.0.9", "10.0.0.2", 1000, 2000, b"x")))
    start = time.time()
    analyze_bytes(pcap(sorted(frames, key=lambda f: f[0])))
    assert time.time() - start < 5

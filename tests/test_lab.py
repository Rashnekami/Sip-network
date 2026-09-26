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

from pathlib import Path

from ble_agent import rules
from ble_agent.cli import _load, main

SAMPLE = str(Path(__file__).with_name("sample_scan.json"))


def test_rules_on_sample():
    ids = {(f.device, f.rule_id) for f in rules.audit(_load(SAMPLE))}
    lock = "C4:11:22:33:44:55"
    for rid in ["ADDR-STATIC", "NAME-LEAK", "SVC-SERIAL", "SVC-DFU", "CHAR-WWR", "RF-TXPOWER", "VENDOR"]:
        assert (lock, rid) in ids
    phone = "4A:AA:BB:CC:DD:EE"  # random private address, Apple
    assert (phone, "ADDR-STATIC") not in ids
    assert (phone, "VENDOR") in ids


def test_cli_offline_report(tmp_path):
    out = tmp_path / "r.md"
    assert main(["audit", "-i", SAMPLE, "-r", str(out)]) == 0
    assert "Firmware update" in out.read_text()

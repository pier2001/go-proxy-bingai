# BLE Security Research Agent

Defensive BLE discovery and audit tool, with optional AI-assisted (Claude) reporting.
It **passively** scans advertisements. It only enumerates GATT on devices you name with `--gatt`,
which must be devices you own or are authorised to test. It never reads values, writes, pairs or sends commands.

## Mac setup
```bash
cd ble-security-agent
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```
- The first time you run a scan, macOS asks to give Terminal/iTerm Bluetooth access. Allow it, or enable it under
  System Settings → Privacy & Security → Bluetooth.
- On macOS, addresses show as CoreBluetooth UUIDs instead of MAC addresses, so the address-tracking rule is skipped.

## Usage
```bash
python -m ble_agent scan -t 15 -o scan.json                    # passive scan
python -m ble_agent audit -i scan.json                         # rule-based audit -> report.md
python -m ble_agent audit -i scan.json --gatt <ADDR>           # + read-only GATT (own devices)
export ANTHROPIC_API_KEY=sk-...; python -m ble_agent audit -i scan.json --llm   # AI report (Chinese)
python -m ble_agent audit -i tests/sample_scan.json            # offline demo, no Bluetooth needed
```
Set the `BLE_AGENT_MODEL` environment variable to change the model (default `claude-sonnet-5-5`).

## Rules
| ID | Severity | Check |
|---|---|---|
| SVC-DFU | high | Firmware-update service (Nordic DFU / TI OAD) is exposed |
| SVC-SERIAL | medium | Nordic UART / FFE0 serial-over-BLE service |
| CHAR-WWR | medium | Characteristic accepts write-without-response |
| ADDR-STATIC | low | Address is not a rotating private address (device can be tracked) |
| NAME-LEAK | low | Advertised name leaks the owner, model or location |
| RF-TXPOWER | info | Advertised TX power ≥ 8 dBm |
| VENDOR | info | Manufacturer, identified from the company ID |

To add a rule, write a function in `ble_agent/rules.py` and add it to `RULES`. Run the tests with `pytest -q tests`.

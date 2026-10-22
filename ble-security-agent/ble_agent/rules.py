"""Rule-based defensive checks. Each rule takes a Device and yields Findings."""
import re

from .models import Device, Finding

# Well-known service UUIDs worth flagging (short form, inside 0000xxxx-0000-1000-8000-00805f9b34fb)
NORDIC_UART = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NORDIC_DFU = "0000fe59-0000-1000-8000-00805f9b34fb"
LEGACY_DFU = "00001530-1212-efde-1523-785feabcd123"
TI_OAD = "f000ffc0-0451-4000-b000-000000000000"
DEBUG_LIKE = {NORDIC_UART: "Nordic UART (serial-over-BLE)", "0000ffe0-0000-1000-8000-00805f9b34fb": "HM-10 style serial (FFE0)"}
DFU_LIKE = {NORDIC_DFU: "Nordic Secure DFU", LEGACY_DFU: "Nordic legacy DFU", TI_OAD: "TI OAD firmware update"}

COMPANY_IDS = {0x004C: "Apple", 0x0006: "Microsoft", 0x0075: "Samsung", 0x00E0: "Google",
               0x0059: "Nordic Semiconductor", 0x000D: "Texas Instruments", 0x02E5: "Espressif"}

SENSITIVE_NAME = re.compile(r"(\b[A-Z][a-z]+'s\b|iphone|ipad|macbook|\d{6,}|@|room|flat|apt|lock)", re.I)


def _all_service_uuids(d: Device) -> set[str]:
    return set(d.service_uuids) | {s.uuid for s in d.services}


def r_public_address(d: Device):
    # Random private addresses have top two bits 01; macOS shows UUIDs instead of MACs, so skip those.
    if re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", d.address):
        top = int(d.address[:2], 16) >> 6
        if top != 0b01:
            yield Finding(d.address, "ADDR-STATIC", "low", "Non-rotating (public/static) address",
                          "Device address does not look like a resolvable private address; it can be tracked over time.")


def r_name_leak(d: Device):
    if d.name and SENSITIVE_NAME.search(d.name):
        yield Finding(d.address, "NAME-LEAK", "low", "Advertised name may leak personal/identifying info",
                      f"Local name '{d.name}' contains owner, model, serial or location hints.")


def r_debug_service(d: Device):
    for u in _all_service_uuids(d):
        if u in DEBUG_LIKE:
            yield Finding(d.address, "SVC-SERIAL", "medium", f"Exposed {DEBUG_LIKE[u]} service",
                          "Serial-style services often accept commands without pairing; verify authentication is required.")


def r_dfu_service(d: Device):
    for u in _all_service_uuids(d):
        if u in DFU_LIKE:
            yield Finding(d.address, "SVC-DFU", "high", f"Firmware update service exposed ({DFU_LIKE[u]})",
                          "Confirm firmware images are signed and DFU entry requires authentication/bonding.")


def r_open_write(d: Device):
    for s in d.services:
        for c in s.characteristics:
            if "write-without-response" in c.properties:
                yield Finding(d.address, "CHAR-WWR", "medium", "Write-without-response characteristic",
                              f"{c.uuid} in service {s.uuid}: unacknowledged writes; check it requires an encrypted link.")


def r_tx_power(d: Device):
    if d.tx_power is not None and d.tx_power >= 8:
        yield Finding(d.address, "RF-TXPOWER", "info", "High advertised TX power",
                      f"TX power {d.tx_power} dBm increases the distance it can be detected or attacked from.")


def r_vendor(d: Device):
    for cid in d.manufacturer_data:
        if cid in COMPANY_IDS:
            yield Finding(d.address, "VENDOR", "info", f"Manufacturer: {COMPANY_IDS[cid]}",
                          f"Company ID 0x{cid:04X} found in advertisement.")


RULES = [r_public_address, r_name_leak, r_debug_service, r_dfu_service, r_open_write, r_tx_power, r_vendor]


def audit(devices: list[Device]) -> list[Finding]:
    return [f for d in devices for rule in RULES for f in rule(d)]

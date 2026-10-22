"""Passive BLE advertisement scanning (no connection, no writes)."""
import asyncio

from .models import Device


async def scan(timeout: float = 10.0) -> list[Device]:
    from bleak import BleakScanner

    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    devices = []
    for d, adv in found.values():
        devices.append(Device(
            address=d.address,
            name=adv.local_name or d.name,
            rssi=adv.rssi,
            connectable=getattr(adv, "connectable", None),
            tx_power=adv.tx_power,
            service_uuids=[u.lower() for u in adv.service_uuids],
            manufacturer_data={k: v.hex() for k, v in adv.manufacturer_data.items()},
        ))
    return sorted(devices, key=lambda x: x.rssi, reverse=True)


def scan_sync(timeout: float = 10.0) -> list[Device]:
    return asyncio.run(scan(timeout))

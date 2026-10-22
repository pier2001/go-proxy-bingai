"""Read-only GATT enumeration of a device you own / are authorised to test.

Only lists services and characteristic properties. It never reads values,
writes, pairs, or sends commands.
"""
import asyncio

from .models import Characteristic, Device, Service


async def enumerate_gatt(device: Device, timeout: float = 15.0) -> Device:
    from bleak import BleakClient

    async with BleakClient(device.address, timeout=timeout) as client:
        for s in client.services:
            svc = Service(uuid=s.uuid.lower(), description=s.description)
            for c in s.characteristics:
                svc.characteristics.append(Characteristic(
                    uuid=c.uuid.lower(), properties=list(c.properties), description=c.description))
            device.services.append(svc)
    return device


def enumerate_sync(device: Device) -> Device:
    return asyncio.run(enumerate_gatt(device))

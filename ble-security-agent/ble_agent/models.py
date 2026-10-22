from dataclasses import dataclass, field, asdict


@dataclass
class Characteristic:
    uuid: str
    properties: list[str]
    description: str = ""


@dataclass
class Service:
    uuid: str
    description: str = ""
    characteristics: list[Characteristic] = field(default_factory=list)


@dataclass
class Device:
    address: str
    name: str | None
    rssi: int
    connectable: bool | None = None
    tx_power: int | None = None
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_data: dict[int, str] = field(default_factory=dict)  # company_id -> hex
    services: list[Service] = field(default_factory=list)  # filled by GATT audit


@dataclass
class Finding:
    device: str
    rule_id: str
    severity: str  # info | low | medium | high
    title: str
    detail: str

    def to_dict(self):
        return asdict(self)

from pydantic import BaseModel


class PortEntry(BaseModel):
    protocol: str
    local_address: str
    port: int | None
    pid: int | None
    process_name: str
    process_path: str | None
    binding_scope: str          # localhost | specific_interface | all_interfaces
    risk: str                   # INFO | LOW | MEDIUM | HIGH
    risk_reason: str


class PortSummary(BaseModel):
    total: int = 0
    tcp: int = 0
    udp: int = 0
    localhost: int = 0
    external: int = 0
    by_risk: dict[str, int] = {}


class HostPortsResult(BaseModel):
    supported: bool
    os: str
    inspected_at: str
    scope_note: str
    warning: str | None = None
    entries: list[PortEntry] = []
    summary: PortSummary = PortSummary()

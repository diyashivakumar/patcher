from fastapi import APIRouter

from app.host import port_inspector
from app.schemas.host import HostPortsResult

router = APIRouter(tags=["host"])


@router.get("/host/ports", response_model=HostPortsResult)
def host_ports():
    """Read-only inspection of local listening ports on this Windows machine.

    Never modifies the host. On non-Windows systems returns supported=false.
    """
    return port_inspector.inspect_ports()

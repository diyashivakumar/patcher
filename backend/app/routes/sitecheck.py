import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.errors import ApiError, not_found
from app.models.audit_log import record
from app.models.site_check import SiteCheck
from app.schemas.site_check import SiteCheckCreate, SiteCheckOut
from app.sitecheck import ssrf
from app.sitecheck.checker import DISCLAIMER, run_site_check

router = APIRouter(tags=["site-checks"])


def _out(row: SiteCheck) -> SiteCheckOut:
    out = SiteCheckOut.model_validate(row)
    out.disclaimer = DISCLAIMER
    return out


@router.post("/site-checks", response_model=SiteCheckOut, status_code=201)
def create_site_check(body: SiteCheckCreate, db: Session = Depends(get_db)):
    """Run a non-invasive external configuration check (HTTPS/TLS, headers, cookies, DNS).

    Only normal GET/HEAD requests are made to a validated, SSRF-protected destination.
    No payloads, crawling or exploitation; response bodies and cookie values are never stored.
    """
    if not body.authorized:
        raise ApiError(422, "authorization_required",
                       "You must confirm you are authorized to assess this website before running a check.")

    # Fail fast (and never persist) if the target is unsafe / unresolvable before any check runs.
    try:
        _, host, _ = ssrf.validate_url(body.url)
    except ssrf.SSRFError as exc:
        raise ApiError(422, "invalid_target", str(exc)) from exc

    result = run_site_check(body.url)
    row = SiteCheck(
        id=uuid.uuid4(), url=result["url"], host=result["host"], authorized=True,
        status=result["status"], final_url=result.get("final_url"),
        resolved_ips=result.get("resolved_ips", []), redirect_chain=result.get("redirect_chain", []),
        posture=result.get("posture", {}), checks=result.get("checks", []),
        error=None if result["status"] == "COMPLETED" else "; ".join(
            c["evidence"] or c["explanation"] for c in result["checks"] if c["status"] == "ERROR") or None,
    )
    db.add(row)
    db.flush()
    record(db, "site_check.run", "site_check", row.id, None, host=host, status=row.status)
    db.commit()
    db.refresh(row)
    return _out(row)


@router.get("/site-checks", response_model=list[SiteCheckOut])
def list_site_checks(db: Session = Depends(get_db)):
    rows = db.scalars(select(SiteCheck).order_by(SiteCheck.created_at.desc())).all()
    return [_out(r) for r in rows]


@router.get("/site-checks/{check_id}", response_model=SiteCheckOut)
def get_site_check(check_id: uuid.UUID, db: Session = Depends(get_db)):
    row = db.get(SiteCheck, check_id)
    if not row:
        raise not_found("Site check")
    return _out(row)

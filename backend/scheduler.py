from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.database import AsyncSessionLocal
from backend.db_models import Domain, Scan
from backend.emailer import EmailConfigError, send_html_email
from backend.scanner import run_scan

scheduler = BackgroundScheduler(timezone="UTC")


def _risk_level(scan_result: dict) -> str:
    return str(scan_result.get("risk_level", "UNKNOWN")).upper()


async def _scan_all_domains() -> None:
    async with AsyncSessionLocal() as db:  # type: AsyncSession
        result = await db.execute(select(Domain).options(selectinload(Domain.user)))
        domains = result.scalars().all()

        for domain in domains:
            scan_result = run_scan(domain.domain)
            new_risk = _risk_level(scan_result)
            old_risk = (domain.current_risk_level or "").upper() if domain.current_risk_level else None

            db.add(Scan(domain_id=domain.id, result=scan_result))
            domain.current_risk_level = new_risk
            domain.last_scanned_at = datetime.now(timezone.utc)

            if old_risk and old_risk != new_risk and domain.user:
                html = (
                    f"<p>Risk level changed for <strong>{domain.domain}</strong>.</p>"
                    f"<p>Previous: <strong>{old_risk}</strong><br/>"
                    f"Current: <strong>{new_risk}</strong></p>"
                )
                try:
                    send_html_email(
                        to_email=domain.user.email,
                        subject=f"SentryDMARC alert: risk level changed for {domain.domain}",
                        html=html,
                        text=f"Risk level changed for {domain.domain}: {old_risk} -> {new_risk}",
                    )
                except EmailConfigError:
                    pass

        await db.commit()


def _scan_all_domains_job() -> None:
    asyncio.run(_scan_all_domains())


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(_scan_all_domains_job, "cron", hour=2, minute=0, id="daily_domain_scan", replace_existing=True)
    scheduler.start()


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)

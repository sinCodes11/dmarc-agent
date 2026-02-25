from __future__ import annotations

import os

import resend


class EmailConfigError(RuntimeError):
    pass


def _ensure_config() -> tuple[str, str]:
    api_key = os.getenv("RESEND_API_KEY", "")
    from_email = os.getenv("FROM_EMAIL", "")
    if not api_key or not from_email:
        raise EmailConfigError("RESEND_API_KEY and FROM_EMAIL are required")
    resend.api_key = api_key
    return api_key, from_email


def send_html_email(to_email: str, subject: str, html: str, text: str | None = None) -> None:
    _, from_email = _ensure_config()
    params: resend.Emails.SendParams = {
        "from": from_email,
        "to": [to_email],
        "subject": subject,
        "html": html,
    }
    if text:
        params["text"] = text
    resend.Emails.send(params)


def send_report(to_email: str, domain: str, scan_result: dict, html_report: str) -> None:
    send_html_email(
        to_email=to_email,
        subject=f"Your DMARC Security Report for {domain}",
        html=html_report,
        text=(
            f"Your DMARC Security Report for {domain}\n"
            f"Risk level: {scan_result.get('risk_level', 'UNKNOWN')}"
        ),
    )

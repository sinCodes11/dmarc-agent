from __future__ import annotations

import os
import resend


class EmailConfigError(RuntimeError):
    pass


def send_report(to_email: str, domain: str, scan_result: dict, html_report: str) -> None:
    api_key = os.getenv("RESEND_API_KEY", "")
    from_email = os.getenv("FROM_EMAIL", "")

    if not api_key or not from_email:
        raise EmailConfigError("RESEND_API_KEY and FROM_EMAIL are required")

    resend.api_key = api_key

    params: resend.Emails.SendParams = {
        "from": from_email,
        "to": [to_email],
        "subject": f"Your DMARC Security Report for {domain}",
        "html": html_report,
        "text": (
            f"Your DMARC Security Report for {domain}\n"
            f"Risk level: {scan_result.get('risk_level', 'UNKNOWN')}"
        ),
    }

    resend.Emails.send(params)

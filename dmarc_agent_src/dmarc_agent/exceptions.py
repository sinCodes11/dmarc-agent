"""Custom exception hierarchy for dmarc-agent."""


class DmarcAgentError(Exception):
    """Base exception for all dmarc-agent errors."""


# ── DNS Errors ─────────────────────────────────────────────────────────────────

class DnsError(DmarcAgentError):
    """Base class for DNS-related errors."""


class DnsTimeoutError(DnsError):
    """DNS query timed out."""


class DnsNxdomainError(DnsError):
    """Domain or record does not exist."""


class DnsServfailError(DnsError):
    """DNS server returned SERVFAIL."""


class DnsRefusedError(DnsError):
    """DNS server refused the query."""


class DnsAllResolversExhaustedError(DnsError):
    """All configured resolvers failed to answer."""


class DnsRateLimitError(DnsError):
    """Rate limit exceeded for DNS queries."""


# ── Validation Errors ──────────────────────────────────────────────────────────

class ValidationError(DmarcAgentError):
    """Base class for input validation errors."""


class InvalidDomainError(ValidationError):
    """The provided domain name is invalid."""


# ── Parse Errors ───────────────────────────────────────────────────────────────

class SpfParseError(DmarcAgentError):
    """Failed to parse SPF record."""


class DmarcParseError(DmarcAgentError):
    """Failed to parse DMARC record."""


class RecursionLimitError(DmarcAgentError):
    """Recursive resolution exceeded the allowed depth."""

"""DNS query engine: multi-resolver fallback, in-memory TTL cache, rate limiting."""

import re
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

import dns.exception
import dns.rdatatype
import dns.resolver

from .exceptions import (
    DnsAllResolversExhaustedError,
    DnsNxdomainError,
    DnsServfailError,
    DnsTimeoutError,
    InvalidDomainError,
)
from .models import DnsRecord, DnsResponse, DnsStatus


# ── Rate Limiter ───────────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket rate limiter. Thread-safe."""

    def __init__(self, rate: float = 50.0):
        self._rate = rate          # tokens per second
        self._tokens = rate
        self._last_check = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a token is available."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_check
            self._last_check = now
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            if self._tokens < 1.0:
                sleep_time = (1.0 - self._tokens) / self._rate
                time.sleep(sleep_time)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


# ── DNS Cache ──────────────────────────────────────────────────────────────────

class DnsCache:
    """In-memory LRU-ish cache with TTL enforcement."""

    MAX_ENTRIES = 10_000
    MIN_TTL = 300
    MAX_TTL = 86_400
    NXDOMAIN_TTL = 300
    SERVFAIL_TTL = 30

    def __init__(self):
        self._store: dict[str, tuple[DnsResponse, datetime]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _make_key(domain: str, record_type: str) -> str:
        return f"{record_type.upper()}:{domain.lower().rstrip('.')}"

    def get(self, domain: str, record_type: str) -> Optional[DnsResponse]:
        key = self._make_key(domain, record_type)
        with self._lock:
            if key not in self._store:
                return None
            response, expires_at = self._store[key]
            if datetime.utcnow() > expires_at:
                del self._store[key]
                return None
            response.cache_hit = True
            return response

    def put(self, domain: str, record_type: str, response: DnsResponse) -> None:
        key = self._make_key(domain, record_type)
        ttl = self._effective_ttl(response)
        expires_at = datetime.utcnow() + timedelta(seconds=ttl)
        with self._lock:
            if len(self._store) >= self.MAX_ENTRIES:
                self._evict_expired()
            self._store[key] = (response, expires_at)

    def _effective_ttl(self, response: DnsResponse) -> int:
        if response.status == DnsStatus.NXDOMAIN:
            return self.NXDOMAIN_TTL
        if response.status == DnsStatus.SERVFAIL:
            return self.SERVFAIL_TTL
        if not response.records:
            return self.MIN_TTL
        raw_ttl = min(r.ttl for r in response.records) if response.records else self.MIN_TTL
        return max(self.MIN_TTL, min(self.MAX_TTL, raw_ttl))

    def invalidate(self, domain: str, record_type: Optional[str] = None) -> None:
        with self._lock:
            if record_type:
                key = self._make_key(domain, record_type)
                self._store.pop(key, None)
            else:
                prefix = f":{domain.lower().rstrip('.')}"
                keys_to_remove = [k for k in self._store if k.endswith(prefix)]
                for k in keys_to_remove:
                    del self._store[k]

    def flush(self) -> None:
        with self._lock:
            self._store.clear()

    def _evict_expired(self) -> None:
        now = datetime.utcnow()
        expired = [k for k, (_, exp) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]


# ── DNS Fetcher ────────────────────────────────────────────────────────────────

_DOMAIN_PATTERN = re.compile(
    r"^(?:_?[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

RESOLVERS = [
    {"name": "Cloudflare", "addresses": ["1.1.1.1", "1.0.0.1"]},
    {"name": "Google",     "addresses": ["8.8.8.8", "8.8.4.4"]},
    {"name": "Quad9",      "addresses": ["9.9.9.9", "149.112.112.112"]},
]

TIMEOUT = 5.0
MAX_RETRIES = 2


class DnsFetcher:
    def __init__(self, cache: Optional[DnsCache] = None, rate_limiter: Optional[RateLimiter] = None):
        self._cache = cache or DnsCache()
        self._rate_limiter = rate_limiter or RateLimiter(rate=50.0)

    def query(self, domain: str, record_type: str) -> DnsResponse:
        """Main entry point. Cache-first, then tries resolvers in order."""
        domain = self._validate_domain(domain)

        cached = self._cache.get(domain, record_type)
        if cached:
            return cached

        last_error: Optional[Exception] = None
        for resolver_group in RESOLVERS:
            for ip in resolver_group["addresses"]:
                for attempt in range(MAX_RETRIES):
                    try:
                        self._rate_limiter.acquire()
                        response = self._query_resolver(ip, domain, record_type)
                        self._cache.put(domain, record_type, response)
                        return response
                    except DnsNxdomainError:
                        # NXDOMAIN is definitive — cache and return immediately
                        response = DnsResponse(
                            domain=domain,
                            record_type=record_type,
                            status=DnsStatus.NXDOMAIN,
                            resolver_used=ip,
                        )
                        self._cache.put(domain, record_type, response)
                        return response
                    except (DnsTimeoutError, DnsServfailError) as e:
                        last_error = e
                        if attempt < MAX_RETRIES - 1:
                            continue
                        break  # try next resolver IP
                    except Exception as e:
                        last_error = e
                        break

        # All resolvers exhausted
        raise DnsAllResolversExhaustedError(
            f"All DNS resolvers failed for {record_type} {domain}: {last_error}"
        )

    def _validate_domain(self, domain: str) -> str:
        domain = domain.lower().strip().rstrip(".")
        if len(domain) > 253:
            raise InvalidDomainError(f"Domain too long: {domain}")
        if not _DOMAIN_PATTERN.match(domain):
            raise InvalidDomainError(f"Invalid domain name: {domain}")
        return domain

    def _query_resolver(self, resolver_ip: str, domain: str, record_type: str) -> DnsResponse:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_ip]
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT

        start = time.monotonic()
        try:
            rdtype = dns.rdatatype.from_text(record_type)
            answer = resolver.resolve(domain, rdtype)
            elapsed = (time.monotonic() - start) * 1000

            records = self._parse_records(answer, record_type)
            return DnsResponse(
                domain=domain,
                record_type=record_type,
                status=DnsStatus.NOERROR,
                records=records,
                resolver_used=resolver_ip,
                response_time_ms=elapsed,
            )
        except dns.resolver.NXDOMAIN:
            raise DnsNxdomainError(f"NXDOMAIN: {domain}")
        except dns.resolver.NoAnswer:
            # Record type doesn't exist but domain does
            return DnsResponse(
                domain=domain,
                record_type=record_type,
                status=DnsStatus.NOERROR,
                records=[],
                resolver_used=resolver_ip,
                response_time_ms=(time.monotonic() - start) * 1000,
            )
        except dns.exception.Timeout:
            raise DnsTimeoutError(f"Timeout querying {resolver_ip} for {record_type} {domain}")
        except dns.resolver.NoNameservers:
            raise DnsServfailError(f"No nameservers available for {domain}")
        except dns.exception.DNSException as e:
            raise DnsServfailError(f"DNS error from {resolver_ip}: {e}")

    def _parse_records(self, answer, record_type: str) -> list:
        records = []
        ttl = answer.rrset.ttl if answer.rrset else 300

        for rdata in answer:
            if record_type == "TXT":
                # Concatenate multi-string TXT records per RFC
                value = b"".join(rdata.strings).decode("ascii", errors="replace")
            elif record_type == "MX":
                value = f"{rdata.preference} {rdata.exchange}"
            elif record_type in ("A", "AAAA"):
                value = str(rdata.address)
            elif record_type == "PTR":
                value = str(rdata.target)
            else:
                value = str(rdata)
            records.append(DnsRecord(record_type=record_type, value=value, ttl=ttl))

        return records

    # ── Convenience methods ────────────────────────────────────────────────────

    def query_txt(self, domain: str) -> DnsResponse:
        return self.query(domain, "TXT")

    def query_mx(self, domain: str) -> DnsResponse:
        return self.query(domain, "MX")

    def query_a(self, domain: str) -> DnsResponse:
        return self.query(domain, "A")

    def query_aaaa(self, domain: str) -> DnsResponse:
        return self.query(domain, "AAAA")


def create_fetcher() -> DnsFetcher:
    """Module-level factory for CLI use."""
    return DnsFetcher(cache=DnsCache(), rate_limiter=RateLimiter(rate=50.0))

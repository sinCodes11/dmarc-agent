# Purpose and Scope

Defines DNS query execution, response parsing, caching logic, error handling, and resolver management for the DMARC Security Agent system. Governs how DNS TXT, MX, A, AAAA, PTR, and CNAME records are retrieved, validated, cached, and provided to consuming components.

# Execution Context

- Agent operates as DNS query execution and caching layer
- Applies to: All DNS lookups required by SPF validation, DKIM detection, DMARC analysis
- Input: Domain names, record types, query parameters
- Output: Parsed DNS responses, cached results, error states
- Integration: Provides DNS data to CLAUDE.md, spf-validator.md, dmarc-parser.md, automation-workflow.md

# Authoritative Sources of Truth

1. RFC 1035 - Domain Names: Implementation and Specification
2. RFC 8484 - DNS Queries over HTTPS (DoH)
3. RFC 7858 - DNS over TLS (DoT)
4. RFC 7208 Section 4.6.4 - SPF DNS lookup limits
5. Live DNS resolver responses
6. CLAUDE.md input processing requirements

# Planning and Execution Rules

## Query Execution Principles

- Cache-first: Always check cache before issuing DNS query
- TTL-aware: Respect DNS TTL for cache expiration
- Rate-limited: Enforce query rate limits to prevent resolver abuse
- Fail-safe: Return clear error states, never fabricate responses
- Logged: Every query and response logged with metadata
- Resolver-resilient: Fallback resolvers if primary fails

## Execution Sequence

**Per DNS query:**
1. Validate input (domain name, record type)
2. Normalize domain name (lowercase, trailing dot handling)
3. Check cache for valid (non-expired) entry
4. If cached: return cached result
5. If not cached: execute DNS query
6. Parse and validate response
7. Store in cache with TTL
8. Return result to caller

**No steps may be skipped. Cache check is mandatory.**

# DNS Query Specifications

## Supported Record Types

| Record Type | Usage in System | Query Format |
|-------------|----------------|--------------|
| TXT | SPF, DKIM, DMARC records | `dig TXT <domain>` |
| MX | SPF mx mechanism validation | `dig MX <domain>` |
| A | SPF a mechanism, IP resolution | `dig A <domain>` |
| AAAA | SPF a mechanism (IPv6) | `dig AAAA <domain>` |
| PTR | Reverse DNS for source classification | `dig PTR <reverse-ip>` |
| CNAME | Alias resolution, DKIM selector chains | `dig CNAME <domain>` |
| NS | Nameserver identification | `dig NS <domain>` |

## Query Parameters

```json
{
  "query": {
    "domain": "example.com",
    "record_type": "TXT",
    "options": {
      "timeout_ms": 5000,
      "retries": 2,
      "resolver": "primary|fallback|specific",
      "dnssec": false,
      "recursion_desired": true
    }
  }
}
```

## DMARC-Specific Query Patterns

**Full domain analysis requires:**
```
1. TXT  example.com                          → SPF record
2. TXT  _dmarc.example.com                   → DMARC record
3. TXT  <selector>._domainkey.example.com    → DKIM record (per selector)
4. MX   example.com                          → Mail exchangers
5. A    example.com                          → Domain IP (for SPF a mechanism)
6. AAAA example.com                          → Domain IPv6
```

**Common DKIM selectors to probe (only when explicitly requested):**
```
google._domainkey.<domain>       → Google Workspace
selector1._domainkey.<domain>    → Microsoft 365
selector2._domainkey.<domain>    → Microsoft 365 (secondary)
default._domainkey.<domain>      → Generic default
k1._domainkey.<domain>           → Mailchimp
s1._domainkey.<domain>           → Generic
s2._domainkey.<domain>           → Generic
```

**DKIM probing constraints:**
- Only probe if explicitly requested by user or automation config
- Never assume DKIM presence from selector probe results alone
- Document which selectors were probed and results
- Flag as "detected" only with valid public key in response

## SPF Recursive Query Pattern

**For SPF include resolution:**
```
function resolveSpfIncludes(domain, depth = 0):
    if depth > 10:
        return ERROR("Maximum recursion depth exceeded")

    spf_record = query(TXT, domain)

    for mechanism in spf_record.includes:
        included_spf = query(TXT, mechanism.domain)
        resolveSpfIncludes(mechanism.domain, depth + 1)

    for mechanism in spf_record.mx:
        mx_records = query(MX, mechanism.domain or domain)
        for mx in mx_records:
            a_records = query(A, mx.hostname)
            aaaa_records = query(AAAA, mx.hostname)

    for mechanism in spf_record.a:
        a_records = query(A, mechanism.domain or domain)
        aaaa_records = query(AAAA, mechanism.domain or domain)
```

# Resolver Configuration

## Primary Resolver

```json
{
  "resolvers": {
    "primary": {
      "addresses": ["1.1.1.1", "1.0.0.1"],
      "name": "Cloudflare DNS",
      "protocol": "udp",
      "port": 53,
      "timeout_ms": 5000,
      "max_retries": 2
    },
    "fallback": {
      "addresses": ["8.8.8.8", "8.8.4.4"],
      "name": "Google Public DNS",
      "protocol": "udp",
      "port": 53,
      "timeout_ms": 5000,
      "max_retries": 2
    },
    "tertiary": {
      "addresses": ["9.9.9.9", "149.112.112.112"],
      "name": "Quad9 DNS",
      "protocol": "udp",
      "port": 53,
      "timeout_ms": 5000,
      "max_retries": 1
    }
  }
}
```

## Resolver Selection Logic

```
function selectResolver(query, attempt):
    if attempt == 1:
        return primary_resolver
    elif attempt == 2:
        return fallback_resolver
    elif attempt == 3:
        return tertiary_resolver
    else:
        return ERROR("All resolvers exhausted")
```

## Resolver Health Monitoring

**Track per resolver:**
```json
{
  "resolver_health": {
    "address": "1.1.1.1",
    "queries_total": 10000,
    "queries_failed": 5,
    "avg_response_ms": 25,
    "p95_response_ms": 80,
    "last_failure": "ISO-8601",
    "status": "healthy|degraded|unhealthy"
  }
}
```

**Health thresholds:**
- Degraded: failure rate > 5% or p95 > 500ms
- Unhealthy: failure rate > 20% or p95 > 2000ms or 3 consecutive failures
- Auto-recovery: check every 60 seconds when unhealthy

# Caching Logic

## Cache Architecture

**Cache layers:**
1. In-memory cache (fastest, limited size)
2. File-based cache (persistent across restarts, larger capacity)

**Cache key format:**
```
<record_type>:<normalized_domain>
```

**Examples:**
```
TXT:example.com
TXT:_dmarc.example.com
MX:example.com
TXT:google._domainkey.example.com
```

## TTL Management

**Cache entry structure:**
```json
{
  "key": "TXT:_dmarc.example.com",
  "domain": "_dmarc.example.com",
  "record_type": "TXT",
  "response": {
    "status": "NOERROR|NXDOMAIN|SERVFAIL|TIMEOUT",
    "records": [],
    "raw_response": "string"
  },
  "ttl": {
    "original": 3600,
    "effective": 3600,
    "cached_at": "ISO-8601",
    "expires_at": "ISO-8601"
  },
  "metadata": {
    "resolver": "1.1.1.1",
    "response_time_ms": 25,
    "query_count": 1
  }
}
```

**TTL rules:**
- Use TTL from DNS response as primary
- Minimum TTL floor: 300 seconds (5 minutes)
- Maximum TTL ceiling: 86400 seconds (24 hours)
- NXDOMAIN responses cached for 300 seconds (per RFC 2308)
- SERVFAIL responses cached for 30 seconds (prevent hammering)
- TIMEOUT responses not cached (retry immediately)

**TTL calculation:**
```
function effectiveTTL(dns_ttl):
    if dns_ttl < 300:
        return 300  # Floor
    elif dns_ttl > 86400:
        return 86400  # Ceiling
    else:
        return dns_ttl
```

## Cache Invalidation

**Invalidation triggers:**
- TTL expiration (automatic)
- Manual invalidation (re-analysis request)
- Domain-wide flush (when user reports DNS changes)
- Full cache clear (maintenance operation)

**Invalidation commands:**
```
cache_invalidate(domain, record_type)    → Remove specific entry
cache_invalidate_domain(domain)          → Remove all entries for domain
cache_flush()                            → Clear entire cache
cache_refresh(domain, record_type)       → Fetch fresh and update
```

## Cache Size Management

**Limits:**
```json
{
  "cache_limits": {
    "max_entries": 10000,
    "max_memory_mb": 50,
    "eviction_policy": "lru",
    "cleanup_interval_seconds": 300
  }
}
```

**Eviction priority (LRU with priority):**
1. Expired entries (remove first)
2. NXDOMAIN entries (lowest priority to keep)
3. Least recently used entries
4. Never evict entries currently being referenced by active analysis

# Response Parsing

## TXT Record Parsing

**SPF record extraction:**
```
function extractSPF(txt_records):
    spf_records = []
    for record in txt_records:
        # Concatenate multi-string TXT records
        full_text = concatenate(record.strings)
        if full_text.startswith("v=spf1"):
            spf_records.append(full_text)

    if len(spf_records) == 0:
        return { "status": "absent", "record": null }
    elif len(spf_records) == 1:
        return { "status": "present", "record": spf_records[0] }
    else:
        return { "status": "duplicate", "records": spf_records, "warning": "Multiple SPF records" }
```

**DMARC record extraction:**
```
function extractDMARC(txt_records):
    for record in txt_records:
        full_text = concatenate(record.strings)
        if full_text.startswith("v=DMARC1"):
            return { "status": "present", "record": full_text }
    return { "status": "absent", "record": null }
```

**DKIM record extraction:**
```
function extractDKIM(txt_records):
    for record in txt_records:
        full_text = concatenate(record.strings)
        if "p=" in full_text and ("v=DKIM1" in full_text or "k=rsa" in full_text):
            return { "status": "present", "record": full_text }
    return { "status": "absent", "record": null }
```

## MX Record Parsing

```json
{
  "mx_records": [
    {
      "priority": 10,
      "hostname": "mail.example.com",
      "resolved_ips": ["1.2.3.4", "5.6.7.8"]
    }
  ],
  "count": 2,
  "warnings": []
}
```

## Response Status Handling

| DNS Status | Meaning | Cache | Action |
|------------|---------|-------|--------|
| NOERROR | Success (may have 0 records) | Yes (TTL) | Process records |
| NXDOMAIN | Domain does not exist | Yes (300s) | Report as absent |
| SERVFAIL | Server failure | Yes (30s) | Retry with fallback |
| REFUSED | Query refused | No | Try different resolver |
| TIMEOUT | No response | No | Retry with fallback |
| FORMERR | Malformed query | No | Log error, check query |

# Rate Limiting

## Query Rate Limits

```json
{
  "rate_limits": {
    "per_resolver": {
      "queries_per_second": 50,
      "queries_per_minute": 500,
      "burst_limit": 20
    },
    "per_domain": {
      "queries_per_minute": 30,
      "concurrent_queries": 5
    },
    "global": {
      "queries_per_second": 100,
      "queries_per_minute": 1000
    }
  }
}
```

## Rate Limit Enforcement

```
function executeQuery(domain, record_type):
    if globalRateLimit.exceeded():
        wait(globalRateLimit.reset_time)

    if perDomainRateLimit(domain).exceeded():
        wait(perDomainRateLimit(domain).reset_time)

    resolver = selectResolver()

    if perResolverRateLimit(resolver).exceeded():
        resolver = selectNextResolver()

    return resolver.query(domain, record_type)
```

# Error Handling

## Error Classification

```json
{
  "error_types": {
    "DNS_TIMEOUT": {
      "description": "Query timed out waiting for response",
      "retryable": true,
      "max_retries": 3,
      "action": "Try fallback resolver"
    },
    "DNS_SERVFAIL": {
      "description": "Authoritative server failure",
      "retryable": true,
      "max_retries": 2,
      "action": "Try fallback resolver, check domain validity"
    },
    "DNS_NXDOMAIN": {
      "description": "Domain does not exist",
      "retryable": false,
      "action": "Report as absent, cache negative result"
    },
    "DNS_REFUSED": {
      "description": "Resolver refused query",
      "retryable": true,
      "max_retries": 2,
      "action": "Switch resolver immediately"
    },
    "NETWORK_ERROR": {
      "description": "Network connectivity failure",
      "retryable": true,
      "max_retries": 3,
      "action": "Check connectivity, try fallback"
    },
    "INVALID_DOMAIN": {
      "description": "Domain name fails validation",
      "retryable": false,
      "action": "Return error to caller, do not query"
    },
    "RECURSION_LIMIT": {
      "description": "SPF include depth exceeded 10",
      "retryable": false,
      "action": "Return partial results with warning"
    }
  }
}
```

## Error Response Format

```json
{
  "query": {
    "domain": "example.com",
    "record_type": "TXT"
  },
  "error": {
    "type": "DNS_TIMEOUT",
    "message": "Query timed out after 5000ms",
    "resolver": "1.1.1.1",
    "attempts": 3,
    "last_attempt": "ISO-8601"
  },
  "fallback_attempted": true,
  "partial_results": null
}
```

# Logging

## Query Log Format

```json
{
  "timestamp": "ISO-8601",
  "request_id": "uuid",
  "query": {
    "domain": "example.com",
    "record_type": "TXT",
    "resolver": "1.1.1.1"
  },
  "response": {
    "status": "NOERROR",
    "record_count": 2,
    "response_time_ms": 25,
    "cache_hit": false,
    "ttl": 3600
  }
}
```

## Metrics

**Track and expose:**
```json
{
  "metrics": {
    "queries_total": "counter",
    "queries_cached": "counter",
    "queries_failed": "counter",
    "query_duration_ms": "histogram",
    "cache_hit_rate": "gauge",
    "cache_size": "gauge",
    "resolver_health": "per-resolver gauge",
    "rate_limit_hits": "counter"
  }
}
```

# Domain Name Validation

## Validation Rules

```
function validateDomain(domain):
    # Remove trailing dot if present
    domain = domain.rstrip('.')

    # Total length check
    if len(domain) > 253:
        return ERROR("Domain exceeds 253 characters")

    # Label checks
    labels = domain.split('.')
    if len(labels) < 2:
        return ERROR("Domain must have at least 2 labels")

    for label in labels:
        if len(label) == 0:
            return ERROR("Empty label (consecutive dots)")
        if len(label) > 63:
            return ERROR("Label exceeds 63 characters")
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return ERROR("Invalid characters in label")

    return OK(domain.lower())
```

## Subdomain Handling

**DMARC subdomain queries:**
```
_dmarc.<domain>                      → DMARC policy
<selector>._domainkey.<domain>       → DKIM public key
```

**Auto-prefix logic:**
```
function buildQueryDomain(domain, record_purpose):
    if record_purpose == "dmarc":
        return "_dmarc." + domain
    elif record_purpose == "dkim":
        return selector + "._domainkey." + domain
    elif record_purpose == "spf":
        return domain
    elif record_purpose == "mx":
        return domain
    else:
        return domain
```

# Integration Points

## CLAUDE.md Integration

- Provides raw DNS data for analysis input
- Executes queries specified in CLAUDE.md input validation
- Returns structured responses per CLAUDE.md expected format
- Handles "verify_spf", "verify_dmarc", "verify_dkim" commands

## spf-validator.md Integration

- Executes recursive include resolution queries
- Provides MX record resolution for lookup counting
- Returns A/AAAA records for SPF a mechanism validation
- Enforces 10-lookup limit tracking across recursive chain

## dmarc-parser.md Integration

- Provides reverse DNS (PTR) for source IP classification
- Resolves hostnames for sender identification
- Caches frequently queried source IPs

## automation-workflow.md Integration

- Rate limits coordinated with automation batch sizes
- Cache warming for scheduled scan domains
- Bulk query optimization for batch analysis
- Query metrics exposed for monitoring

# Constraints and Prohibitions

## Critical Prohibitions

**Never:**
- Fabricate DNS responses
- Return cached data past TTL without marking as stale
- Query without rate limit enforcement
- Log full DKIM private key data (should never appear in DNS, but guard against)
- Bypass cache for performance testing in production
- Use a single resolver without fallback configuration
- Ignore NXDOMAIN responses (they are valid data)
- Execute queries for invalid domain names

**Always:**
- Validate domain names before querying
- Respect TTL values from DNS responses
- Enforce rate limits per resolver and globally
- Log all queries with timing metadata
- Cache negative responses (NXDOMAIN) appropriately
- Provide clear error states with context
- Fall back to secondary resolvers on failure
- Track and report resolver health

# Verification Criteria

## Query Complete When

- [ ] Domain name validated
- [ ] Cache checked before query
- [ ] Query executed with appropriate resolver
- [ ] Response parsed and validated
- [ ] Result cached with correct TTL
- [ ] Error handled (if applicable)
- [ ] Response returned to caller in expected format
- [ ] Query logged with metadata
- [ ] Rate limits respected

## System Health When

- [ ] All configured resolvers reachable
- [ ] Cache hit rate > 30% under normal operation
- [ ] Average query time < 100ms (cached) / < 500ms (uncached)
- [ ] Error rate < 5% over 1-hour window
- [ ] No rate limit violations
- [ ] Cache size within configured limits
- [ ] Stale entries cleaned up on schedule

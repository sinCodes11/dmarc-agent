# Purpose and Scope

Defines SPF record syntax validation, DNS lookup counting, mechanism evaluation, and compliance verification logic for the DMARC Security Agent system. Governs record parsing, RFC 7208 compliance checks, lookup limit enforcement, and remediation guidance.

# Execution Context

- Agent operates as SPF record validator and analyzer
- Applies to: SPF TXT record syntax validation, lookup counting, mechanism evaluation
- Input: Raw SPF TXT record strings, DNS query results
- Output: Validation results, lookup counts, compliance status, remediation suggestions
- Integration: Feeds into CLAUDE.md SPF analysis, dns-fetcher.md for recursive lookups, report-generator.md for findings

# Authoritative Sources of Truth

1. RFC 7208 - Sender Policy Framework (SPF)
2. RFC 4408 - SPF (original, superseded by 7208)
3. RFC 6652 - SPF Authentication Failure Reporting
4. Observed DNS TXT record data
5. CLAUDE.md SPF analysis protocol

# Planning and Execution Rules

## Validation Sequence

**Mandatory execution order:**
1. Extract SPF record from TXT records
2. Validate version identifier
3. Tokenize mechanisms and modifiers
4. Validate each mechanism syntax
5. Count DNS-querying mechanisms
6. Evaluate qualifier logic
7. Check for common misconfigurations
8. Generate validation report
9. Provide remediation if issues found

**No steps may be skipped or reordered**

## Input Processing

**Accept only:**
- Raw TXT record string containing SPF data
- Multiple TXT records for duplicate detection
- DNS query output from dig or equivalent

**Never accept:**
- SPF records not retrieved from DNS (user-composed records require explicit labeling)
- Partial records without flagging truncation
- Records from untrusted secondary sources without verification note

# SPF Record Syntax Validation

## Version Identifier

**Required:**
```
v=spf1
```

**Validation rules:**
- Must be the first token in the record
- Must be exactly `v=spf1` (case-sensitive for value)
- No spaces before `v=spf1`
- Only one SPF record per domain (flag duplicates)

**Error conditions:**
```json
{
  "missing_version": "No v=spf1 found - record is not valid SPF",
  "wrong_version": "Found v=spf2 or similar - unsupported version",
  "duplicate_records": "Multiple SPF TXT records found - RFC violation",
  "version_not_first": "v=spf1 is not the first token"
}
```

## Mechanism Validation

**Valid mechanisms (RFC 7208 Section 5):**

| Mechanism | Syntax | DNS Lookups | Description |
|-----------|--------|-------------|-------------|
| `all` | `all` | 0 | Match all (must be last) |
| `include` | `include:<domain>` | 1+ (recursive) | Include another domain's SPF |
| `a` | `a` or `a:<domain>` or `a:<domain>/<prefix>` | 1 | Match A/AAAA record |
| `mx` | `mx` or `mx:<domain>` or `mx:<domain>/<prefix>` | 1 (+ 1 per MX) | Match MX record |
| `ip4` | `ip4:<ip4-address>` or `ip4:<ip4-network>/<prefix>` | 0 | Match IPv4 address/range |
| `ip6` | `ip6:<ip6-address>` or `ip6:<ip6-network>/<prefix>` | 0 | Match IPv6 address/range |
| `exists` | `exists:<domain>` | 1 | Match if domain resolves |
| `ptr` | `ptr` or `ptr:<domain>` | 1+ | Reverse DNS (deprecated) |

**Qualifier prefixes:**
| Qualifier | Meaning | Symbol |
|-----------|---------|--------|
| Pass | Authorized sender | `+` (default if omitted) |
| Fail | Not authorized | `-` |
| SoftFail | Not authorized but transitioning | `~` |
| Neutral | No assertion | `?` |

**Syntax validation per mechanism:**

```
include:
  - Must have domain argument
  - Domain must be valid FQDN
  - Recursive lookup required

a:
  - Domain argument optional (defaults to current domain)
  - Optional CIDR prefix (/0-32 for IPv4, /0-128 for IPv6)
  - Dual CIDR allowed: a:<domain>/<ip4-prefix>//<ip6-prefix>

mx:
  - Domain argument optional (defaults to current domain)
  - Optional CIDR prefix
  - Each MX record costs an additional lookup

ip4:
  - Must have valid IPv4 address or CIDR range
  - Prefix length 0-32
  - No DNS lookup required

ip6:
  - Must have valid IPv6 address or CIDR range
  - Prefix length 0-128
  - No DNS lookup required

exists:
  - Must have domain argument
  - Often uses macros

ptr:
  - DEPRECATED per RFC 7208 Section 5.5
  - Flag as warning if encountered
  - Expensive: requires reverse DNS + forward verification

all:
  - Must be last mechanism
  - No arguments
  - Qualifier determines default behavior
```

## Modifier Validation

**Valid modifiers (RFC 7208 Section 6):**

```
redirect=<domain>
  - Replaces current SPF evaluation with target domain's SPF
  - Only processed if no mechanisms match
  - Counts as 1 DNS lookup
  - Cannot coexist with "all" mechanism (flag as warning)

exp=<domain>
  - Explanation string for failures
  - Counts as 1 DNS lookup
  - TXT record of target provides explanation text
```

**Invalid modifiers:**
- Any modifier not defined in RFC 7208
- Duplicate modifiers of the same type
- Modifiers with invalid domain arguments

# DNS Lookup Counting

## Lookup Limit Enforcement

**RFC 7208 Section 4.6.4:**
- Maximum 10 DNS-querying mechanisms/modifiers per SPF evaluation
- Exceeding limit results in `permerror`
- Limit applies to entire evaluation chain (including recursive includes)

**Mechanisms that consume lookups:**

| Mechanism/Modifier | Lookups Consumed |
|--------------------|-----------------|
| `include` | 1 (+ recursive target lookups) |
| `a` | 1 |
| `mx` | 1 (+ 1 per MX record returned, up to 10 MX limit) |
| `ptr` | 1 (+ reverse lookups) |
| `exists` | 1 |
| `redirect` | 1 |
| `exp` | 1 |

**Mechanisms that do NOT consume lookups:**
| Mechanism | Lookups |
|-----------|---------|
| `ip4` | 0 |
| `ip6` | 0 |
| `all` | 0 |

## Lookup Counting Algorithm

```
function countLookups(spf_record, depth = 0):
    if depth > 10:
        return ERROR("Recursive depth exceeded - possible loop")

    lookups = 0

    for mechanism in spf_record.mechanisms:
        if mechanism.type in ['include']:
            lookups += 1
            target_spf = dns_fetch(mechanism.domain)
            lookups += countLookups(target_spf, depth + 1)

        elif mechanism.type in ['a', 'exists', 'ptr']:
            lookups += 1

        elif mechanism.type == 'mx':
            lookups += 1
            mx_count = count_mx_records(mechanism.domain)
            if mx_count > 10:
                FLAG("MX lookup limit exceeded: void lookup")

        elif mechanism.type in ['ip4', 'ip6', 'all']:
            lookups += 0  // No DNS lookup

    for modifier in spf_record.modifiers:
        if modifier.type in ['redirect', 'exp']:
            lookups += 1
            if modifier.type == 'redirect':
                target_spf = dns_fetch(modifier.domain)
                lookups += countLookups(target_spf, depth + 1)

    return lookups
```

## Lookup Count Output

```json
{
  "total_lookups": 8,
  "limit": 10,
  "status": "within_limit|at_limit|exceeded",
  "breakdown": [
    {
      "mechanism": "include:_spf.google.com",
      "direct_lookups": 1,
      "recursive_lookups": 3,
      "subtotal": 4,
      "chain": [
        "include:_netblocks.google.com (1)",
        "include:_netblocks2.google.com (1)",
        "include:_netblocks3.google.com (1)"
      ]
    },
    {
      "mechanism": "include:spf.protection.outlook.com",
      "direct_lookups": 1,
      "recursive_lookups": 2,
      "subtotal": 3
    },
    {
      "mechanism": "mx",
      "direct_lookups": 1,
      "recursive_lookups": 0,
      "subtotal": 1
    }
  ],
  "remaining_lookups": 2,
  "warnings": [
    "At 8/10 lookups. Adding more include mechanisms may exceed limit."
  ]
}
```

# Common Misconfiguration Detection

## Misconfiguration Rules

**Critical misconfigurations:**

```json
[
  {
    "id": "SPF-CRIT-001",
    "name": "pass_all",
    "pattern": "+all or all (without qualifier)",
    "severity": "critical",
    "description": "SPF record authorizes ALL senders - defeats purpose entirely",
    "remediation": "Replace +all with -all after verifying authorized senders"
  },
  {
    "id": "SPF-CRIT-002",
    "name": "no_spf_record",
    "pattern": "No TXT record with v=spf1",
    "severity": "critical",
    "description": "No SPF record present - no sender validation",
    "remediation": "Create SPF record with authorized senders and -all"
  },
  {
    "id": "SPF-CRIT-003",
    "name": "lookup_exceeded",
    "pattern": "DNS lookups > 10",
    "severity": "critical",
    "description": "SPF evaluation will return permerror - effectively no protection",
    "remediation": "Flatten includes, remove unused mechanisms, use ip4/ip6 where possible"
  }
]
```

**High misconfigurations:**

```json
[
  {
    "id": "SPF-HIGH-001",
    "name": "softfail_all",
    "pattern": "~all",
    "severity": "high",
    "description": "Softfail allows spoofed mail with warning flag only",
    "remediation": "Change ~all to -all after confirming all senders are listed"
  },
  {
    "id": "SPF-HIGH-002",
    "name": "duplicate_records",
    "pattern": "Multiple TXT records with v=spf1",
    "severity": "high",
    "description": "RFC violation - causes undefined behavior in evaluation",
    "remediation": "Merge into single SPF record"
  },
  {
    "id": "SPF-HIGH-003",
    "name": "ptr_mechanism",
    "pattern": "ptr or ptr:<domain>",
    "severity": "high",
    "description": "Deprecated mechanism - slow, unreliable, and resource-intensive",
    "remediation": "Replace with a: or ip4:/ip6: mechanisms"
  },
  {
    "id": "SPF-HIGH-004",
    "name": "overly_broad_include",
    "pattern": "include:<entire-cloud-provider>",
    "severity": "high",
    "description": "Authorizes potentially millions of IPs from shared infrastructure",
    "remediation": "Use more specific include or ip4 ranges"
  }
]
```

**Medium misconfigurations:**

```json
[
  {
    "id": "SPF-MED-001",
    "name": "neutral_all",
    "pattern": "?all",
    "severity": "medium",
    "description": "Neutral result provides no actionable signal to receivers",
    "remediation": "Change to ~all (transitional) or -all (enforced)"
  },
  {
    "id": "SPF-MED-002",
    "name": "near_lookup_limit",
    "pattern": "DNS lookups 8-10",
    "severity": "medium",
    "description": "Close to 10-lookup limit - fragile to upstream changes",
    "remediation": "Consider flattening includes to reduce lookup count"
  },
  {
    "id": "SPF-MED-003",
    "name": "redirect_with_all",
    "pattern": "redirect= and all in same record",
    "severity": "medium",
    "description": "redirect is ignored when all mechanism present - likely misconfiguration",
    "remediation": "Remove redirect or remove all mechanism"
  },
  {
    "id": "SPF-MED-004",
    "name": "missing_common_provider",
    "pattern": "Known email provider not in SPF",
    "severity": "medium",
    "description": "Email provider detected in DMARC reports but not in SPF",
    "remediation": "Add appropriate include mechanism for provider"
  }
]
```

# SPF Record Generation

## Generation Rules

**Template:**
```
v=spf1 [ip4/ip6 mechanisms] [a/mx mechanisms] [include mechanisms] -all
```

**Ordering (most specific to least specific):**
1. `ip4:` and `ip6:` (direct IP authorization)
2. `a` and `a:<domain>` (A record matching)
3. `mx` and `mx:<domain>` (MX record matching)
4. `include:<domain>` (delegated authorization)
5. `-all` (terminator - always last)

**Pre-generation validation:**
- Count total DNS lookups (must be <= 10)
- Verify no duplicate mechanisms
- Confirm all domains are valid FQDNs
- Check total record length (must be <= 255 chars per TXT string, can span multiple strings)

**Record length handling:**
- Single TXT string limit: 255 characters
- Multiple strings concatenated by receiver
- Total SPF record should stay under 450 characters when practical
- If exceeding limits, recommend flattening includes

## Flattening Recommendations

**When lookup count exceeds limit:**
```
Strategy 1: Replace include with ip4/ip6 ranges
  - Resolve include target to IP ranges
  - Replace with explicit ip4:/ip6: mechanisms
  - Trade-off: Must update when provider changes IPs
  - Warning: Maintenance burden increases

Strategy 2: Remove unused mechanisms
  - Cross-reference with DMARC reports
  - Identify senders with zero volume
  - Remove mechanisms for inactive services

Strategy 3: Consolidate includes
  - Some providers have consolidated SPF records
  - Check for provider-recommended optimizations
  - Use provider-specific subdomains if available
```

# Output Standards

## Validation Report Format

```json
{
  "domain": "example.com",
  "timestamp": "ISO-8601",
  "raw_record": "v=spf1 include:_spf.google.com ~all",
  "validation": {
    "status": "valid|invalid|warnings",
    "version": "spf1",
    "mechanisms": [
      {
        "order": 1,
        "raw": "include:_spf.google.com",
        "type": "include",
        "qualifier": "+",
        "argument": "_spf.google.com",
        "valid": true,
        "lookups": 4
      }
    ],
    "modifiers": [],
    "all_mechanism": {
      "present": true,
      "qualifier": "~",
      "position": "last",
      "valid_position": true
    }
  },
  "lookup_analysis": {
    "total": 4,
    "limit": 10,
    "status": "within_limit",
    "breakdown": []
  },
  "misconfigurations": [
    {
      "id": "SPF-HIGH-001",
      "name": "softfail_all",
      "severity": "high",
      "description": "...",
      "remediation": "..."
    }
  ],
  "risk_contribution": "low|medium|high|critical",
  "recommended_record": "v=spf1 include:_spf.google.com -all"
}
```

# Integration Points

## CLAUDE.md Integration

- Provides SPF status to SECURITY STATUS section
- Feeds risk contribution to RISK LEVEL calculation
- Generates copy-paste SPF records for RECOMMENDED RECORDS
- Identifies issues for ISSUES FOUND section

## dns-fetcher.md Integration

- Requests recursive DNS lookups for include targets
- Requests MX record resolution for mx mechanism counting
- Requests A/AAAA resolution for a mechanism validation
- Caches lookup results per dns-fetcher.md caching policy

## dmarc-parser.md Integration

- Cross-references SPF results in aggregate reports
- Identifies senders passing/failing SPF
- Validates that SPF mechanisms cover legitimate senders

# Constraints and Prohibitions

## Critical Prohibitions

**Never:**
- Generate SPF records with +all or ?all
- Recommend removing -all enforcement once in place (only softening if mail delivery issues documented)
- Ignore lookup limit violations
- Fabricate IP ranges not provided or resolved
- Skip duplicate record detection
- Generate records exceeding DNS limits without warning

**Always:**
- Count lookups recursively through all includes
- Flag deprecated ptr mechanism
- Validate all IP address syntax
- Check for duplicate SPF records
- Recommend -all as the target enforcement
- Document lookup count in output

# Verification Criteria

## Validation Complete When

- [ ] SPF record extracted and parsed
- [ ] Version identifier validated
- [ ] All mechanisms syntax-checked
- [ ] All modifiers validated
- [ ] DNS lookup count calculated (recursive)
- [ ] Lookup limit compliance determined
- [ ] Misconfigurations identified and classified
- [ ] Risk contribution assessed
- [ ] Remediation record generated (if issues found)
- [ ] Output conforms to required format

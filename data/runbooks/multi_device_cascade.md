# Runbook: Multi-Device Cascade — Correlated Downstream Outage

**Applicable Alert Types:** `LINK_DOWN`, `DEVICE_UNREACHABLE`, `PACKET_LOSS`, `HIGH_LATENCY`
**Severity:** Critical
**Devices:** Any hierarchical path (core → distribution → access)

## Title
Multi-Device Cascading Failure — Topology-Driven Correlation

## Symptoms
- Multiple alerts (typically ≥5) from distinct devices within 5 minutes
- Alerts are topologically adjacent (direct links in `topology.json`)
- Alert types are related (`LINK_DOWN` ↔ `DEVICE_UNREACHABLE` ↔ `PACKET_LOSS`)
- Earliest alert is usually highest in the hierarchy (core or distribution), latest is access
- Underlying fingerprint count may be high but correlated grouping shows one incident

## Likely Causes
1. Single upstream failure propagating downstream (fiber, SFP, or device)
2. Power or environmental event affecting a site (e.g., `AGG-CHENNAI-02`)
3. Software bug causing IGP churn and transient unreachability
4. Upstream packet loss / latency inflating downstream measurements (not independent events)

## Initial Checks
- Identify earliest alert timestamp — this is the likely root (check `first_seen`)
- Map affected devices onto topology: run `impact_of_failure(root_device)` to see expected downstream set and compare to actual affected set
- Count distinct fingerprints vs correlated grouping — high dedup ratio suggests repeated observations of same upstream cause
- Check if alerts outside the main cluster remain ungrouped (noise) — these need separate triage

## Recommended Actions
1. Focus investigation on the earliest (upstream) device first — confirm its interface/device state before touching downstream nodes
2. Do NOT reboot downstream access routers while upstream is still down — they will recover via IGP when upstream returns
3. If upstream is core and redundant peer exists, fail over to peer (see `core_router_failure.md` step 1)
4. After upstream recovery, verify downstream devices in topology order (distribution before access) — clear counters and confirm packet loss returns to <1%

## Escalation Conditions
- Root device not found or multiple roots with no common ancestor → escalate as ambiguous multi-incident, do not force a single root cause
- Downstream devices remain unreachable after upstream recovers for >10 min → escalate to routing / transport for independent investigation
- More than 10 devices affected or >2000 subscribers impacted → escalate to P1, engage incident commander

## Evidence Tags
- Section `Initial Checks` for root identification via earliest timestamp and topology mapping
- Section `Recommended Actions` step 1 for upstream-first strategy
- Section `Escalation Conditions` for ambiguous root handling

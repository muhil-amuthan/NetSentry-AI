# Runbook: Authentication Failure — RADIUS / AAA Rejects

**Applicable Alert Types:** `AUTH_FAILURE`, `RADIUS_TIMEOUT`
**Severity:** Medium
**Devices:** Access routers, Distribution switches (subscriber authentication)

## Title
Authentication Failure — Repeated RADIUS Rejects

## Symptoms
- Syslog reports `Authentication failure` or `RADIUS timeout` bursts (≥5 per minute)
- Subscriber sessions fail to establish (PPPoE / DHCP auth rejects)
- Usually clustered on 1-2 access devices after a configuration change
- Other devices on same AAA server may be unaffected — points to local config mismatch

## Likely Causes
1. RADIUS shared secret mismatch after recent change (most common)
2. AAA server unreachable or overloaded (check `RADIUS_TIMEOUT` correlation)
3. Clock skew preventing certificate auth (check NTP/PTP status)
4. Stale user database or realm mapping after change window

## Initial Checks
- Compare shared secret on device vs AAA server (`show radius server` and vault template)
- Check AAA server reachability: `ping <aaa_ip>` and `show radius statistics`
- Review change log for the affected devices in last 24h (look for AAA or template push)
- Check if issue is isolated: are other devices using same AAA server healthy?
- Check system time: `show clock` vs NTP source

## Recommended Actions
1. If secret mismatch confirmed, re-apply shared secret from golden template and test with `test aaa group radius`
2. If AAA server is unreachable from device but reachable elsewhere, check management routing or ACL
3. If isolated to RADIUS timeout with no auth rejects, investigate AAA server load and restart radius process if needed
4. After fix, monitor auth success rate for 10 min — should return to >99%

## Escalation Conditions
- Fix requires vault secret rotation → escalate to security team
- Multiple sites affected and AAA server itself is degraded → escalate to AAA platform team (P2)
- No change found and other devices on same server are healthy → escalate for deep packet capture on RADIUS

## Evidence Tags
- Section `Initial Checks` for change-window correlation
- Section `Recommended Actions` step 1 for secret re-application

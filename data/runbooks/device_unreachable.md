# Runbook: Device Unreachable — Management Plane Loss

**Applicable Alert Types:** `DEVICE_UNREACHABLE`, `LINK_DOWN`
**Severity:** Critical
**Devices:** Core router, Distribution switch, Access router

## Title
Device Unreachable — ICMP/SNMP Polling Failure

## Symptoms
- NMS reports `ICMP probe timed out after 3 attempts` or SNMP timeout
- Device does not respond to SSH / NETCONF
- Directly connected neighbors may report `LINK_DOWN` or `BGP_SESSION_DROP`
- Subscriber sessions behind device may flap or show packet loss

## Likely Causes
1. Control-plane overload (CPU >90%)
2. Upstream link failure isolating the device (check topology upstream)
3. Device hardware failure or unexpected reboot
4. ACL or firewall change blocking management network
5. Power or environmental failure at site

## Initial Checks
- From nearest reachable hop, try `ping <mgmt_ip>` and `traceroute <mgmt_ip>`
- Check upstream link status in NMS: is parent interface `LINK_DOWN`?
- Review syslog for reboot messages (`System restarted`, `Power supply failure`)
- Check CPU and memory telemetry for the device (last 15 min)
- Verify management VRF routing and ACLs

## Recommended Actions
1. If upstream link is down, follow `link_down.md` first — device may be reachable once transport recovers
2. If device is isolated but powered, attempt out-of-band console access (LTE OOB)
3. If CPU overload is confirmed, identify top talkers: `show processes cpu sorted`
4. If no upstream cause, dispatch field ops with console access and crash log collection

## Escalation Conditions
- Core device unreachable for >5 min with no redundant path → escalate to P1 incident commander
- Multiple devices unreachable behind same distribution switch → escalate as site/aggregation failure
- Device returns but state is unstable (flapping) → keep monitoring, do not auto-close

## Evidence Tags
- Section `Initial Checks` for confirming upstream link vs device root cause
- Section `Recommended Actions` step 1 for ordering with link_down evidence

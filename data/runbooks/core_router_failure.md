# Runbook: Core Router Failure — Upstream Transit and Distribution Impact

**Applicable Alert Types:** `LINK_DOWN`, `DEVICE_UNREACHABLE`, `PACKET_LOSS`, `HIGH_LATENCY`, `BGP_SESSION_DROP`
**Severity:** Critical
**Devices:** Core router (CORE-R1, CORE-R2), Distribution switches, Transit uplink

## Title
Core Router Uplink or Device Failure With Downstream Cascade

## Symptoms
- Core router (`CORE-R1` or `CORE-R2`) reports `LINK_DOWN` on transit interface `Te0/1`
- Within 30-120s, downstream distribution switches (`SW-S1`, `SW-S2`) report `LINK_DOWN` or `HIGH_LATENCY`
- Access routers behind distribution (ACC-R3..R6) go `DEVICE_UNREACHABLE` in sequence
- Packet loss appears on multiple downstream interfaces simultaneously
- IGP / BGP sessions may drop (`BGP_SESSION_DROP`)

## Likely Causes
1. Fiber cut or SFP failure on core transit port
2. Core device hardware or power failure
3. Software crash or ISSU failure during maintenance
4. Upstream provider outage (validate with provider status)
5. Configuration change withdrawing IGP / BGP peering

## Initial Checks
- Verify core interface status and optics (see `link_down.md` Initial Checks for Te0/1)
- Check device reachability: `ping CORE-R1` from core neighbor; if unreachable, confirm power and OOB
- Review distribution reachability: are `SW-S1`/`SW-S2` isolated via topology (check `impact_of_failure`)?
- Check BGP/IGP state: `show bgp summary`, `show ip ospf neighbor`
- Confirm no recent config change on core in last 24h; check provider NOC status

## Recommended Actions
1. Validate optics on core transit port — if Rx low, fail traffic to standby core router (`CORE-R2`) via VRRP / IGP cost adjustment before touching fiber
2. If core device itself is unreachable and OOB also fails, dispatch field ops immediately — do NOT attempt remote reboot without console
3. Once core recovers, verify distribution uplinks automatically recover; if not, clear interface on distribution side
4. Monitor subscriber reachability on access routers for 15 min — downstream restoration should follow IGP convergence

## Escalation Conditions
- Both core routers unreachable → P1 major incident, engage incident commander and provider immediately
- Downstream does not recover after core recovers → escalate to routing team for IGP/BGP investigation
- Repeated core failure within 24h → escalate to hardware TAC with crash info

## Evidence Tags
- Section `Initial Checks` for confirming core vs downstream root cause
- Section `Recommended Actions` step 1 for standby core failover
- Section `Escalation Conditions` for dual-core outage

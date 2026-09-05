# Runbook: Distribution Switch Degradation

**Applicable Alert Types:** `LINK_DOWN`, `PACKET_LOSS`, `HIGH_LATENCY`, `DEVICE_UNREACHABLE`, `CRC_ERRORS`
**Severity:** High
**Devices:** Distribution switch (SW-S1, SW-S2)

## Title
Distribution Switch Uplink or Downlink Degradation

## Symptoms
- Distribution switch (`SW-S1` or `SW-S2`) reports `LINK_DOWN` on uplink towards core or downlink towards access
- Access routers behind the switch report `DEVICE_UNREACHABLE` or `PACKET_LOSS`
- Core side may show `PACKET_LOSS` toward the same switch
- Isolated to one distribution domain — the peer distribution switch remains healthy

## Likely Causes
1. Uplink fiber or SFP failure between core and distribution
2. Distribution switch CPU or line card overload
3. Configuration change pushing bad VLAN or port-channel config
4. Power anomaly at aggregation site
5. Downstream access fiber cut appearing as distribution packet loss (check both ends)

## Initial Checks
- From core, check interface toward the distribution switch: `show interfaces <core_if> status`
- On the distribution switch, check both uplink and downlink: `show interfaces et-0/0/1 status`, `show interfaces ge-0/0/10 status`
- Check distribution CPU and logs: `show chassis alarms`, `show system uptime`
- Map affected access devices: `show topology` — confirms blast radius is limited to this distribution's downstream
- Compare loss counters on both sides of the link to identify local media vs remote

## Recommended Actions
1. If uplink is down, follow core recovery before touching distribution — distribution may be victim, not root
2. If distribution itself is reachable but downlink LOS is local, clean/replace SFP on the affected `ge-0/0/x` port
3. If CPU high, identify process: `show system processes extensive` and mitigate top talker
4. If both distribution switches degrade simultaneously, treat as core-side cause per `core_router_failure.md`

## Escalation Conditions
- Both distribution switches down simultaneously → escalate as core or site failure, not isolated switch
- Distribution switch unreachable and OOB fails → dispatch field ops with console
- Repeated failures after SFP replacement → escalate to hardware TAC for line card diagnostics

## Evidence Tags
- Section `Initial Checks` for confirming uplink vs downlink root and blast radius mapping
- Section `Recommended Actions` step 1 for upstream-first ordering

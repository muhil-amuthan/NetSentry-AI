# Runbook: High Latency — Control and Data Plane Delay

**Applicable Alert Types:** `HIGH_LATENCY`, `PACKET_LOSS`, `JITTER_THRESHOLD`
**Severity:** Medium to High
**Devices:** Core, Distribution, Access (transit and edge paths)

## Title
High Latency Above Baseline

## Symptoms
- `rtt_ms` in alert is >80 ms vs baseline ~18 ms, or `jitter` >15 ms
- May appear with `PACKET_LOSS` on same path, or alone during peak utilization
- Latency typically measured by TWAMP or ICMP probes across the link
- Users may report increased application response time without full outage

## Likely Causes
1. Link congestion (buffer queue building) during peak hours
2. Upstream routing change elongating the path (check traceroute hops)
3. CPU overload delaying control-plane packet forwarding
4. Upstream packet loss causing retransmit latency inflation
5. Transient congestion due to link failure elsewhere (cascade propagation)

## Initial Checks
- Compare `rtt_ms` to baseline and to peer direction (asymmetry indicates one-way congestion)
- Check interface utilization: `show interfaces <if> | include rate` — look for >70% sustained
- Review CPU on both ends: `show processes cpu` — high CPU adds forwarding delay
- Check for recent routing changes: `show ip route <peer>`, `show bgp summary`
- Correlate with packet loss on same device — if both present, treat loss as primary

## Recommended Actions
1. If utilization is high, identify top talkers and consider temporary rate-limit or load balancing
2. If latency is isolated and within SLA (<100 ms), monitor for 15 min — evening peak pattern may be benign
3. If latency propagates from core, investigate upstream link (`link_down.md`) before tuning edge
4. Clear interface counters and re-measure after any change: `clear counters <if>`

## Escalation Conditions
- RTT holds above 100 ms for >15 min or breaches SLA → escalate to capacity planning
- Latency with concurrent `DEVICE_UNREACHABLE` downstream → escalate as cascade failure (see `multi_device_cascade.md`)
- No congestion or CPU cause found and latency remains → escalate to transport for OTN delay check

## Evidence Tags
- Section `Initial Checks` for confirming congestion vs CPU vs routing
- Section `Recommended Actions` step 2 for benign peak handling

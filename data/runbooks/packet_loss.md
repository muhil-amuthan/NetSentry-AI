# Runbook: Packet Loss — Forwarding Path Degradation

**Applicable Alert Types:** `PACKET_LOSS`, `CRC_ERRORS`, `LINK_DOWN`
**Severity:** High
**Devices:** Core, Distribution, Access (uplink ports and customer aggregates)

## Title
Packet Loss Exceeding Threshold

## Symptoms
- `netflow` / `snmp` reports loss `>20%` over 5 min window (alert includes `loss_pct`)
- User complaints of slow transfers, retransmits in TCP
- May correlate with `HIGH_LATENCY` or `CRC_ERRORS` on same interface
- Single interface typically affected; peer interface may be clean

## Likely Causes
1. Dirty or damaged fiber causing CRC and retransmits
2. Congested egress queue (output drops) during peak hours
3. Faulty line card or SFP
4. Upstream packet loss propagating downstream via back-pressure
5. Duplex mismatch on copper handoff

## Initial Checks
- Compare `loss_pct` on both ends of the link — local-only loss points to local media
- Check interface error counters: `show interfaces <if> counters errors` — rising CRC/FCS
- Review traffic load: `show interfaces <if> | include rate` — utilization >80% suggests congestion
- Check QoS drops: `show policy-map interface <if>`
- Correlate with latency (`rtt_ms`) — loss + latency suggests congestion or buffer bloat

## Recommended Actions
1. If CRC errors rising and loss is local to one end, clean/replace SFP and patch lead
2. If utilization high, check for elephant flows and apply or tune egress shaping
3. If both ends show loss, look upstream: this is downstream propagation, follow core runbook
4. Monitor for 15 min after mitigation — loss should return below 1% baseline

## Escalation Conditions
- Loss persists after SFP replacement and utilization is normal → escalate to transport/optics
- Loss affecting >1 interface on same device → suspect line card, escalate to hardware team
- Loss coincides with `DEVICE_UNREACHABLE` on peer → treat as `LINK_DOWN` precursor, escalate

## Evidence Tags
- Section `Initial Checks` for confirming local vs peer loss
- Section `Recommended Actions` step 1 for physical media fix

# Runbook: Link Down — Interface or Transport Failure

**Applicable Alert Types:** `LINK_DOWN`, `LINK_UP`
**Severity:** Critical
**Devices:** Router, Switch, Access (uplink / downlink ports)

## Title
Link Down — Physical or Logical Interface Failure

## Symptoms
- Interface operational status transitions to `down` (SNMP trap `linkDown` or syslog `Interface down`)
- Adjacent device reports `DEVICE_UNREACHABLE` within seconds
- Traffic counters stop incrementing on the affected interface
- Downstream packet loss / latency may follow if no redundant path exists

## Likely Causes
1. Fiber patch cut, dirty connector, or bent fiber
2. SFP / transceiver failure (high temperature, low Rx power)
3. Remote device reboot or power loss
4. Configuration change disabling the interface (`shutdown`)
5. Upstream transport (DWDM/OTN) outage

## Initial Checks
- Verify interface admin vs oper state: `show interfaces <if> status`
- Check optical levels: `show interfaces <if> transceiver detail` — expect Tx/Rx within vendor spec (-14 to -18 dBm for 10G-LR)
- Inspect error counters: `show interfaces <if> counters errors` — rising input errors indicate media issue
- Confirm peer interface status on the far end
- Check for recent configuration changes in audit log (last 24h)
- Ping the next hop across the link

## Recommended Actions
1. If optical Rx is below threshold, reseat the SFP and clean fiber connectors
2. If peer is down, check power and environment on peer device first
3. Fail traffic to redundant path if available (`clear mpls lsp` or IGP cost adjustment)
4. Replace patch lead / SFP during maintenance window if errors persist
5. Open field operations ticket if physical plant is suspected

## Escalation Conditions
- Multiple links down on the same device simultaneously → escalate as potential device or site failure
- No matching peer failure but link stays down after SFP reseat → escalate to transport team
- Repeated flapping (>3 times in 10 min) → treat as `IF_FLAP`, not single `LINK_DOWN`

## Evidence Tags
- Section `Initial Checks` is typically cited for optics verification
- Section `Recommended Actions` step 1 for SFP/connector handling
- Section `Escalation Conditions` for multi-link correlation

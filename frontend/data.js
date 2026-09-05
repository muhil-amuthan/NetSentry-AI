/*
 * NetSentry AI — presentation data layer.
 *
 * ARCHITECTURE RULE
 * -----------------
 * This file is the ONLY place the UI gets its data from. Every function below
 * returns a plain object/array in the exact shape the UI renders, and today it
 * resolves from MOCK constants.
 *
 * Later, each function is swapped for a `fetch()` against FastAPI without
 * touching app.js, e.g.:
 *
 *     getIncidents: () => fetch('/api/incidents').then(r => r.json())
 *
 * All getters are already async (they return Promises), so app.js is written
 * against the future API contract from day one. No correlation, scoring,
 * dedup or retrieval logic lives here — that belongs in the backend engine.
 */
(function (global) {
  "use strict";

  /* ----------------------------- MOCK DATA ----------------------------- */

  const NETWORK_STATUS = {
    state: "operational", // operational | degraded | outage
    label: "Operational",
    lastUpdated: "just now",
    facts: [
      { label: "Managed nodes", value: "9" },
      { label: "Uptime (30d)", value: "99.982%" },
      { label: "Mean triage time", value: "42s" },
    ],
  };

  const NETWORK_HEALTH = {
    overall: 94,
    tiers: [
      { name: "Core", value: 100, status: "ok" },
      { name: "Edge", value: 96, status: "ok" },
      { name: "Access", value: 91, status: "warn" },
    ],
  };

  const KPIS = [
    { id: "alerts",   label: "Active Alerts",    value: "127", status: "info", icon: "alert",
      trend: { dir: "up", text: "+18 in 5m" }, note: "raw ingest" },
    { id: "incidents",label: "Open Incidents",   value: "8",   status: "warn", icon: "incident",
      trend: { dir: "up", text: "+2 in 15m" }, note: "correlated" },
    { id: "critical", label: "Critical",         value: "2",   status: "crit", icon: "critical",
      trend: { dir: "flat", text: "no change" }, note: "P1 severity" },
    { id: "devices",  label: "Devices Affected", value: "14",  status: "high", icon: "device",
      trend: { dir: "up", text: "+5 in 10m" }, note: "across 3 sites" },
    { id: "auto",     label: "Auto-Resolved",    value: "86%", status: "ok",   icon: "auto",
      trend: { dir: "up", text: "+4% vs 24h" }, note: "runbook driven" },
  ];

  const INCIDENTS = [
    {
      id: "INC-2048",
      title: "Core Router R1 Failure",
      severity: "critical",
      state: "open",
      devices: 14,
      started: "3m ago",
      confidence: 87,
      correlated: 24,
      site: "DC-CHENNAI-01",
      owner: "Unassigned",
      aiAvailable: true,
      summary:
        "Uplink on Core-R1 stopped forwarding. Downstream switches S1/S2 and six access routers lost reachability within 19 seconds.",
      signals: ["LINK_DOWN", "DEVICE_UNREACHABLE", "PACKET_LOSS", "BGP_SESSION_DROP"],
      nodes: ["R1", "S1", "S2", "R3", "R4", "R5", "R6"],
    },
    {
      id: "INC-2049",
      title: "Switch S2 Packet Loss",
      severity: "high",
      state: "open",
      devices: 5,
      started: "9m ago",
      confidence: 74,
      correlated: 11,
      site: "AGG-MADURAI-02",
      owner: "N. Iyer",
      aiAvailable: true,
      summary:
        "Sustained 6.2% packet loss on S2 uplink port Gi1/0/24. CRC error counter rising — likely optical/patch degradation.",
      signals: ["PACKET_LOSS", "CRC_ERRORS", "HIGH_LATENCY"],
      nodes: ["S2", "R5", "R6"],
    },
    {
      id: "INC-2051",
      title: "Authentication Failures",
      severity: "medium",
      state: "investigating",
      devices: 3,
      started: "21m ago",
      confidence: 62,
      correlated: 7,
      site: "EDGE-COIMBATORE",
      owner: "S. Rahman",
      aiAvailable: true,
      summary:
        "Repeated RADIUS auth rejects from access routers R3 and R4. Pattern matches a stale shared-secret after last night's change window.",
      signals: ["AUTH_FAILURE", "RADIUS_TIMEOUT"],
      nodes: ["R3", "R4"],
    },
    {
      id: "INC-2053",
      title: "Edge Latency Spike",
      severity: "low",
      state: "monitoring",
      devices: 2,
      started: "34m ago",
      confidence: 55,
      correlated: 4,
      site: "EDGE-SALEM",
      owner: "Auto-triage",
      aiAvailable: false,
      summary:
        "RTT on the Salem edge path rose from 18ms to 47ms during the evening peak. Within SLA, trending back to baseline.",
      signals: ["HIGH_LATENCY", "JITTER"],
      nodes: ["R6"],
    },
  ];

  // Seeded, finite alert buffer. The UI replays this on a slow timer — no
  // synthetic traffic generation, no runaway loops.
  const ALERTS = [
    { time: "12:41:08", node: "R1", type: "LINK_DOWN",          severity: "critical" },
    { time: "12:41:11", node: "R1", type: "DEVICE_UNREACHABLE", severity: "critical" },
    { time: "12:41:15", node: "S2", type: "HIGH_LATENCY",       severity: "medium"   },
    { time: "12:41:21", node: "R1", type: "PACKET_LOSS",        severity: "high"     },
    { time: "12:41:27", node: "S2", type: "AUTH_FAILURE",       severity: "medium"   },
    { time: "12:41:33", node: "S1", type: "BGP_SESSION_DROP",   severity: "high"     },
    { time: "12:41:39", node: "R4", type: "CRC_ERRORS",         severity: "medium"   },
    { time: "12:41:44", node: "R3", type: "RADIUS_TIMEOUT",     severity: "low"      },
    { time: "12:41:52", node: "R5", type: "IF_FLAP",            severity: "medium"   },
    { time: "12:41:58", node: "R6", type: "JITTER_THRESHOLD",   severity: "low"      },
    { time: "12:42:05", node: "S2", type: "PACKET_LOSS",        severity: "high"     },
    { time: "12:42:12", node: "R1", type: "OPTICAL_RX_LOW",     severity: "critical" },
  ];

  // Topology shaped like data/topology.json so the swap is a one-line change.
  // Coordinates are normalised 0..1 and scaled to the SVG viewBox at render.
  const TOPOLOGY = {
    nodes: [
      { id: "INTERNET", label: "INTERNET", type: "cloud",  status: "ok",   x: 0.5,  y: 0.08, meta: "Transit · 2x100G" },
      { id: "R1",  label: "CORE-R1", type: "router", status: "down", x: 0.5,  y: 0.31, meta: "Core router · uplink Te0/1 down" },
      { id: "S1",  label: "SW-S1",   type: "switch", status: "warn", x: 0.28, y: 0.56, meta: "Distribution · BGP session dropped" },
      { id: "S2",  label: "SW-S2",   type: "switch", status: "warn", x: 0.72, y: 0.56, meta: "Distribution · 6.2% packet loss" },
      { id: "R3",  label: "R3", type: "access", status: "warn", x: 0.13, y: 0.85, meta: "Access · RADIUS timeouts" },
      { id: "R4",  label: "R4", type: "access", status: "warn", x: 0.36, y: 0.85, meta: "Access · CRC errors rising" },
      { id: "R5",  label: "R5", type: "access", status: "ok",   x: 0.63, y: 0.85, meta: "Access · nominal" },
      { id: "R6",  label: "R6", type: "access", status: "ok",   x: 0.87, y: 0.85, meta: "Access · latency 47ms" },
    ],
    links: [
      { source: "INTERNET", target: "R1", status: "down" },
      { source: "R1", target: "S1", status: "warn" },
      { source: "R1", target: "S2", status: "warn" },
      { source: "S1", target: "R3", status: "warn" },
      { source: "S1", target: "R4", status: "warn" },
      { source: "S2", target: "R5", status: "ok" },
      { source: "S2", target: "R6", status: "ok" },
    ],
  };

  // Keyed by incident id — later served by /api/incidents/{id}/analysis
  const AI_ANALYSIS = {
    "INC-2048": {
      headline: "Multiple alerts appear correlated.",
      rootCause: "Core Router R1 connectivity failure",
      confidence: 87,
      correlated: 24,
      devices: 14,
      action:
        "Check uplink interface and optical signal levels on Core-R1. Confirm Te0/1 light levels, then fail traffic to the standby core path before dispatching field ops.",
      source: "RUNBOOK-NET-001",
      evidence: [
        "19 downstream alerts began within 22s of the R1 LINK_DOWN event",
        "Optical Rx on Te0/1 reported below -18 dBm threshold",
        "No configuration change recorded on R1 in the last 24h",
      ],
    },
    "INC-2049": {
      headline: "Loss localised to a single uplink port.",
      rootCause: "Degraded optics on S2 port Gi1/0/24",
      confidence: 74,
      correlated: 11,
      devices: 5,
      action:
        "Inspect CRC/input-error counters on Gi1/0/24 and reseat or replace the SFP and patch lead during the next maintenance window.",
      source: "RUNBOOK-NET-014",
      evidence: [
        "CRC error counter climbing ~120/min on Gi1/0/24 only",
        "Peer interface clean — points to local media, not the far end",
      ],
    },
    "INC-2051": {
      headline: "Auth failures cluster after a change window.",
      rootCause: "Stale RADIUS shared secret on R3/R4",
      confidence: 62,
      correlated: 7,
      devices: 3,
      action:
        "Compare the RADIUS shared secret on R3/R4 against the AAA server config and re-apply from the golden template.",
      source: "RUNBOOK-AAA-004",
      evidence: [
        "First reject 6 minutes after change CHG-8821 completed",
        "Other sites on the same AAA server are unaffected",
      ],
    },
    "INC-2053": {
      headline: "Latency elevated but within SLA.",
      rootCause: "Evening peak congestion on the Salem edge path",
      confidence: 55,
      correlated: 4,
      devices: 2,
      action: "No immediate action. Keep monitoring; escalate if RTT holds above 60ms for 15 minutes.",
      source: "RUNBOOK-NET-022",
      evidence: ["RTT tracks the daily utilisation curve", "No packet loss observed alongside the latency rise"],
    },
  };

  const TIMELINES = {
    "INC-2048": [
      { time: "14:31:02", text: "Link Down detected",              kind: "crit" },
      { time: "14:31:08", text: "Device unreachable",              kind: "crit" },
      { time: "14:31:15", text: "Packet loss detected",            kind: "high" },
      { time: "14:31:21", text: "Related alerts grouped",          kind: "info" },
      { time: "14:31:27", text: "Incident created",                kind: "info" },
      { time: "14:31:35", text: "Runbook recommendation generated",kind: "ok"   },
    ],
    "INC-2049": [
      { time: "14:25:11", text: "Packet loss threshold breached", kind: "high" },
      { time: "14:25:40", text: "CRC errors correlated to Gi1/0/24", kind: "high" },
      { time: "14:26:02", text: "Incident created",               kind: "info" },
      { time: "14:26:18", text: "Runbook RUNBOOK-NET-014 matched", kind: "ok"   },
    ],
    "INC-2051": [
      { time: "14:13:44", text: "RADIUS timeout on R3",     kind: "medium" },
      { time: "14:14:02", text: "Auth failures on R4",      kind: "medium" },
      { time: "14:14:30", text: "Change CHG-8821 linked",   kind: "info"   },
      { time: "14:14:55", text: "Incident created",         kind: "info"   },
    ],
    "INC-2053": [
      { time: "14:00:09", text: "Latency above baseline",  kind: "low"  },
      { time: "14:02:31", text: "Trend classified benign", kind: "info" },
      { time: "14:03:00", text: "Monitoring window opened",kind: "ok"   },
    ],
  };

  // Canned NLP answers — placeholder for the future Gemini + FAISS handler.
  const ASK_SUGGESTIONS = [
    "Why is INC-2048 critical?",
    "What alerts were grouped?",
    "What should I check first?",
    "Show affected devices",
  ];

  const ASK_ANSWERS = [
    {
      match: /critical|inc-?2048|severity/i,
      answer:
        "INC-2048 is CRITICAL because Core-R1 sits on the only active transit path. Its failure isolates 2 distribution switches and 4 access routers — 14 devices, ~6,200 subscribers. Priority score 96/100, confidence 87%.",
      refs: ["INC-2048", "RUNBOOK-NET-001"],
    },
    {
      match: /group|correlat|cluster/i,
      answer:
        "24 alerts were grouped into INC-2048 by node adjacency and a 30s time window: 1× LINK_DOWN, 7× DEVICE_UNREACHABLE, 9× PACKET_LOSS, 4× BGP_SESSION_DROP and 3× OPTICAL_RX_LOW. Dedup removed 11 repeats.",
      refs: ["INC-2048"],
    },
    {
      match: /check first|first step|what should|next step|action/i,
      answer:
        "Start at Core-R1: read optical Rx on Te0/1 (expect below -18 dBm), then verify the uplink admin/oper state. If optics are out of spec, fail traffic to the standby core path before dispatching field ops. Step 1 of RUNBOOK-NET-001.",
      refs: ["RUNBOOK-NET-001"],
    },
    {
      match: /device|affected|impact|subscriber/i,
      answer:
        "14 devices are affected: CORE-R1 (down), SW-S1 and SW-S2 (degraded), access routers R3, R4, R5, R6 plus 7 CPE aggregates behind S1. Sites: DC-CHENNAI-01, AGG-MADURAI-02.",
      refs: ["INC-2048", "INC-2049"],
    },
  ];

  const ASK_FALLBACK =
    "The natural-language triage handler is not connected yet — this console currently returns mock answers. Once the incident engine and retrieval layer are wired up, this question will be answered from live alert, incident and runbook data.";

  /* ------------------------------ GETTERS ------------------------------ */
  // Swap each body for a fetch() when the API lands. Shapes stay identical.

  const NetSentryData = {
    getNetworkStatus: async () => NETWORK_STATUS,
    getNetworkHealth: async () => NETWORK_HEALTH,
    getKpis: async () => KPIS,
    getIncidents: async () => INCIDENTS,
    getAlerts: async () => ALERTS,
    getTopology: async () => TOPOLOGY,
    getAnalysis: async (incidentId) => AI_ANALYSIS[incidentId] || null,
    getTimeline: async (incidentId) => TIMELINES[incidentId] || [],
    getAskSuggestions: async () => ASK_SUGGESTIONS,
    ask: async (question) => {
      const hit = ASK_ANSWERS.find((a) => a.match.test(question));
      return hit
        ? { answer: hit.answer, refs: hit.refs, mock: true }
        : { answer: ASK_FALLBACK, refs: [], mock: true };
    },
    // Real endpoint — already live in the backend.
    getHealth: async () => {
      const res = await fetch("/api/health");
      if (!res.ok) throw new Error("health check failed");
      return res.json();
    },
  };

  global.NetSentryData = NetSentryData;
})(window);

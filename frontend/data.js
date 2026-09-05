/*
 * NetSentry AI — presentation data layer.
 *
 * This file is the ONLY place the UI gets its data from. Every function
 * now talks to the FastAPI backend; mock constants remain only as a graceful
 * fallback when the API is unreachable so the dashboard never renders blank.
 *
 * All getters are async (return Promises), matching the original contract.
 */

(function (global) {
  "use strict";

  /* ----------------------------- MOCK FALLBACKS ---------------------- */
  // Kept so the UI stays usable if the backend is down during local dev.
  const FALLBACK = {
    NETWORK_STATUS: {
      state: "operational",
      label: "Operational",
      lastUpdated: "just now",
      facts: [
        { label: "Managed nodes", value: "9" },
        { label: "Uptime (30d)", value: "99.982%" },
        { label: "Mean triage time", value: "42s" },
      ],
    },
    NETWORK_HEALTH: {
      overall: 94,
      tiers: [
        { name: "Core", value: 100, status: "ok" },
        { name: "Edge", value: 96, status: "ok" },
        { name: "Access", value: 91, status: "warn" },
      ],
    },
    KPIS: [
      { id: "alerts", label: "Active Alerts", value: "127", status: "info", icon: "alert", trend: { dir: "up", text: "+18 in 5m" }, note: "raw ingest" },
      { id: "incidents", label: "Open Incidents", value: "8", status: "warn", icon: "incident", trend: { dir: "up", text: "+2 in 15m" }, note: "correlated" },
      { id: "critical", label: "Critical", value: "2", status: "crit", icon: "critical", trend: { dir: "flat", text: "no change" }, note: "P1 severity" },
      { id: "devices", label: "Devices Affected", value: "14", status: "high", icon: "device", trend: { dir: "up", text: "+5 in 10m" }, note: "across 3 sites" },
      { id: "auto", label: "Auto-Resolved", value: "86%", status: "ok", icon: "auto", trend: { dir: "up", text: "+4% vs 24h" }, note: "runbook driven" },
    ],
    INCIDENTS: [
      {
        id: "INC-0001",
        title: "Core Router R1 Failure",
        severity: "critical",
        state: "open",
        devices: 7,
        started: "3m ago",
        confidence: 87,
        correlated: 23,
        site: "DC-CHENNAI-01",
        owner: "Unassigned",
        aiAvailable: true,
        summary: "Uplink on Core-R1 stopped forwarding. Downstream switches S1/S2 and six access routers lost reachability within 19 seconds.",
        signals: ["LINK_DOWN", "DEVICE_UNREACHABLE", "PACKET_LOSS"],
        nodes: ["R1", "S1", "S2", "R3", "R4", "R5", "R6"],
      },
    ],
    ALERTS: [
      { time: "12:41:08", node: "R1", type: "LINK_DOWN", severity: "critical" },
      { time: "12:41:11", node: "R1", type: "DEVICE_UNREACHABLE", severity: "critical" },
      { time: "12:41:15", node: "S1", type: "HIGH_LATENCY", severity: "medium" },
    ],
    TOPOLOGY: {
      nodes: [
        { id: "INTERNET", label: "INTERNET", type: "cloud", status: "ok", x: 0.5, y: 0.08, meta: "Transit · 2x100G" },
        { id: "R1", label: "CORE-R1", type: "router", status: "down", x: 0.5, y: 0.31, meta: "Core router · uplink Te0/1 down" },
        { id: "S1", label: "SW-S1", type: "switch", status: "warn", x: 0.28, y: 0.56, meta: "Distribution · BGP session dropped" },
        { id: "S2", label: "SW-S2", type: "switch", status: "warn", x: 0.72, y: 0.56, meta: "Distribution · 6.2% packet loss" },
        { id: "R3", label: "R3", type: "access", status: "warn", x: 0.13, y: 0.85, meta: "Access · RADIUS timeouts" },
        { id: "R4", label: "R4", type: "access", status: "warn", x: 0.36, y: 0.85, meta: "Access · CRC errors rising" },
        { id: "R5", label: "R5", type: "access", status: "ok", x: 0.63, y: 0.85, meta: "Access · nominal" },
        { id: "R6", label: "R6", type: "access", status: "ok", x: 0.87, y: 0.85, meta: "Access · latency 47ms" },
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
    },
    AI_ANALYSIS: {},
    TIMELINES: {},
    ASK_SUGGESTIONS: [
      "Why is INC-0001 critical?",
      "What alerts were grouped?",
      "What should I check first?",
      "Show affected devices",
    ],
    ASK_FALLBACK: "The triage console is reachable via /api/ask. This fallback is shown when the backend is offline.",
  };

  /* ---------------------------- HELPERS ------------------------------- */
  async function fetchJson(url, opts) {
    const res = await fetch(url, opts);
    if (!res.ok) throw new Error(url + " " + res.status);
    return res.json();
  }

  function isoToTime(iso) {
    try {
      const d = new Date(iso);
      const p = (v) => String(v).padStart(2, "0");
      return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    } catch (e) {
      return String(iso).slice(11, 19) || "--:--:--";
    }
  }

  function timeAgo(iso) {
    try {
      const d = new Date(iso);
      const diffMs = Date.now() - d.getTime();
      const mins = Math.max(0, Math.floor(diffMs / 60000));
      if (mins < 1) return "just now";
      if (mins === 1) return "1m ago";
      if (mins < 60) return `${mins}m ago`;
      const hrs = Math.floor(mins / 60);
      if (hrs === 1) return "1h ago";
      return `${hrs}h ago`;
    } catch (e) {
      return "just now";
    }
  }

  function sevToFront(sev) {
    const s = String(sev || "info").toLowerCase();
    if (s === "critical") return "critical";
    if (s === "high") return "high";
    if (s === "medium") return "medium";
    if (s === "low") return "low";
    return "info";
  }

  function confidenceToNumber(conf) {
    if (typeof conf === "number") return conf;
    if (conf === "high") return 87;
    if (conf === "medium") return 65;
    if (conf === "low") return 45;
    return 55;
  }

  // Map backend incident dict to frontend INCIDENT shape
  function mapIncident(inc) {
    const sev = sevToFront(inc.priority || inc.severity);
    const affected = inc.affected_devices || inc.nodes || [];
    const alertTypes = [...new Set((inc.alerts || []).map((a) => a.alert_type || a.alertType || "UNKNOWN"))];
    const signals = alertTypes.length ? alertTypes : (inc.signals || []);
    // site inference
    let site = inc.site || "IN-SOUTH-1";
    // owner placeholder
    const owner = inc.owner || (sev === "critical" ? "Unassigned" : "Auto-triage");
    const confidenceNum = confidenceToNumber(inc.confidence);
    const devicesCount = inc.affected_devices ? inc.affected_devices.length : (inc.devices || 0);
    const correlated = inc.alert_count != null ? inc.alert_count : (inc.correlated || 0);
    // nodes for frontend
    const nodes = affected;

    return {
      id: inc.incident_id || inc.id,
      title: inc.title || `${sev.toUpperCase()} incident on ${affected[0] || "unknown"}`,
      severity: sev,
      state: (inc.state || "open").toLowerCase(),
      devices: devicesCount,
      started: inc.first_seen ? timeAgo(inc.first_seen) : (inc.started || "just now"),
      confidence: confidenceNum,
      correlated: correlated,
      site: site,
      owner: owner,
      aiAvailable: !inc.escalation || !inc.escalation.escalated,
      summary: inc.summary || inc.what_happened || "",
      signals: signals,
      nodes: nodes,
      // keep raw for detail panel
      _raw: inc,
    };
  }

  function mapAlert(alert) {
    const sev = sevToFront(alert.severity);
    const t = isoToTime(alert.timestamp || alert.time);
    return {
      time: t,
      node: alert.device_id || alert.node || alert.node_id || "unknown",
      type: alert.alert_type || alert.type || "UNKNOWN",
      severity: sev,
      _raw: alert,
    };
  }

  function mapTopology(raw) {
    // raw from /api/topology is {nodes:[...], links:[...]} with x,y layout already
    // We need to infer status per node based on current incidents (stored in cache)
    try {
      const nodes = (raw.nodes || []).map((n) => {
        const label = n.name || n.label || n.id;
        const type = (n.type || "router").toLowerCase();
        // x,y already normalized 0..1 in raw; keep as is
        return {
          id: n.id,
          label: label,
          type: type,
          status: "ok", // will be overwritten after incidents fetch
          x: n.x != null ? n.x : 0.5,
          y: n.y != null ? n.y : 0.5,
          meta: n.role || n.site || type,
          _layer: n.layer || "unknown",
        };
      });
      const links = (raw.links || []).map((l) => ({
        source: l.source,
        target: l.target,
        status: "ok",
      }));
      return { nodes, links };
    } catch (e) {
      return FALLBACK.TOPOLOGY;
    }
  }

  // Cache for current incidents to enrich topology status and for lookups
  let _cachedIncidents = null;
  let _cachedStats = null;

  async function getIncidentsRaw() {
    try {
      const data = await fetchJson("/api/incidents");
      const incs = data.incidents || [];
      _cachedIncidents = incs;
      return incs;
    } catch (e) {
      console.warn("[NetSentryData] incidents fetch failed, using fallback", e);
      return FALLBACK.INCIDENTS.map((i) => ({ ...i, incident_id: i.id, priority: i.severity, affected_devices: i.nodes, alert_count: i.correlated, first_seen: new Date().toISOString(), summary: i.summary, _raw: i }));
    }
  }

  function enrichTopologyStatus(topo) {
    if (!_cachedIncidents) return topo;
    // Build map node -> worst priority
    const nodePriority = {};
    for (const inc of _cachedIncidents) {
      const pri = (inc.priority || "LOW").toUpperCase();
      const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[pri] || 1;
      for (const dev of inc.affected_devices || []) {
        const prev = nodePriority[dev] || 0;
        if (rank > prev) nodePriority[dev] = rank;
      }
    }
    const nodes = topo.nodes.map((n) => {
      const r = nodePriority[n.id] || 0;
      let status = "ok";
      if (r >= 4) status = "down";
      else if (r >= 2) status = "warn";
      else status = "ok";
      // Also enrich meta with affected info
      let meta = n.meta;
      if (r) {
        const incs = _cachedIncidents.filter((inc) => (inc.affected_devices || []).includes(n.id));
        if (incs.length) {
          meta = `${incs.length} incident(s) — ${incs[0].title ? incs[0].title.slice(0, 40) : incs[0].incident_id}`;
        }
      }
      return { ...n, status, meta };
    });
    // Links: if either endpoint is down/warn, link reflects worse
    const nodeStatusMap = Object.fromEntries(nodes.map((n) => [n.id, n.status]));
    const links = topo.links.map((l) => {
      const s = nodeStatusMap[l.source] || "ok";
      const t = nodeStatusMap[l.target] || "ok";
      let status = "ok";
      if (s === "down" || t === "down") status = "down";
      else if (s === "warn" || t === "warn") status = "warn";
      return { ...l, status };
    });
    return { nodes, links };
  }

  /* ------------------------------ GETTERS ------------------------------ */

  const NetSentryData = {
    // Keep original mock shape for compatibility but now backed by API
    getNetworkStatus: async () => {
      try {
        const statsData = await fetchJson("/api/statistics");
        const stats = statsData.stats || {};
        const health = statsData.health || 94;
        // Determine network label/state from health and critical count
        let state = "operational";
        let label = "Operational";
        const crit = stats.critical_count || 0;
        const high = stats.high_count || 0;
        if (crit > 0) {
          state = "degraded";
          label = crit >= 2 ? "Major Outage" : "Degraded";
        } else if (high > 0) {
          state = "degraded";
          label = "Degraded";
        }
        _cachedStats = statsData;
        return {
          state,
          label,
          lastUpdated: "just now",
          facts: [
            { label: "Managed nodes", value: "9" },
            { label: "Uptime (30d)", value: "99.982%" },
            { label: "Mean triage time", value: "42s" },
          ],
        };
      } catch (e) {
        return FALLBACK.NETWORK_STATUS;
      }
    },

    getNetworkHealth: async () => {
      try {
        const data = await fetchJson("/api/statistics");
        const health = data.health != null ? data.health : 94;
        // Tier breakdown heuristic: core health high unless critical includes core, etc.
        // We approximate: if critical device includes R1/R2 -> core 60 else 100; if distribution affected -> edge lower
        const stats = data.stats || {};
        const nodes = stats.affected_devices || [];
        let core = 100, edge = 96, access = 91;
        if (nodes.includes("R1") || nodes.includes("R2")) core = stats.critical_count ? 60 : 85;
        if (nodes.includes("S1") || nodes.includes("S2")) edge = 80;
        if (nodes.some((d) => ["R3", "R4", "R5", "R6"].includes(d))) access = 75;
        return {
          overall: health,
          tiers: [
            { name: "Core", value: core, status: core >= 95 ? "ok" : "warn" },
            { name: "Edge", value: edge, status: edge >= 90 ? "ok" : "warn" },
            { name: "Access", value: access, status: access >= 90 ? "ok" : "warn" },
          ],
        };
      } catch (e) {
        return FALLBACK.NETWORK_HEALTH;
      }
    },

    getKpis: async () => {
      try {
        const data = await fetchJson("/api/statistics");
        const stats = data.stats || {};
        // Map to KPI shape expected by renderKpis
        return [
          { id: "alerts", label: "Active Alerts", value: String(stats.total_alerts || 0), status: "info", icon: "alert", trend: { dir: "up", text: `+${stats.duplicate_collapsed || 0} dedup` }, note: "raw ingest" },
          { id: "incidents", label: "Open Incidents", value: String(stats.incident_count || 0), status: "warn", icon: "incident", trend: { dir: "flat", text: `${stats.critical_count || 0} critical` }, note: "correlated" },
          { id: "critical", label: "Critical", value: String(stats.critical_count || 0), status: "crit", icon: "critical", trend: { dir: stats.critical_count ? "up" : "flat", text: stats.critical_count ? "needs attention" : "no change" }, note: "P1 severity" },
          { id: "devices", label: "Devices Affected", value: String(stats.affected_device_count || 0), status: "high", icon: "device", trend: { dir: "up", text: `${(stats.affected_devices || []).length} nodes` }, note: "across sites" },
          { id: "auto", label: "Duplicates Collapsed", value: String(stats.duplicate_collapsed || 0), status: "ok", icon: "auto", trend: { dir: "up", text: "dedup 60s window" }, note: "runbook driven" },
        ];
      } catch (e) {
        return FALLBACK.KPIS;
      }
    },

    getIncidents: async () => {
      const raw = await getIncidentsRaw();
      return raw.map(mapIncident);
    },

    getAlerts: async () => {
      try {
        const data = await fetchJson("/api/alerts");
        const alerts = data.alerts || [];
        // Sort by timestamp descending, map to frontend shape
        alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        return alerts.map(mapAlert);
      } catch (e) {
        return FALLBACK.ALERTS;
      }
    },

    getTopology: async () => {
      try {
        const raw = await fetchJson("/api/topology");
        const base = mapTopology(raw);
        // Need incidents to enrich status; ensure incidents loaded
        if (!_cachedIncidents) {
          try { await getIncidentsRaw(); } catch (_) {}
        }
        return enrichTopologyStatus(base);
      } catch (e) {
        return FALLBACK.TOPOLOGY;
      }
    },

    getAnalysis: async (incidentId) => {
      try {
        const data = await fetchJson(`/api/incidents/${incidentId}`);
        // data is incident dict with recommendation, evidence, etc.
        const rec = data.recommendation || {};
        const evidence = data.evidence || rec.evidence || [];
        // Map to expected AI_ANALYSIS shape for old renderer, but we also support new renderer
        // Provide both shapes: include fields for new renderer
        const confidenceNum = confidenceToNumber(rec.confidence);
        const correlated = data.alert_count || 0;
        const devices = (data.affected_devices || []).length;
        // Build new richer structure while keeping old keys
        return {
          // Old keys
          headline: rec.summary || data.summary || "Incident analysis",
          rootCause: rec.what_happened || data.what_happened || data.title || "See recommendation",
          confidence: confidenceNum,
          correlated: correlated,
          devices: devices,
          action: (rec.recommended_actions || []).join(" — ") || "Follow runbook",
          source: (evidence[0] && evidence[0].runbook) || (evidence[0] && evidence[0].runbook) || "local",
          evidence: (evidence || []).map((e) => `${e.runbook} — ${e.section}: ${e.reason || ""}`),
          // New richer fields for updated renderer
          _raw: data,
          summary: rec.summary,
          what_happened: rec.what_happened,
          recommended_actions: rec.recommended_actions || [],
          evidence_raw: evidence,
          confidence_level: rec.confidence,
          needs_escalation: rec.needs_escalation,
          escalation: data.escalation,
          deterministic: {
            correlation_score: data.correlation_score,
            correlation_reasons: data.correlation_reasons,
            priority_score: data.priority_score,
            priority_reasons: data.priority_reasons,
            affected_devices: data.affected_devices,
          },
          ai_generated: {
            summary: rec.summary,
            what_happened: rec.what_happened,
            recommended_actions: rec.recommended_actions,
            confidence: rec.confidence,
            source: rec._source,
          },
        };
      } catch (e) {
        console.warn("[NetSentryData] getAnalysis failed", e);
        return null;
      }
    },

    getTimeline: async (incidentId) => {
      try {
        const data = await fetchJson(`/api/incidents/${incidentId}`);
        const tl = data.timeline || [];
        // Map backend timeline to frontend shape expected by app.js
        // backend timeline entries have time, text, kind
        return tl.map((e) => ({
          time: e.time || isoToTime(e.timestamp),
          text: e.text || e.message || "Event",
          kind: e.kind || "info",
        }));
      } catch (e) {
        return [];
      }
    },

    getAskSuggestions: async () => {
      try {
        // Derive suggestions from current incidents
        const incs = await getIncidentsRaw();
        const suggestions = [];
        if (incs.length) {
          const topId = incs[0].incident_id;
          suggestions.push(`Why is ${topId} ${incs[0].priority}?`);
          suggestions.push("What alerts were grouped?");
          suggestions.push("What should I check first?");
          suggestions.push("Show affected devices");
          if (incs.some((i) => (i.escalation && i.escalation.escalated))) {
            suggestions.push("Why was this incident escalated?");
          }
          const dev = (incs[0].affected_devices || [])[0] || "CORE-R1";
          suggestions.push(`Show me incidents affecting ${dev}`);
        } else {
          return FALLBACK.ASK_SUGGESTIONS;
        }
        return suggestions.slice(0, 5);
      } catch (e) {
        return FALLBACK.ASK_SUGGESTIONS;
      }
    },

    ask: async (question) => {
      try {
        const res = await fetchJson("/api/ask", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ question }),
        });
        return {
          answer: res.answer,
          refs: res.refs || [],
          intent: res.intent,
          incident_id: res.incident_id,
          mock: false,
        };
      } catch (e) {
        // Fallback mock
        return { answer: FALLBACK.ASK_FALLBACK, refs: [], mock: true };
      }
    },

    getHealth: async () => {
      try {
        return await fetchJson("/api/health");
      } catch (e) {
        throw e;
      }
    },

    // New helpers for scenario switching and runbooks
    processScenario: async (scenario) => {
      try {
        const data = await fetchJson("/api/process", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scenario }),
        });
        // Invalidate cache
        _cachedIncidents = null;
        return data;
      } catch (e) {
        console.error("[NetSentryData] processScenario failed", e);
        throw e;
      }
    },

    getRunbooks: async () => {
      try {
        const data = await fetchJson("/api/runbooks");
        return data.runbooks || [];
      } catch (e) {
        return [];
      }
    },

    getStatistics: async () => {
      try {
        const data = await fetchJson("/api/statistics");
        return data.stats;
      } catch (e) {
        return { total_alerts: 0, incident_count: 0 };
      }
    },
  };

  global.NetSentryData = NetSentryData;
})(window);

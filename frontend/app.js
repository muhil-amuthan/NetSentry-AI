/*
 * NetSentry AI — dashboard UI controller (Live Backend Integrated)
 *
 * Pure presentation. No correlation, scoring, dedup or retrieval logic lives
 * here — all of that belongs to the backend engine. Every value rendered comes
 * from window.NetSentryData (see data.js), which now fetches from FastAPI.
 */
(function () {
  "use strict";

  const D = window.NetSentryData;
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  /* Severity / status -> CSS custom property colour token. */
  const SEV_COLOR = {
    critical: ["var(--crit)", "var(--crit-dim)"],
    high:     ["var(--high)", "var(--high-dim)"],
    medium:   ["var(--warn)", "var(--warn-dim)"],
    low:      ["var(--info)", "var(--info-dim)"],
    ok:       ["var(--ok)",   "var(--ok-dim)"],
    warn:     ["var(--warn)", "var(--warn-dim)"],
    crit:     ["var(--crit)", "var(--crit-dim)"],
    info:     ["var(--info)", "var(--info-dim)"],
  };
  const setSev = (el, key) => {
    const [c, dim] = SEV_COLOR[key] || SEV_COLOR.info;
    el.style.setProperty("--c", c);
    el.style.setProperty("--c-dim", dim);
  };

  const ICONS = {
    alert:    '<path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 10v4M12 17h.01"/>',
    incident: '<path d="M4 5h16v12H8l-4 3V5Z"/><path d="M9 9h6M9 13h4"/>',
    critical: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5v5M12 16h.01"/>',
    device:   '<rect x="3" y="6" width="18" height="5" rx="1.5"/><rect x="3" y="14" width="18" height="5" rx="1.5"/><path d="M6.5 8.5h.01M6.5 16.5h.01"/>',
    auto:     '<path d="M20 12a8 8 0 1 1-2.6-5.9"/><path d="M20 4v4h-4"/><path d="m9 12 2 2 4-4"/>',
    devices:  '<rect x="3" y="6" width="18" height="5" rx="1.5"/>',
    clock:    '<circle cx="12" cy="12" r="8"/><path d="M12 7.5V12l3 1.8"/>',
    chevron:  '<path d="m6 9 6 6 6-6"/>',
    up:       '<path d="M12 19V5M6 11l6-6 6 6"/>',
    down:     '<path d="M12 5v14M18 13l-6 6-6-6"/>',
    flat:     '<path d="M5 12h14"/>',
    site:     '<path d="M12 21s7-5.3 7-11a7 7 0 1 0-14 0c0 5.7 7 11 7 11Z"/><circle cx="12" cy="10" r="2.5"/>',
  };
  const svg = (name, cls = "") =>
    `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ""}</svg>`;

  const SEV_LABEL = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };
  const SEV_SHORT = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW" };

  /* ======================================================================
     CLOCK
     ====================================================================== */
  function initClock() {
    const el = $("#clock");
    const tick = () => {
      const n = new Date();
      const p = (v) => String(v).padStart(2, "0");
      el.textContent = `${p(n.getHours())}:${p(n.getMinutes())}:${p(n.getSeconds())} IST`;
    };
    tick();
    setInterval(tick, 1000);
  }

  /* ======================================================================
     HERO + NETWORK HEALTH
     ====================================================================== */
  async function renderHero() {
    try {
      const [status, health] = await Promise.all([D.getNetworkStatus(), D.getNetworkHealth()]);

      $("#netStatusText").textContent = status.label;
      $("#lastUpdated").textContent = status.lastUpdated;
      const hero = $(".hero");
      hero.classList.toggle("is-degraded", status.state === "degraded");
      hero.classList.toggle("is-outage", status.state === "outage");

      $("#heroFacts").innerHTML = status.facts
        .map((f) => `<li><span class="k">${f.label}</span><span class="v">${f.value}</span></li>`)
        .join("");

      const SEGMENTS = 20;
      const filled = Math.round((health.overall / 100) * SEGMENTS);
      $("#healthBar").innerHTML = Array.from({ length: SEGMENTS }, (_, i) =>
        i < filled ? '<i class="on"></i>' : "<i></i>"
      ).join("");
      $("#healthBar").setAttribute("aria-label", `Overall network health ${health.overall} percent`);

      const scoreEl = $("#healthScore");
      scoreEl.textContent = `${health.overall}%`;
      scoreEl.style.color = health.overall >= 95 ? "var(--ok)" : health.overall >= 85 ? "var(--warn)" : "var(--crit)";

      $("#tierList").innerHTML = health.tiers
        .map(
          (t) => `<li>
            <span class="tier__name">${t.name}</span>
            <span class="tier__track"><b class="tier__fill ${t.status === "warn" ? "warn" : ""}" style="width:${t.value}%"></b></span>
            <span class="tier__val">${t.value}%</span>
          </li>`
        )
        .join("");
    } catch (e) {
      console.error("[hero] failed", e);
    }
  }

  /* ======================================================================
     KPI CARDS
     ====================================================================== */
  async function renderKpis() {
    try {
      const kpis = await D.getKpis();
      const grid = $("#kpiGrid");
      grid.innerHTML = "";
      kpis.forEach((k) => {
        const card = document.createElement("article");
        card.className = "kpi";
        card.dataset.kpi = k.id;
        setSev(card, k.status);
        const dir = k.trend.dir;
        card.innerHTML = `
          <div class="kpi__top">
            <span class="kpi__icon">${svg(k.icon)}</span>
            <span class="kpi__tag">${k.status === "crit" ? "Critical" : k.status === "high" ? "High" : k.status === "warn" ? "Warning" : k.status === "ok" ? "Healthy" : "Info"}</span>
          </div>
          <p class="kpi__value">${k.value}</p>
          <p class="kpi__label">${k.label}</p>
          <p class="kpi__foot">
            <span class="trend trend--${dir}">${svg(dir)}${k.trend.text}</span>
            <span>· ${k.note}</span>
          </p>`;
        grid.appendChild(card);
      });
    } catch (e) {
      console.error("[kpi] failed", e);
    }
  }

  /* ======================================================================
     INCIDENTS
     ====================================================================== */
  let incidents = [];
  let selectedIncident = null;
  let activeFilter = "all";
  let _incListenersBound = false;

  function incidentMarkup(inc) {
    const dash = 2 * Math.PI * 14;
    const offset = dash * (1 - inc.confidence / 100);
    const raw = inc._raw || {};
    const escalated = raw.escalation && raw.escalation.escalated;
    const priorityScore = raw.priority_score != null ? raw.priority_score : inc.confidence;
    const priorityLabel = raw.priority || inc.severity;
    const escBadge = escalated ? `<span class="chip chip--crit" style="font-size:10px;">ESCALATED</span>` : "";
    // Show priority score explicitly
    const scoreBadge = `<span class="mono" style="font-size:11px; color:var(--text-dim);">Score ${priorityScore}</span>`;
    return `
      <button class="incident__head" aria-expanded="false" aria-controls="body-${inc.id}">
        <span class="sevbadge">${svg(inc.severity === "critical" ? "critical" : "alert")}${SEV_LABEL[inc.severity] || priorityLabel}</span>
        <span style="flex:1;">
          <span class="incident__id">${inc.id} · ${inc.site} ${escBadge} ${scoreBadge}</span>
          <span class="incident__title">${inc.title}</span>
          <span class="incident__facts">
            <span>${svg("devices")}${inc.devices} devices affected</span>
            <span>${svg("clock")}Started ${inc.started}</span>
            ${inc.aiAvailable ? '<span class="aiflag"><i class="ai-spark"></i>AI recommendation available</span>' : '<span class="aiflag" style="opacity:0.6;">No runbook — escalated</span>'}
          </span>
        </span>
        <span class="incident__right">
          <span class="conf">
            <span class="conf__label">Priority score</span>
            <span class="conf__row">
              <svg class="dial" viewBox="0 0 32 32" aria-hidden="true">
                <circle class="dial__bg" cx="16" cy="16" r="14"></circle>
                <circle class="dial__fg" cx="16" cy="16" r="14"
                  stroke-dasharray="${dash.toFixed(1)}" stroke-dashoffset="${offset.toFixed(1)}"
                  transform="rotate(-90 16 16)"></circle>
              </svg>
              <span class="conf__val">${inc.confidence}%</span>
            </span>
          </span>
          ${svg("chevron", "chev")}
        </span>
      </button>
      <div class="incident__body" id="body-${inc.id}">
        <div class="incident__bodyinner">
          <div class="incident__detail">
            <p class="incident__summary">${inc.summary}</p>
            <div class="tagrow">${inc.signals.map((s) => `<span class="tag">${s}</span>`).join("")}</div>
            <div class="detailgrid">
              <div><span class="k">Status</span><span class="v">${inc.state}</span></div>
              <div><span class="k">Correlated alerts</span><span class="v mono">${inc.correlated}</span></div>
              <div><span class="k">Priority</span><span class="v mono">${priorityLabel} (${priorityScore})</span></div>
              <div><span class="k">Nodes</span><span class="v mono">${inc.nodes.join(", ")}</span></div>
            </div>
            ${escalated ? `<div style="margin:10px 0; padding:8px 10px; background:var(--crit-dim); border:1px solid var(--crit); border-radius:6px; font-size:12px;"><strong>Escalated:</strong> ${raw.escalation.reason || "No runbook"}</div>` : ""}
            <div class="incident__actions">
              <button class="primarybtn" data-action="view" data-id="${inc.id}">View Incident</button>
              <button class="ghostbtn" data-action="ask" data-id="${inc.id}">Ask NetSentry</button>
            </div>
          </div>
        </div>
      </div>`;
  }

  function paintIncidents() {
    const list = $("#incidentList");
    const visible = incidents.filter((i) => {
      if (activeFilter === "all") return true;
      if (activeFilter === "open") return i.state === "open";
      return i.severity === activeFilter;
    });

    list.innerHTML = "";
    if (!visible.length) {
      list.innerHTML = '<li style="padding:24px;text-align:center;color:var(--text-faint)">No incidents match this filter.</li>';
      return;
    }
    visible.forEach((inc) => {
      const li = document.createElement("li");
      li.className = "incident";
      li.dataset.id = inc.id;
      setSev(li, inc.severity);
      li.innerHTML = incidentMarkup(inc);
      if (inc.id === selectedIncident) li.classList.add("is-selected");
      list.appendChild(li);
    });
    // Update subtitle count
    const sub = $("#incSub");
    if (sub) sub.textContent = `${visible.length} of ${incidents.length} incidents · ranked by deterministic priority score · live backend`;
  }

  async function selectIncident(id) {
    selectedIncident = id;
    $$(".incident").forEach((el) => el.classList.toggle("is-selected", el.dataset.id === id));
    await Promise.all([renderAi(id), renderTimeline(id)]);
    // Highlight topology nodes for this incident
    const inc = incidents.find((i) => i.id === id);
    if (inc && inc.nodes) {
      // Highlight via topology
      inc.nodes.forEach((n) => Topology.highlight(n));
    }
  }

  async function renderIncidents() {
    incidents = await D.getIncidents();
    // Sort already by backend priority order, but keep as is
    selectedIncident = incidents[0] ? incidents[0].id : null;
    paintIncidents();

    if (!_incListenersBound) {
      _incListenersBound = true;
      $("#incidentList").addEventListener("click", (e) => {
        const action = e.target.closest("[data-action]");
        if (action) {
          e.stopPropagation();
          const inc = incidents.find((i) => i.id === action.dataset.id);
          if (action.dataset.action === "ask") {
            Ask.open(`Why is ${inc.id} ${inc.severity}?`);
          } else {
            selectIncident(inc.id);
            $("#timeline").scrollIntoView({ behavior: "smooth", block: "center" });
          }
          return;
        }
        const head = e.target.closest(".incident__head");
        if (!head) return;
        const card = head.closest(".incident");
        const open = card.classList.toggle("is-open");
        head.setAttribute("aria-expanded", String(open));
        selectIncident(card.dataset.id);
      });

      $$(".seg").forEach((btn) =>
        btn.addEventListener("click", () => {
          $$(".seg").forEach((b) => b.classList.remove("is-active"));
          btn.classList.add("is-active");
          activeFilter = btn.dataset.filter;
          paintIncidents();
        })
      );
    }
    if (selectedIncident) await selectIncident(selectedIncident);
  }

  async function refreshIncidents() {
    incidents = await D.getIncidents();
    // keep selected if still exists else pick first
    if (!incidents.find((i) => i.id === selectedIncident)) {
      selectedIncident = incidents[0] ? incidents[0].id : null;
    }
    paintIncidents();
    if (selectedIncident) await selectIncident(selectedIncident);
  }

  /* ======================================================================
     LIVE ALERT STREAM
     ====================================================================== */
  const Stream = (function () {
    let buffer = [];
    let cursor = 0;
    let timer = null;
    let live = true;
    const MAX_ROWS = 40;
    const INTERVAL = 3200;

    function nowStamp() {
      const n = new Date();
      const p = (v) => String(v).padStart(2, "0");
      return `${p(n.getHours())}:${p(n.getMinutes())}:${p(n.getSeconds())}`;
    }

    function row(a, isNew) {
      const li = document.createElement("li");
      li.className = "alert" + (isNew ? " is-new" : "");
      li.tabIndex = 0;
      li.dataset.node = a.node;
      setSev(li, a.severity);
      li.innerHTML = `
        <span class="alert__time">${a.time}</span>
        <span class="alert__node">${a.node}</span>
        <span class="alert__type" title="${a.type}">${a.type}</span>
        <span class="alert__sev"><i></i>${SEV_SHORT[a.severity] || a.severity.toUpperCase()}</span>`;
      li.setAttribute("aria-label", `${a.time} ${a.node} ${a.type.replace(/_/g, " ")} severity ${a.severity}`);
      return li;
    }

    function push(alert) {
      const list = $("#alertStream");
      if (!list) return;
      list.prepend(row(alert, true));
      while (list.children.length > MAX_ROWS) list.lastElementChild.remove();
      $("#streamCount").textContent = list.children.length;
    }

    function tick() {
      if (!live || !buffer.length) return;
      const a = buffer[cursor % buffer.length];
      cursor += 1;
      push({ ...a, time: nowStamp() });
    }

    async function init() {
      buffer = await D.getAlerts();
      const list = $("#alertStream");
      list.innerHTML = "";
      buffer.slice(-12).forEach((a) => list.prepend(row(a, false)));
      $("#streamCount").textContent = list.children.length;
      cursor = buffer.length;
      if (timer) clearInterval(timer);
      timer = setInterval(tick, INTERVAL);

      document.addEventListener("visibilitychange", () => {
        if (document.hidden) { clearInterval(timer); timer = null; }
        else if (live && !timer) { timer = setInterval(tick, INTERVAL); }
      });

      const toggle = $("#streamToggle");
      if (toggle && !toggle._bound) {
        toggle._bound = true;
        toggle.addEventListener("click", () => {
          live = !live;
          toggle.setAttribute("aria-pressed", String(live));
          toggle.lastChild.textContent = live ? " Live" : " Paused";
        });
      }

      list.addEventListener("click", (e) => {
        const el = e.target.closest(".alert");
        if (!el) return;
        $$(".alert", list).forEach((a) => a.classList.remove("is-selected"));
        el.classList.add("is-selected");
        Topology.highlight(el.dataset.node);
      });
    }

    async function refresh() {
      if (timer) clearInterval(timer);
      await init();
    }

    return { init, refresh };
  })();

  /* ======================================================================
     TOPOLOGY
     ====================================================================== */
  const Topology = (function () {
    const W = 720, H = 380, PAD_X = 60, PAD_Y = 34;
    const BOX_W = 92, BOX_H = 44;
    let data = null;

    const px = (n) => PAD_X + n.x * (W - PAD_X * 2);
    const py = (n) => PAD_Y + n.y * (H - PAD_Y * 2);
    const cls = (s) => (s === "down" ? "is-down" : s === "warn" ? "is-warn" : "is-ok");

    function render() {
      const svgEl = $("#topoSvg");
      if (!svgEl || !data) return;
      const byId = Object.fromEntries(data.nodes.map((n) => [n.id, n]));
      const parts = [];

      data.links.forEach((l) => {
        const a = byId[l.source], b = byId[l.target];
        if (!a || !b) return;
        const x1 = px(a), y1 = py(a) + BOX_H / 2;
        const x2 = px(b), y2 = py(b) - BOX_H / 2;
        const my = (y1 + y2) / 2;
        const d = `M ${x1} ${y1} V ${my} H ${x2} V ${y2}`;
        parts.push(`<path class="link link--${l.status}" d="${d}" data-link="${l.source}-${l.target}" fill="none"/>`);
        if (l.status === "ok") {
          parts.push(`<circle class="pkt" r="2.6"><animateMotion dur="3s" repeatCount="indefinite" path="${d}"/></circle>`);
        }
      });

      data.nodes.forEach((n) => {
        const x = px(n), y = py(n);
        const left = x - BOX_W / 2, top = y - BOX_H / 2;
        const halo = n.status === "down"
          ? `<rect class="node__halo" x="${left - 4}" y="${top - 4}" width="${BOX_W + 8}" height="${BOX_H + 8}" rx="11"/>` : "";
        parts.push(`
          <g class="node ${cls(n.status)}" data-node="${n.id}" tabindex="0" role="button"
             aria-label="${n.label}, status ${n.status === "down" ? "down" : n.status === "warn" ? "degraded" : "healthy"}. ${n.meta}">
            ${halo}
            <rect class="node__box" x="${left}" y="${top}" width="${BOX_W}" height="${BOX_H}"/>
            <circle class="node__dot node__dot--${n.status}" cx="${left + 11}" cy="${top + 11}" r="3.4"/>
            <text class="node__label" x="${x}" y="${y + 1}">${n.label}</text>
            <text class="node__sub" x="${x}" y="${y + 14}">${n.type.toUpperCase()}</text>
          </g>`);
      });

      svgEl.innerHTML = parts.join("");
      bind(svgEl);
    }

    function bind(svgEl) {
      const tip = $("#topoTip");
      const wrap = $(".topowrap");
      if (!tip || !wrap) return;
      const show = (g) => {
        const n = data.nodes.find((x) => x.id === g.dataset.node);
        if (!n) return;
        tip.hidden = false;
        tip.innerHTML = `<strong>${n.label}</strong><small>${n.meta}</small>`;
        const r = wrap.getBoundingClientRect();
        const b = g.getBoundingClientRect();
        tip.style.left = `${b.left - r.left + b.width / 2}px`;
        tip.style.top = `${b.top - r.top}px`;
      };
      $$(".node", svgEl).forEach((g) => {
        g.addEventListener("mouseenter", () => show(g));
        g.addEventListener("focus", () => show(g));
        g.addEventListener("mouseleave", () => { tip.hidden = true; });
        g.addEventListener("blur", () => { tip.hidden = true; });
      });
    }

    function highlight(nodeId) {
      $$(".node").forEach((g) => {
        const box = $(".node__box", g);
        if (!box) return;
        box.style.stroke = g.dataset.node === nodeId ? "var(--info)" : "";
      });
    }

    async function init() {
      data = await D.getTopology();
      render();
      const refreshBtn = $("#topoRefresh");
      if (refreshBtn && !refreshBtn._bound) {
        refreshBtn._bound = true;
        refreshBtn.addEventListener("click", async () => {
          refreshBtn.textContent = "Refreshing...";
          data = await D.getTopology();
          render();
          setTimeout(() => (refreshBtn.textContent = "Refresh"), 800);
        });
      }
    }

    async function refresh() {
      data = await D.getTopology();
      render();
    }

    return { init, highlight, refresh, setData: (d) => { data = d; render(); } };
  })();

  /* ======================================================================
     AI INSIGHT PANEL — grounded recommendation with deterministic vs AI split
     ====================================================================== */
  async function renderAi(incidentId) {
    const el = $("#aiPanel");
    const chip = $("#aiChip");
    const sub = $("#aiSub");
    try {
      const a = await D.getAnalysis(incidentId);
      if (!a) {
        el.innerHTML = '<p class="ai-action">No AI analysis available for this incident yet.</p>';
        return;
      }
      const raw = a._raw || {};
      const isEscalated = raw.escalation && raw.escalation.escalated;
      const source = (a.ai_generated && a.ai_generated.source) || "deterministic";
      const isAI = source === "gemini";
      if (chip) {
        chip.textContent = isAI ? "GEMINI" : "LIVE";
        chip.className = isAI ? "chip chip--ok" : "chip chip--info";
      }
      if (sub) sub.textContent = isEscalated ? "Escalated — human investigation required" : isAI ? "Grounded Gemini recommendation · evidence cited" : "Deterministic recommendation · evidence backed";

      // Deterministic facts vs AI explanation
      const det = a.deterministic || {};
      const ai = a.ai_generated || {};

      const evidenceList = a.evidence_raw || a.evidence || [];
      const evidenceHtml = evidenceList.length
        ? evidenceList.map((e) => {
            const rb = e.runbook || e.runbook_id || e;
            const sec = e.section || "";
            const reason = e.reason || "";
            return `<li><strong>${rb}</strong> — ${sec}<br><small style="color:var(--text-dim);">${reason}</small></li>`;
          }).join("")
        : '<li style="color:var(--text-faint)">No matching runbook — insufficient evidence to ground recommendation.</li>';

      const actions = a.recommended_actions || (a.action ? [a.action] : []);
      const actionsHtml = actions.length
        ? actions.map((act, idx) => `<li><span class="mono" style="color:var(--text-faint);">Step ${idx + 1}.</span> ${act}</li>`).join("")
        : '<li style="color:var(--text-faint)">No recommended actions — see escalation.</li>';

      const escHtml = isEscalated
        ? `<div style="margin:12px 0; padding:10px 12px; background:var(--crit-dim); border:1px solid var(--crit); border-radius:8px;">
             <strong style="color:var(--crit);">ESCALATED — ${raw.escalation.reason}</strong>
             <p style="margin:6px 0 0; font-size:12px; color:var(--text-dim);">${raw.escalation.summary || ""}</p>
             <p style="margin:6px 0 0; font-size:12px;"><strong>Next step:</strong> ${raw.escalation.next_step}</p>
             <p style="margin:6px 0 0; font-size:11px; color:var(--text-faint);">Grouped alerts: ${raw.escalation.grouped_alerts ? raw.escalation.grouped_alerts.length : (raw.alert_count || 0)} · Affected: ${(raw.affected_devices || []).join(", ")}</p>
           </div>`
        : "";

      el.innerHTML = `
        <p class="ai-kicker">AI Incident Analysis · ${incidentId} ${isAI ? "· Gemini grounded" : "· Deterministic"}</p>
        <p class="ai-headline">${a.headline || a.summary || "Incident analysis"}</p>

        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin:12px 0;">
          <div class="ai-block">
            <span class="k">DETERMINISTIC FACTS</span>
            <div style="font-size:12px; line-height:1.5; color:var(--text-dim);">
              <div><strong>Correlation score:</strong> ${det.correlation_score != null ? det.correlation_score : "—"} </div>
              <div><strong>Priority:</strong> ${det.priority_reasons ? det.priority_reasons[0] : (raw.priority ? raw.priority + " (" + raw.priority_score + ")" : "")}</div>
              <div><strong>Affected:</strong> ${(det.affected_devices || raw.affected_devices || []).join(", ") || "—"}</div>
              <div><strong>Alert count:</strong> ${raw.alert_count || a.correlated || "—"}</div>
              <div style="margin-top:6px; font-size:11px; color:var(--text-faint);">${(det.correlation_reasons || []).slice(0,1).join(" ") || ""}</div>
            </div>
          </div>
          <div class="ai-block">
            <span class="k">AI-GENERATED EXPLANATION</span>
            <div style="font-size:12px; line-height:1.5; color:var(--text-dim);">
              <div>${a.what_happened || a.rootCause || ""}</div>
              <div style="margin-top:6px;"><strong>Confidence:</strong> <span class="${a.confidence >= 80 ? "conf-hi" : ""}">${a.confidence_level || a.confidence || "low"} (${a.confidence}%)</span></div>
              <div><strong>Source:</strong> ${source}</div>
            </div>
            <div class="confbar" style="margin-top:8px;"><i style="width:${a.confidence}%"></i></div>
          </div>
        </div>

        <div class="ai-metrics">
          <div class="ai-block"><span class="k">Confidence</span><span class="v ${a.confidence >= 80 ? "conf-hi" : ""}">${a.confidence}%</span></div>
          <div class="ai-block"><span class="k">Correlated alerts</span><span class="v">${a.correlated}</span></div>
          <div class="ai-block"><span class="k">Affected devices</span><span class="v">${a.devices}</span></div>
        </div>

        <div class="ai-block">
          <span class="k">Recommended actions</span>
          <ol class="ai-evidence" style="margin-top:6px;">${actionsHtml}</ol>
        </div>

        <div class="ai-block">
          <span class="k">Evidence (runbook citations)</span>
          <ul class="ai-evidence">${evidenceHtml}</ul>
        </div>

        ${escHtml}

        <div class="ai-source">
          <span class="k" style="font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--text-faint)">Grounding</span>
          <span class="srcpill">${evidenceList.length ? evidenceList[0].runbook || evidenceList[0].runbook_id || "local" : "no runbook"}</span>
          <span class="srcpill" style="margin-left:6px; background:var(--surface-3);">${isAI ? "Gemini grounded" : "Deterministic fallback"}</span>
        </div>`;
    } catch (e) {
      el.innerHTML = `<p class="ai-action">Failed to load analysis: ${e.message}</p>`;
    }
  }

  /* ======================================================================
     INCIDENT TIMELINE
     ====================================================================== */
  async function renderTimeline(incidentId) {
    const events = await D.getTimeline(incidentId);
    const inc = incidents.find((i) => i.id === incidentId);
    $("#tlSub").textContent = inc ? `${inc.id} · ${inc.title}` : incidentId;
    const ol = $("#timeline");
    ol.innerHTML = events
      .map((e) => {
        const [c] = SEV_COLOR[e.kind] || SEV_COLOR.info;
        return `<li style="--c:${c}"><span class="t">${e.time}</span><span class="d">${e.text}</span></li>`;
      })
      .join("");
  }

  /* ======================================================================
     ASK NETSENTRY
     ====================================================================== */
  const Ask = (function () {
    const panel = () => $("#askPanel");
    const log = () => $("#askLog");

    function bubble(cls, html) {
      const div = document.createElement("div");
      div.className = `msg msg--${cls}`;
      div.innerHTML = html;
      log().appendChild(div);
      log().scrollTop = log().scrollHeight;
      return div;
    }

    async function send(question) {
      bubble("user", question);
      const thinking = bubble("ai", '<span class="typing"><i></i><i></i><i></i></span>');
      try {
        const res = await D.ask(question);
        const tag = res.mock ? "NetSentry · fallback" : "NetSentry · live";
        const refs = res.refs && res.refs.length ? `<span class="msg__refs">${res.refs.map((r) => `<span>${r}</span>`).join("")}</span>` : "";
        // Slight delay for perceived thinking
        setTimeout(() => {
          thinking.innerHTML = `<span class="msg__tag">${tag}</span>${res.answer}${refs}`;
          log().scrollTop = log().scrollHeight;
        }, 420);
      } catch (e) {
        thinking.innerHTML = `<span class="msg__tag">NetSentry · error</span>Failed to answer: ${e.message}`;
      }
    }

    function open(prefill) {
      panel().hidden = false;
      $("#askFab").setAttribute("aria-expanded", "true");
      if (prefill) send(prefill);
      else $("#askInput").focus();
    }

    function close() {
      panel().hidden = true;
      $("#askFab").setAttribute("aria-expanded", "false");
      $("#askFab").focus();
    }

    async function init() {
      const suggestions = await D.getAskSuggestions();
      $("#askSuggest").innerHTML = suggestions
        .map((s) => `<button class="suggestbtn" type="button">${s}</button>`).join("");
      $("#askSuggest").addEventListener("click", (e) => {
        const b = e.target.closest(".suggestbtn");
        if (b) send(b.textContent);
      });

      bubble("ai",
        '<span class="msg__tag">NetSentry</span>Triage console ready. Ask about an incident, a grouped alert set, or what to check first. Responses are grounded in live incident and runbook data.');

      $("#askFab").addEventListener("click", () => open());
      $("#askClose").addEventListener("click", close);
      $("#navAsk").addEventListener("click", (e) => { e.preventDefault(); open(); });
      $("#askForm").addEventListener("submit", (e) => {
        e.preventDefault();
        const input = $("#askInput");
        const q = input.value.trim();
        if (!q) return;
        input.value = "";
        send(q);
      });
      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && !panel().hidden) close();
      });
    }

    return { init, open };
  })();

  /* ======================================================================
     SCENARIO SELECTOR
     ====================================================================== */
  function initScenarioSelector() {
    const select = $("#scenarioSelect");
    const btn = $("#scenarioRun");
    const status = $("#scenarioStatus");
    if (!select || !btn) return;

    const run = async () => {
      const scenario = select.value;
      btn.disabled = true;
      btn.textContent = "Loading...";
      status.textContent = "";
      try {
        await D.processScenario(scenario);
        status.textContent = "Loaded " + scenario;
        status.style.color = "var(--ok)";
        // Refresh all panels
        await Promise.all([renderHero(), renderKpis()]);
        await refreshIncidents();
        await Promise.all([Stream.refresh(), Topology.refresh()]);
        // Update subtitle
        $("#incSub").textContent = `Scenario: ${scenario} · ranked by deterministic priority score · live backend`;
      } catch (e) {
        status.textContent = "Failed: " + e.message;
        status.style.color = "var(--crit)";
      } finally {
        btn.disabled = false;
        btn.textContent = "Load";
        setTimeout(() => (status.textContent = ""), 4000);
      }
    };

    btn.addEventListener("click", run);
    select.addEventListener("keydown", (e) => {
      if (e.key === "Enter") run();
    });
  }

  /* ======================================================================
     NAVIGATION + SHELL
     ====================================================================== */
  function initNav() {
    $$(".navlink").forEach((link) =>
      link.addEventListener("click", (e) => {
        e.preventDefault();
        if (link.id === "navAsk") return;
        $$(".navlink").forEach((l) => { l.classList.remove("is-active"); l.removeAttribute("aria-current"); });
        link.classList.add("is-active");
        link.setAttribute("aria-current", "page");
        if (window.innerWidth <= 1100) $("#sidebar").classList.remove("is-open");
      })
    );

    const toggle = $("#navToggle");
    if (toggle) {
      toggle.addEventListener("click", () => {
        const open = $("#sidebar").classList.toggle("is-open");
        toggle.setAttribute("aria-expanded", String(open));
      });
    }
  }

  /* Backend health probe */
  async function probeHealth() {
    const foot = $("#footHealth");
    const dot = $("#apiHealthDot");
    try {
      const h = await D.getHealth();
      foot.textContent = `api: ${h.status} · ${h.project} ${h.version || ""} · ${h.scenario || ""}`;
      foot.style.color = "var(--ok)";
      dot.className = "navlink__count navlink__count--ok";
    } catch (err) {
      foot.textContent = "api: unreachable";
      foot.style.color = "var(--crit)";
      dot.className = "navlink__count navlink__count--crit";
      dot.textContent = "!";
    }
  }

  function initFreshness() {
    let mins = 0;
    setInterval(() => {
      mins += 1;
      $("#lastUpdated").textContent = mins === 1 ? "1 min ago" : `${mins} min ago`;
    }, 60000);
  }

  /* ======================================================================
     BOOT
     ====================================================================== */
  async function boot() {
    initClock();
    initNav();
    initFreshness();
    initScenarioSelector();
    await renderHero();
    await renderKpis();
    await renderIncidents();
    if (selectedIncident) await selectIncident(selectedIncident);
    await Promise.all([Stream.init(), Topology.init(), Ask.init()]);
    probeHealth();
  }

  document.addEventListener("DOMContentLoaded", () => {
    boot().catch((err) => console.error("[NetSentry] boot failed:", err));
  });
})();

/*
 * NetSentry AI — dashboard UI controller.
 *
 * Pure presentation. No correlation, scoring, dedup or retrieval logic lives
 * here — all of that belongs to the backend engine. Every value rendered comes
 * from window.NetSentryData (see data.js), which is the single seam to swap
 * mock data for FastAPI responses.
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
    const [status, health] = await Promise.all([D.getNetworkStatus(), D.getNetworkHealth()]);

    $("#netStatusText").textContent = status.label;
    $("#lastUpdated").textContent = status.lastUpdated;
    const hero = $(".hero");
    hero.classList.toggle("is-degraded", status.state === "degraded");
    hero.classList.toggle("is-outage", status.state === "outage");

    $("#heroFacts").innerHTML = status.facts
      .map((f) => `<li><span class="k">${f.label}</span><span class="v">${f.value}</span></li>`)
      .join("");

    // Segmented health bar: 20 segments, filled proportionally.
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
  }

  /* ======================================================================
     KPI CARDS
     ====================================================================== */
  async function renderKpis() {
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
  }

  /* ======================================================================
     INCIDENTS
     ====================================================================== */
  let incidents = [];
  let selectedIncident = null;
  let activeFilter = "all";

  function incidentMarkup(inc) {
    const dash = 2 * Math.PI * 14;
    const offset = dash * (1 - inc.confidence / 100);
    return `
      <button class="incident__head" aria-expanded="false" aria-controls="body-${inc.id}">
        <span class="sevbadge">${svg(inc.severity === "critical" ? "critical" : "alert")}${SEV_LABEL[inc.severity]}</span>
        <span>
          <span class="incident__id">${inc.id} · ${inc.site}</span>
          <span class="incident__title">${inc.title}</span>
          <span class="incident__facts">
            <span>${svg("devices")}${inc.devices} devices affected</span>
            <span>${svg("clock")}Started ${inc.started}</span>
            ${inc.aiAvailable ? '<span class="aiflag"><i class="ai-spark"></i>AI recommendation available</span>' : ""}
          </span>
        </span>
        <span class="incident__right">
          <span class="conf">
            <span class="conf__label">Root cause confidence</span>
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
              <div><span class="k">Owner</span><span class="v">${inc.owner}</span></div>
              <div><span class="k">Nodes</span><span class="v mono">${inc.nodes.join(", ")}</span></div>
            </div>
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
  }

  async function selectIncident(id) {
    selectedIncident = id;
    $$(".incident").forEach((el) => el.classList.toggle("is-selected", el.dataset.id === id));
    await Promise.all([renderAi(id), renderTimeline(id)]);
  }

  async function renderIncidents() {
    incidents = await D.getIncidents();
    selectedIncident = incidents[0] ? incidents[0].id : null;
    paintIncidents();

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

  /* ======================================================================
     LIVE ALERT STREAM
     Replays a finite seeded buffer on a slow timer — deliberately cheap.
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
        <span class="alert__sev"><i></i>${SEV_SHORT[a.severity]}</span>`;
      li.setAttribute("aria-label", `${a.time} ${a.node} ${a.type.replace(/_/g, " ")} severity ${a.severity}`);
      return li;
    }

    function push(alert) {
      const list = $("#alertStream");
      list.prepend(row(alert, true));
      while (list.children.length > MAX_ROWS) list.lastElementChild.remove();
      $("#streamCount").textContent = list.children.length;
    }

    function tick() {
      if (!live) return;
      const a = buffer[cursor % buffer.length];
      cursor += 1;
      push({ ...a, time: nowStamp() });
    }

    async function init() {
      buffer = await D.getAlerts();
      const list = $("#alertStream");
      // Seed with the newest 12 events, newest first, without animation.
      buffer.slice(-12).forEach((a) => list.prepend(row(a, false)));
      $("#streamCount").textContent = list.children.length;
      cursor = buffer.length;
      timer = setInterval(tick, INTERVAL);

      // Pause the stream when the tab is hidden — no background churn.
      document.addEventListener("visibilitychange", () => {
        if (document.hidden) { clearInterval(timer); timer = null; }
        else if (live && !timer) { timer = setInterval(tick, INTERVAL); }
      });

      const toggle = $("#streamToggle");
      toggle.addEventListener("click", () => {
        live = !live;
        toggle.setAttribute("aria-pressed", String(live));
        toggle.lastChild.textContent = live ? " Live" : " Paused";
      });

      list.addEventListener("click", (e) => {
        const el = e.target.closest(".alert");
        if (!el) return;
        $$(".alert", list).forEach((a) => a.classList.remove("is-selected"));
        el.classList.add("is-selected");
        Topology.highlight(el.dataset.node);
      });
    }

    return { init };
  })();

  /* ======================================================================
     TOPOLOGY  (local SVG renderer — no external libraries or services)
     Reads the same {nodes, links} shape as data/topology.json.
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
      const byId = Object.fromEntries(data.nodes.map((n) => [n.id, n]));
      const parts = [];

      // Links first so nodes paint on top.
      data.links.forEach((l) => {
        const a = byId[l.source], b = byId[l.target];
        if (!a || !b) return;
        const x1 = px(a), y1 = py(a) + BOX_H / 2;
        const x2 = px(b), y2 = py(b) - BOX_H / 2;
        const my = (y1 + y2) / 2;
        const d = `M ${x1} ${y1} V ${my} H ${x2} V ${y2}`;
        parts.push(`<path class="link link--${l.status}" d="${d}" data-link="${l.source}-${l.target}" fill="none"/>`);
        if (l.status === "ok") {
          parts.push(`<circle class="pkt" r="2.6">
            <animateMotion dur="3s" repeatCount="indefinite" path="${d}"/></circle>`);
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
      const show = (g, evt) => {
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
        g.addEventListener("mouseenter", (e) => show(g, e));
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
    }

    // setData() lets a future /api/topology response replace the mock in place.
    return { init, highlight, setData: (d) => { data = d; render(); } };
  })();

  /* ======================================================================
     AI INSIGHT PANEL  (mock — no Gemini call)
     ====================================================================== */
  async function renderAi(incidentId) {
    const a = await D.getAnalysis(incidentId);
    const el = $("#aiPanel");
    if (!a) {
      el.innerHTML = '<p class="ai-action">No AI analysis available for this incident yet.</p>';
      return;
    }
    el.innerHTML = `
      <p class="ai-kicker">AI Incident Analysis · ${incidentId}</p>
      <p class="ai-headline">${a.headline}</p>

      <div class="ai-block">
        <span class="k">Likely root cause</span>
        <span class="v">${a.rootCause}</span>
        <div class="confbar"><i style="width:${a.confidence}%"></i></div>
      </div>

      <div class="ai-metrics">
        <div class="ai-block"><span class="k">Confidence</span><span class="v ${a.confidence >= 80 ? "conf-hi" : ""}">${a.confidence}%</span></div>
        <div class="ai-block"><span class="k">Correlated alerts</span><span class="v">${a.correlated}</span></div>
        <div class="ai-block"><span class="k">Affected devices</span><span class="v">${a.devices}</span></div>
      </div>

      <div class="ai-block">
        <span class="k">Recommended action</span>
        <p class="ai-action">${a.action}</p>
        <ul class="ai-evidence">${a.evidence.map((e) => `<li>${e}</li>`).join("")}</ul>
      </div>

      <div class="ai-source">
        <span class="k" style="font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--text-faint)">Source</span>
        <span class="srcpill">${a.source}</span>
      </div>`;
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
     ASK NETSENTRY  (mock NLP console — future Gemini/FAISS handler)
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
      const res = await D.ask(question);
      setTimeout(() => {
        thinking.innerHTML =
          `<span class="msg__tag">NetSentry · mock response</span>${res.answer}` +
          (res.refs.length ? `<span class="msg__refs">${res.refs.map((r) => `<span>${r}</span>`).join("")}</span>` : "");
        log().scrollTop = log().scrollHeight;
      }, 520);
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
        '<span class="msg__tag">NetSentry</span>Triage console ready. Ask about an incident, a grouped alert set, or what to check first. Responses are mock data until the intelligence engine is connected.');

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
     NAVIGATION + SHELL
     ====================================================================== */
  function initNav() {
    $$(".navlink").forEach((link) =>
      link.addEventListener("click", (e) => {
        e.preventDefault();
        if (link.id === "navAsk") return; // handled by Ask
        $$(".navlink").forEach((l) => { l.classList.remove("is-active"); l.removeAttribute("aria-current"); });
        link.classList.add("is-active");
        link.setAttribute("aria-current", "page");
        if (window.innerWidth <= 1100) $("#sidebar").classList.remove("is-open");
      })
    );

    const toggle = $("#navToggle");
    toggle.addEventListener("click", () => {
      const open = $("#sidebar").classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", String(open));
    });
  }

  /* Backend health probe — the one real API call on this page. */
  async function probeHealth() {
    const foot = $("#footHealth");
    const dot = $("#apiHealthDot");
    try {
      const h = await D.getHealth();
      foot.textContent = `api: ${h.status} · ${h.project}`;
      foot.style.color = "var(--ok)";
      dot.className = "navlink__count navlink__count--ok";
    } catch (err) {
      foot.textContent = "api: unreachable";
      foot.style.color = "var(--crit)";
      dot.className = "navlink__count navlink__count--crit";
      dot.textContent = "!";
    }
  }

  /* Freshness label on the hero — cheap, once a minute. */
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

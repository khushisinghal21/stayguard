"use strict";
// Every string from the API is treated as untrusted (messages are written by attackers):
// the UI only ever inserts text with textContent, never innerHTML.

const $ = (s) => document.querySelector(s);
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v; // CSSOM, allowed under a CSP without 'unsafe-inline'

    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
async function api(path, body) {
  const r = await fetch(path, body === undefined ? {} : {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`${path} returned ${r.status}`);
  return r.json();
}

const STAMP = { deliver: "DELIVERED", warn: "WARNED", hold: "HELD", block: "BLOCKED" };
const TERMS = { pay_at_property: "pays at hotel", prepaid: "prepaid", deposit: "deposit", unknown: "terms unknown" };
const SESSION_TEXT = {
  SESSION_TOKEN_REPLAYED_FROM_NEW_NETWORK: "Session cookie reused from a new network (stolen cookie)",
  IMPOSSIBLE_TRAVEL: "Impossible travel since the last login",
  PAYOUT_CHANGE_FROM_NEW_DEVICE: "Tried to change payout bank details from a new device",
  NEW_DEVICE_BULK_RESERVATION_READ: "New device reading reservations in bulk",
  NEW_DEVICE_NEW_COUNTRY: "New device in a new country",
};
const stamp = (d, land) => h("span", { class: `stamp ${d}${land ? " land" : ""}` }, STAMP[d] || d);

function highlight(text, quotes) {
  const frag = document.createDocumentFragment();
  const lower = text.toLowerCase();
  const ranges = [];
  for (const q of quotes || []) {
    const ql = String(q).toLowerCase().trim();
    if (ql.length < 2) continue;
    const isL = (c) => !!c && /\p{L}/u.test(c);
    let i = lower.indexOf(ql);
    while (i !== -1) {
      // whole words only: "pay" should not light up inside "payment"
      if (!(isL(lower[i - 1]) && isL(ql[0])) && !(isL(lower[i + ql.length]) && isL(ql[ql.length - 1]))) ranges.push([i, i + ql.length]);
      i = lower.indexOf(ql, i + ql.length);
    }
  }
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of ranges) {
    if (merged.length && r[0] <= merged[merged.length - 1][1]) merged[merged.length - 1][1] = Math.max(merged[merged.length - 1][1], r[1]);
    else merged.push([...r]);
  }
  let pos = 0;
  for (const [a, b] of merged) {
    if (a > pos) frag.append(text.slice(pos, a));
    frag.append(h("mark", {}, text.slice(a, b)));
    pos = b;
  }
  frag.append(text.slice(pos));
  return frag;
}

// ------------------------------------------------------------------ status bar
async function refreshStatus() {
  try {
    const s = await api("/healthz");
    const judge = s.judge_provider === "offline-deterministic" ? "AI judges: offline mode" : `AI judges: ${s.judge_provider}`;
    const down = s.breaker !== "closed";
    $("#status").replaceChildren(
      h("span", {}, judge),
      h("span", { class: down ? "down" : "" }, down ? "Judges unavailable, safe fallback on" : "Judges available"),
      h("span", {}, `${Number(s.blocklist_size).toLocaleString()} live phishing domains`));
  } catch { $("#status").replaceChildren(h("span", { class: "down" }, "API not reachable")); }
}

// ------------------------------------------------------------------ tabs
const loaders = {};
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
  document.querySelectorAll(".panel").forEach((p) => { p.hidden = p.id !== `tab-${b.dataset.tab}`; });
  loaders[b.dataset.tab]?.();
}));

// ------------------------------------------------------------------ message card
function messageCard(m, opts = {}) {
  const res = m.reservation;
  const quotes = (m.evidence || []).map((e) => e.quote);
  return h("div", { class: "msg" },
    stamp(m.decision, opts.land),
    res ? h("div", { class: "who" }, `To ${res.guest_name}`, h("span", { class: "terms" }, TERMS[res.payment_terms] || res.payment_terms),
      h("span", { class: "terms" }, `arrives ${res.arrival_date}`))
      : h("div", { class: "who" }, opts.direction === "guest_to_hotel" ? "Guest to hotel" : "Hotel to guest",
        h("span", { class: "terms" }, TERMS[m.payment_terms] || m.payment_terms || "")),
    h("p", { class: "body" }, highlight(opts.text ?? m.masked_text ?? "", quotes)),
    h("ul", { class: "why" }, (m.explanations || []).map((t) => h("li", {}, t))),
    m.guest_banner ? h("div", { class: "banner" }, "Shown to the guest: ", m.guest_banner) : null,
    h("div", { class: "meta" }, `Decided by ${m.path === "rule" ? "a rule" : m.path === "model" ? "the language model" :
      m.path === "judges" ? "the AI judges" : m.path === "degraded" ? "the fallback policy" : m.path} in ${m.latency_ms ?? "–"} ms`));
}

// ------------------------------------------------------------------ live attack
let attackState = null;
$("#runAttack").addEventListener("click", async () => {
  const btn = $("#runAttack");
  btn.disabled = true; btn.textContent = "Running…";
  try {
    const sim = await api("/v1/demo/simulate-attack", {});
    attackState = sim;
    const list = $("#timeline");
    list.replaceChildren();
    $("#account").replaceChildren(h("h2", {}, "Attacker session"), h("p", { class: "muted" }, "Waiting for the login…"));
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    for (const e of sim.timeline) {
      const cls = `ev ${e.actor}`;
      let card;
      if (e.message) {
        const raw = e.message;
        card = messageCard(raw, { land: true, text: raw.masked_text });
      } else {
        const s = e.session;
        card = h("div", { class: "login" },
          h("div", { class: "who" }, e.event),
          h("p", { class: "body" }, `Login risk ${s.risk.toFixed(2)} (${s.level})`),
          s.reasons.length ? h("ul", { class: "why" }, s.reasons.filter((r) => SESSION_TEXT[r]).map((r) => h("li", {}, SESSION_TEXT[r]))) : null);
        if (e.actor === "attacker") renderAccount(s);
      }
      list.append(h("li", { class: cls }, h("time", {}, e.t), card));
      if (!reduce) await new Promise((r) => setTimeout(r, 520));
    }
  } catch (err) {
    $("#timeline").replaceChildren(h("li", { class: "empty" }, `The demo could not run: ${err.message}. Is the API running?`));
  } finally {
    btn.disabled = false; btn.textContent = "Run the attack again";
  }
});

function renderAccount(s) {
  const reasons = s.reasons.filter((r) => SESSION_TEXT[r]);
  $("#account").replaceChildren(
    h("h2", {}, "Attacker session"),
    h("div", { class: "risk" }, h("b", {}, s.risk.toFixed(2)), h("span", {}, `takeover risk, ${s.level}`)),
    h("div", { class: "meter" }, h("i", { style: `width:${Math.round(s.risk * 100)}%` })),
    h("ul", { class: "signals" }, reasons.map((r) => h("li", {}, SESSION_TEXT[r]))),
    s.mitre?.length ? h("p", { class: "muted" }, `Matches ${s.mitre.length} MITRE ATT&CK techniques.`) : null,
    h("button", { class: "primary", id: "contain", onclick: contain }, "Log everyone out and warn guests"));
}

async function contain() {
  const btn = $("#contain");
  btn.disabled = true; btn.textContent = "Containing…";
  try {
    const c = await api(`/v1/properties/${attackState.property_id}/contain`, { session_id: attackState.attacker_session });
    const f = c.file;
    const label = {
      revoke_all_sessions: (a) => `${a.count} sessions logged out`,
      force_password_reset_and_passkey_enrolment: () => "Password reset and passkey required",
      freeze_payout_bank_changes: (a) => `Payout bank changes frozen for ${a.hours} hours`,
      rotate_reservation_pins: (a) => `${a.count} reservation PINs rotated`,
      warn_guests_in_app: (a) => `${a.count} guests warned in the app`,
      quarantine_messages_from_session: (a) => `${a.count} messages quarantined`,
    };
    btn.replaceWith(
      h("h3", {}, `Case ${f.case_id} contained in ${f.duration_ms} ms`),
      h("ul", { class: "actions" }, f.actions.map((a) => h("li", {}, (label[a.action] || ((x) => x.action))(a)))),
      h("h3", {}, "MITRE ATT&CK"),
      h("ul", { class: "mitre" }, f.mitre_attack.map((m) => h("li", {}, m))));
  } catch (err) { btn.disabled = false; btn.textContent = `Failed: ${err.message}. Try again`; }
}

// ------------------------------------------------------------------ lab
let samples = [];
loaders.lab = async () => {
  if (samples.length) return;
  samples = await api("/v1/samples");
  const sel = $("#sample");
  samples.forEach((s, i) => sel.append(h("option", { value: String(i) },
    `${s.label ? "Scam" : "Normal"}: ${s.text.slice(0, 60)}${s.text.length > 60 ? "…" : ""}`)));
};
$("#sample").addEventListener("change", (e) => {
  const s = samples[Number(e.target.value)];
  if (!s) return;
  $("#labText").value = s.text;
  $("#terms").value = s.terms || "pay_at_property";
  $("#direction").value = s.direction || "hotel_to_guest";
});
$("#outage").addEventListener("change", async (e) => { await api("/v1/admin/llm-outage", { on: e.target.checked }); refreshStatus(); });

const SESSIONS = {
  risky: { hour: 14, is_new_device: true, km_from_usual: 900, speed_kmh: 120, new_asn: true, reservations_viewed: 20, messages_sent: 4 },
  critical: { hour: 3, is_new_device: true, km_from_usual: 5400, speed_kmh: 9800, new_asn: true, hosting_asn: true,
              reservations_viewed: 240, messages_sent: 40, token_replay: true },
};
$("#labForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#labResult");
  out.replaceChildren(h("p", { class: "muted" }, "Checking…"));
  try {
    let session_id = null;
    const sv = $("#sess").value;
    if (SESSIONS[sv]) session_id = (await api("/v1/sessions/score", { property_id: "H2", user: "lab", ...SESSIONS[sv] })).session_id;
    const text = $("#labText").value;
    const m = await api("/v1/messages/check", { text, payment_terms: $("#terms").value, direction: $("#direction").value, session_id });
    out.replaceChildren(...[messageCard(m, { land: true, text, direction: $("#direction").value }), traceView(m), judgesView(m), linksView(m)].filter(Boolean));
  } catch (err) { out.replaceChildren(h("p", {}, `Check failed: ${err.message}`)); }
});

function traceView(m) {
  const decisive = { rule: "rules", model: "model", judges: "judges", degraded: "judges" }[m.path];
  const names = { guardrails: "Guardrails", links: "Links", rules: "Rules", model: "Language model", judges: "AI judges", session: "Login risk" };
  const describe = (t) => {
    switch (t.stage) {
      case "guardrails": return t.pii_masked.length ? `Masked ${t.pii_masked.join(", ")} before any AI sees it` : (t.injection ? "Prompt injection found" : "No personal data to mask");
      case "links": return t.checked ? `${t.checked} link(s), worst score ${t.worst}` : "No links";
      case "rules": return t.decided ? t.reasons.join(", ") : (m.reasons || []).includes("NO_PAYMENT_ASK")
        ? "Nothing a scam needs: no payment ask, no risky link" : "No rule settled it";
      case "model": return `Scam probability ${t.p}`;
      case "judges": return t.provider === "unavailable" ? `Unavailable (${t.breaker}), fallback used` : `${t.provider}: scam probability ${t.p_scam}`;
      case "session": return `Risk ${t.risk} (${t.level})`;
      default: return "";
    }
  };
  const stages = m.trace || [];
  if (!stages.some((t) => t.stage === "judges")) stages.splice(4, 0, { stage: "judges", ms: 0, skipped: true });
  return h("div", {}, h("h3", { style: "margin-top:1.4rem" }, "How it was decided"),
    h("ol", { class: "pipe" }, stages.map((t) => h("li", { class: t.stage === decisive ? "decisive" : t.skipped ? "skipped" : "" },
      h("b", {}, names[t.stage] || t.stage), h("span", {}, t.skipped ? "Not needed, so no AI cost" : describe(t)),
      h("span", { class: "ms" }, t.skipped ? "" : `${t.ms} ms`)))));
}
function judgesView(m) {
  if (!m.judges) return null;
  const j = (o, title) => h("div", { class: "judge" }, h("b", {}, `${title}: ${o.verdict} (${o.confidence})`),
    h("p", {}, o.rationale || ""), o.evidence.length ? h("ul", { class: "why" }, o.evidence.map((q) => h("li", {}, `“${q}”`))) : null,
    o.rejected_evidence.length ? h("p", { class: "muted" }, `${o.rejected_evidence.length} invented quote(s) thrown out`) : null);
  return h("div", { class: "judges" }, j(m.judges.prosecutor, "Prosecutor"), j(m.judges.defender, "Defender"));
}
function linksView(m) {
  if (!m.links?.length) return null;
  return h("div", {}, h("h3", { style: "margin-top:1.2rem" }, "Links"),
    h("ul", { class: "links" }, m.links.map((l) => h("li", {}, h("b", {}, l.host), ` is ${l.verdict} (${l.score}): ${l.reasons.join(", ")}`))));
}

// ------------------------------------------------------------------ guest view
$("#gFill").addEventListener("click", async () => {
  const offset = Math.floor(Math.random() * 200);
  const [r] = await api(`/v1/properties/H2/reservations?limit=1&terms=pay_at_property&offset=${offset}`);
  const p = await api(`/v1/reservations/${r.id}/demo-pin`, {});
  $("#gRes").value = r.id; $("#gPin").value = p.pin;
});
$("#guestForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#guestResult");
  try {
    const r = await api("/v1/guest/verify", { reservation_id: $("#gRes").value.trim(), pin: $("#gPin").value.trim(), text: $("#gText").value });
    if (!r.ok) { out.replaceChildren(h("div", { class: "answer err" }, h("h3", {}, r.message))); return; }
    out.replaceChildren(h("div", { class: `answer ${r.verdict}` },
      h("h3", {}, r.headline),
      h("p", {}, `Your booking: ${r.what_you_owe}.`),
      r.reasons.length ? h("ul", {}, r.reasons.map((t) => h("li", {}, t))) : null,
      h("p", {}, r.sent_through_platform ? "This message did come through the platform." : "We have no record of your hotel sending this through the platform."),
      h("p", {}, r.advice)));
  } catch (err) { out.replaceChildren(h("div", { class: "answer err" }, h("h3", {}, `Check failed: ${err.message}`))); }
});

// ------------------------------------------------------------------ results
const pct = (x, d = 0) => (x === null || x === undefined ? "–" : `${(x * 100).toFixed(d)}%`);
loaders.results = async () => {
  const m = await api("/v1/metrics");
  const ev = m.evaluation;
  const root = $("#results");
  if (!ev) { root.replaceChildren(h("p", {}, "No evaluation yet. Run python -m eval.evaluate, then reload.")); return; }
  // Every field read below is listed in tests/test_eval_harness.py, which checks it exists in a real report.
  const A = ev.A_messages, B = ev.B_real_sms, C = ev.C_links, D = ev.D_sessions, E = ev.E_cost_latency, F = ev.F_robustness;
  const FL = ev.heldout_first_look;
  // Review round 4 (C2): this tab used to repeat claims the reviews had retracted (v1 "never tuned on", the tuned v1
  // number as the lead, "87.6% paid at the hotel", no classifier-only baseline). It now leads with the blind numbers.
  const V2 = ev.heldout_v2_first_look ? ev.heldout_v2_first_look.A_messages_heldout_v2 : null;
  const SYS = {
    baseline_blocklist_only: "Phishing blocklist only", baseline_generic_spam_filter: "Generic spam filter",
    baseline_stayguard_classifier_only: "StayGuard's classifier alone",
    stayguard_rules_only: "StayGuard, rules only", stayguard_full: "StayGuard",
    stayguard_zero_day_links_blocklist_off: "StayGuard, blocklist switched off", stayguard_degraded_llm_down: "StayGuard, AI judges down",
  };
  const bar = (v, bad) => h("div", { class: "bar2" }, h("i", { class: bad ? "bad" : "", style: `width:${Math.max(2, (v || 0) * 160)}px` }), pct(v, 1));
  const MUT = { no_urgency: "Deadline removed", neutral_new_domain: "Fresh brand-free domain", leetspeak: "Leetspeak (c@rd)",
                zero_width: "Hidden characters (flagged as obfuscation)", spaced_letters: "Spaced letters (p a y)", combined: "All of the above" };
  const FLF = FL ? FL.A_messages_heldout.systems.stayguard_full : null;
  const lead = V2
    ? h("div", { class: "lead" },
        h("div", {}, h("b", {}, pct(V2.systems.stayguard_full.catch_rate, 1)), h("span", {}, `of ${V2.n_scam} held-out v2 scams stopped (blind, run once)`)),
        h("div", {}, h("b", {}, pct(V2.systems.stayguard_full.false_alarm_rate, 1)), h("span", {}, `of ${V2.n_legit} held-out v2 normal messages wrongly held`)),
        h("div", {}, h("b", {}, pct(V2.systems.baseline_stayguard_classifier_only.catch_rate, 1)), h("span", {}, "caught by StayGuard's classifier alone, same messages")),
        h("div", {}, h("b", {}, `$${E.hotel_heldout_est_cost_per_1000_usd}`), h("span", {}, "estimated AI cost per 1,000 hotel messages")))
    : h("p", { class: "muted" }, "Held-out v2 (the blind set) has not had its one run yet, so there is no blind headline number.");
  root.replaceChildren(
    h("h1", {}, "How well it works: read the blind numbers first"),
    h("p", { class: "muted" }, `Held-out v2: ${V2 ? V2.n : 148} messages written by a separate agent instructed not to read the code, run once and frozen. ` +
      `Held-out v1: ${A.heldout.n} messages, blind only for its first run; later fixes targeted its misses, so its current numbers are tuned. ` +
      `Dev: ${A.dev.n} messages written alongside the rules.`),
    lead,
    FLF ? h("p", { class: "muted" }, `Held-out v1 first blind run (${FL.generated}): ${pct(FLF.catch_rate, 1)} stopped, ${pct(FLF.false_alarm_rate, 1)} wrongly held. ` +
      `Now ${pct(A.heldout.systems.stayguard_full.catch_rate, 1)}, but that is after fixes made from its misses (DECISIONS #28).`) : null,
    h("div", { class: "rsec" }, h("h2", {}, "Against the alternatives (held-out v1, not blind, and dev)"),
      h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "System"), h("th", {}, "v1 stopped"),
        h("th", {}, "v1 wrongly held"), h("th", {}, "Dev stopped"), h("th", {}, "Dev wrongly held"))),
        h("tbody", {}, Object.keys(SYS).map((k) => h("tr", { class: k === "stayguard_full" ? "ours" : "" },
          h("td", {}, SYS[k]), h("td", {}, bar(A.heldout.systems[k].catch_rate)), h("td", {}, bar(A.heldout.systems[k].false_alarm_rate, true)),
          h("td", {}, pct(A.dev.systems[k].catch_rate)), h("td", {}, pct(A.dev.systems[k].false_alarm_rate)))))))),
    h("div", { class: "rsec" }, h("h2", {}, "When attackers rewrite the scam (held-out v1, not blind)"),
      h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Rewrite"), h("th", {}, "v1 still stopped"), h("th", {}, "Dev"))),
        h("tbody", {}, Object.keys(MUT).map((k) =>
          h("tr", {}, h("td", {}, MUT[k]), h("td", {}, bar(F.heldout[k].catch_rate)), h("td", {}, pct(F.dev[k].catch_rate)))))))),
    h("div", { class: "rsec" }, h("h2", {}, "Links nobody has reported yet (blocklist off)"),
      h("p", {}, `${pct(C.heldout.c1_detection_rate, 1)} of ${C.heldout.c1_n} Booking look-alike phishing hosts flagged (selected for containing "booking", so this is look-alike coverage); ` +
        `${pct(C.heldout.c2_detection_rate, 1)} of ${C.heldout.c2_n.toLocaleString()} random hosts from the whole feed; ` +
        `${pct(C.heldout.c3_false_positive_rate, 3)} of ${C.heldout.c3_n.toLocaleString()} legit domains not examined while tuning, but ` +
        `${pct(C.heldout.c3_brand_token_false_positive_rate, 1)} of the ${C.heldout.c3_brand_token_n} that contain a travel-brand word.`)),
    h("div", { class: "rsec" }, h("h2", {}, "Ordinary chat"),
      h("p", {}, `${B.real_ham.n.toLocaleString()} real personal SMS sent through as if a hotel wrote them: ${pct(B.real_ham.held_or_blocked_rate, 2)} held, ` +
        `${pct(B.real_ham.warned_rate, 2)} warned. These are not hotel messages, and this split was used as a check while writing rules (two rules were narrowed because of it).`)),
    h("div", { class: "rsec" }, h("h2", {}, "Hijacked logins (synthetic)"),
      h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Attack"), h("th", {}, "Flagged risky"), h("th", {}, "Flagged critical"))),
        h("tbody", {}, Object.keys(D.recall_at_risky).map((k) => h("tr", {}, h("td", {}, k.replaceAll("_", " ")),
          h("td", {}, bar(D.recall_at_risky[k])), h("td", {}, bar(D.recall_at_critical[k]))))))),
      h("p", {}, `False alarms on normal logins: ${pct(D.fpr_at_risky, 2)}. The synthetic attacks are generated from the features the rules use, so detection is true by construction. Malware on the hotel's own PC looks like a normal login, which is why every message is checked on its own.`)),
    h("div", { class: "rsec" }, h("h2", {}, "Speed and cost"),
      h("p", {}, `Hotel messages reaching the AI judges: ${pct(E.hotel_heldout_judge_share, 1)} (held-out v1); on an SMS-heavy mix ${pct(E.judge_share, 1)}. ` +
        `In-process p50 ${E.p50_ms} ms, p95 ${E.p95_ms} ms with the offline judge. ${E.note} Bookings in the public dataset: ${m.dataset.reservations.toLocaleString()}, ` +
        `of which ${pct(m.dataset.share_pay_at_property, 1)} had "No Deposit" (two Portuguese hotels, 2015-17; not the same as "pay at the hotel").`)));
};

// ------------------------------------------------------------------ audit
loaders.audit = async () => {
  const rows = await api("/v1/audit?limit=60");
  const detail = (p) => {
    if (p.decision) return `${p.decision.toUpperCase()} ${p.reasons.join(", ")}`;
    if (p.level) return `${p.level} risk ${p.risk}`;
    if (p.summary) return p.summary;
    if (p.verdict) return `Guest check for ${p.reservation_id}: ${p.verdict.replaceAll("_", " ")}`;
    if ("on" in p) return p.on ? "AI judges switched off (simulated outage)" : "AI judges back on";
    return JSON.stringify(p).slice(0, 120);
  };
  $("#auditBody").replaceChildren(...rows.map((r) => h("tr", {},
    h("td", {}, r.seq), h("td", {}, new Date(r.ts * 1000).toLocaleTimeString()), h("td", {}, r.kind),
    h("td", {}, detail(r.payload)), h("td", {}, `${r.hash.slice(0, 16)}…`))));
};
$("#verifyChain").addEventListener("click", async () => {
  const v = await api("/v1/audit/verify");
  $("#chainResult").replaceChildren(v.ok ? h("p", { class: "chain-ok" }, `Chain intact: ${v.checked} entries verified.`)
    : h("p", { class: "chain-bad" }, `Chain broken at entry ${v.broken_at_seq}.`));
});

refreshStatus();

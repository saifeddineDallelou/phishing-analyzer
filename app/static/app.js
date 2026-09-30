"use strict";
// SECURITY RULE FOR THIS FILE: almost everything in a report was written by the attacker
// (subject, sender, file names, URLs, and the finding descriptions that quote them).
// It is only ever inserted with textContent / text nodes, NEVER innerHTML or similar.
// tests/test_ui.py fails if a dangerous HTML-injection API appears in this file.

const $ = (id) => document.getElementById(id);

/** Build an element. Children that are strings become text nodes: they can never become HTML. */
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** Show invisible direction characters (RTLO trick) instead of letting the browser apply them. */
function reveal(text) {
  return String(text ?? "").replace(/[‎‏‪-‮⁦-⁩]/g,
    (ch) => `[U+${ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}]`);
}

/** http://evil.com -> hxxp://evil[.]com : can't be clicked or auto-linked by accident. */
function defang(value) {
  return reveal(value).replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

function mitreLink(id) {
  if (!/^T\d{4}(\.\d{3})?$/.test(id || "")) return el("span", { class: "mono muted" }, id || "");
  const [main, sub] = id.split(".");
  const href = `https://attack.mitre.org/techniques/${main}/${sub ? sub + "/" : ""}`;
  return el("a", { class: "mono", href, target: "_blank", rel: "noopener noreferrer" }, id);
}

function showStatus(message, isError = false) {
  const status = $("status");
  status.textContent = message;
  status.className = isError ? "error" : "";
}

async function analyze(file) {
  if (!file) return;
  if (file.size > 25 * 1024 * 1024) return showStatus("File too large (max 25 MB).", true);
  showStatus(`Analyzing ${reveal(file.name)}…`);
  const body = new FormData();
  body.append("file", file);
  try {
    const response = await fetch(`/analyze?intel=${$("intel").checked}`, { method: "POST", body });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(typeof error.detail === "string" ? error.detail : `HTTP ${response.status}`);
    }
    renderReport(await response.json(), $("intel").checked);
    showStatus("");
  } catch (error) {
    showStatus(`Analysis failed: ${error.message}`, true);
  }
}

function section(title, ...content) {
  return el("div", { class: "section" }, el("h3", {}, title), ...content);
}

function renderReport(report, usedIntel) {
  const { email, findings, iocs } = report;
  const sorted = [...findings].sort((a, b) => b.score - a.score);
  const high = findings.filter((f) => f.severity === "high").length;
  const iocCount = Object.values(iocs).reduce((n, list) => n + list.length, 0);
  const techniques = [...new Set(findings.map((f) => f.mitre).filter(Boolean))].sort();

  const bar = el("div", { class: "bar" }, el("div", { class: `fill ${report.verdict}` }));
  bar.firstChild.style.width = `${Math.min(100, report.score)}%`;  // CSSOM: allowed by our CSP

  const reportEl = $("report");
  reportEl.replaceChildren(
    el("div", { class: "card" },
      el("div", { class: "head" },
        el("div", { class: "grow" },
          el("h2", {}, reveal(email.subject) || "(no subject)"),
          el("p", { class: "muted" }, `From ${reveal(email.from)} · to ${reveal(email.to)}`),
          email.date ? el("p", { class: "muted small" }, reveal(email.date)) : null),
        el("span", { class: `verdict ${report.verdict}` }, report.verdict)),

      el("div", { class: "metrics" },
        el("div", { class: "metric" }, el("span", { class: "label" }, "Risk score"),
          el("span", { class: `value ${report.verdict}` }, String(report.score), el("small", {}, " / 100")), bar),
        el("div", { class: "metric" }, el("span", { class: "label" }, "Findings"),
          el("span", { class: "value" }, String(findings.length), el("small", {}, ` ${high} high`))),
        el("div", { class: "metric" }, el("span", { class: "label" }, "Indicators"),
          el("span", { class: "value" }, String(iocCount)),
          el("span", { class: "small muted" }, usedIntel ? "threat intel on" : "rules only"))),

      section("Why this verdict",
        sorted.length === 0 ? el("p", { class: "muted" }, "No suspicious signals found.") :
        el("div", { class: "findings" }, sorted.map((f) =>
          el("div", { class: "finding" },
            el("span", { class: `pill ${f.severity}` }, f.severity),
            el("span", { class: "mono" }, f.rule_id),
            el("span", { class: "desc" }, reveal(f.description)),
            el("span", { class: "mono muted" }, `+${f.score}`),
            mitreLink(f.mitre))))),

      section("Indicators of compromise",
        iocCount === 0 ? el("p", { class: "muted" }, "None extracted.") :
        el("div", { class: "iocs" },
          Object.entries(iocs).filter(([, list]) => list.length).map(([kind, list]) =>
            el("div", { class: "ioc-group" }, el("span", { class: "label" }, kind),
              list.map((value) => el("code", { class: "ioc" }, defang(value)))))),
        iocCount ? copyButton(iocs) : null),

      email.attachments.length ? section("Attachments",
        email.attachments.map((a) => el("div", { class: "row" },
          el("span", {}, reveal(a.filename || "(unnamed)")),
          el("span", { class: "muted small" }, `${a.content_type} · ${a.size} bytes`),
          el("code", { class: "ioc" }, a.sha256)))) : null,

      email.links.length ? section("Links (not clickable)",
        email.links.map((l) => el("div", { class: "row" },
          el("span", { class: "muted small" }, l.text ? `shows "${reveal(l.text)}"` : "plain-text link"),
          el("code", { class: "ioc" }, defang(l.href))))) : null,

      techniques.length ? section("MITRE ATT&CK", el("div", { class: "chips" }, techniques.map(mitreLink))) : null,

      email.text_body ? section("Message text (preview)",
        el("pre", { class: "body" }, reveal(email.text_body.slice(0, 2000)))) : null,

      el("button", { type: "button", id: "again" }, "Analyze another email")));

  $("again").addEventListener("click", () => {
    reportEl.hidden = true;
    $("upload").hidden = false;
    $("file").value = "";
  });
  $("upload").hidden = true;
  reportEl.hidden = false;
  window.scrollTo(0, 0);
}

function copyButton(iocs) {
  const button = el("button", { type: "button" }, "Copy IOCs as JSON");
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(iocs, null, 2));
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
  });
  return button;
}

document.addEventListener("DOMContentLoaded", () => {
  const dropzone = $("dropzone");
  $("file").addEventListener("change", (event) => analyze(event.target.files[0]));
  dropzone.addEventListener("dragover", (event) => { event.preventDefault(); dropzone.classList.add("over"); });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("over"));
  dropzone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropzone.classList.remove("over");
    analyze(event.dataTransfer.files[0]);
  });
});

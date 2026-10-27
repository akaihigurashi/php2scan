"use strict";

// Everything that comes from the checked website (server header, technology names, URLs) is
// inserted with textContent only - never as HTML - so a site can't inject markup here.

(function () {
  const form = document.getElementById("check");
  const hostInput = document.getElementById("host");
  // "Details" from the landing page's Check all: /?host=www.example.ch fills in the address
  const preset = new URLSearchParams(location.search).get("host");
  if (preset) hostInput.value = preset.slice(0, 253);
  const consent = document.getElementById("consent");
  const button = document.getElementById("go");
  const result = document.getElementById("result");
  const SVG = "http://www.w3.org/2000/svg";

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "text") node.textContent = v;
      else node.setAttribute(k, v);
    }
    for (const c of children || []) if (c) node.append(c);
    return node;
  }

  function icon(level) {
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", "26");
    svg.setAttribute("height", "26");
    svg.setAttribute("aria-hidden", "true");
    const paths = {
      warn: ["M12 3 2 21h20L12 3Z", "M12 10v5M12 18v.01"],
      bad: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Z", "M12 7v6M12 16.5v.01"],
      good: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Z", "m7.5 12.5 3 3 6-6.5"],
      unknown: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Z", "M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6M12 17v.01"],
    }[level] || [];
    for (const d of paths) {
      const p = document.createElementNS(SVG, "path");
      p.setAttribute("d", d);
      p.setAttribute("fill", "none");
      p.setAttribute("stroke", "currentColor");
      p.setAttribute("stroke-width", "2");
      p.setAttribute("stroke-linecap", "round");
      p.setAttribute("stroke-linejoin", "round");
      svg.append(p);
    }
    return svg;
  }

  function showFormError(message) {
    clearFormError();
    const p = el("p", { class: "form-error", role: "alert", text: message });
    p.id = "form-error";
    form.append(p);
  }

  function clearFormError() {
    const old = document.getElementById("form-error");
    if (old) old.remove();
  }

  function joinList(items) {
    if (items.length <= 1) return items.join("");
    return items.slice(0, -1).join(", ") + " and " + items[items.length - 1];
  }

  function verdictLine(r) {
    const h = el("h2", { class: "verdict", id: "result-h" });
    const host = el("span", { class: "host", text: r.host });
    if (!r.reachable) {
      h.append("We couldn't reach ", host, ".");
      return h;
    }
    if (!r.php) {
      h.append(host, " shows no signs of PHP.");
      return h;
    }
    let text = " runs PHP";
    if (r.php_version) text += " " + r.php_version;
    if (r.apps && r.apps.length) text += " with " + joinList(r.apps);
    h.append(host, text + ".");
    return h;
  }

  // same words as the command-line scanner
  const STATUS = {
    bad: ["bad", "Vulnerable"],
    good: ["good", "Patched"],
    unknown: ["warn", "Patch status not visible"],
  };

  function render(r) {
    // "Run it yourself": the command now uses the address that was just checked
    const cli = document.getElementById("cli-target");
    if (cli && r.host) cli.textContent = r.host;
    result.replaceChildren();
    result.setAttribute("aria-labelledby", "result-h");
    result.append(el("p", { class: "kicker", text: "Here's what we found" }), verdictLine(r));

    if (!r.reachable) {
      result.append(el("p", { text: r.error || "The website did not answer." }));
      result.append(el("p", { class: "meta", text: "Check the address and try again later." }));
      return;
    }

    let level, title, text;
    if (r.php && r.php_check) {
      [level, title] = STATUS[r.php_check.status] || STATUS.unknown;
      text = r.php_check.text;
    } else {
      [level, title] = ["good", "No PHP found"];
      text = "Nothing on the start page points to PHP. It may still use PHP and simply not " +
        "reveal it, which is good practice.";
    }
    result.append(el("div", { class: "status " + level }, [
      icon(level),
      el("div", {}, [el("strong", { text: title }), el("p", { text: text })]),
    ]));

    if (r.php && r.fixed && r.fixed.length) {
      const rows = r.fixed.map((f) => {
        const name = el("td", { text: f.software });
        if (f.found) name.append(" ", el("span", { class: "found-tag", text: "(found on this site)" }));
        const ver = el("td", {}, [f.versions ? el("span", { class: "code", text: f.versions }) : null]);
        if (f.note) ver.append(f.versions ? el("br") : "", el("span", { class: "fix-note", text: f.note }));
        return el("tr", f.found ? { class: "found" } : {}, [name, ver]);
      });
      result.append(el("h3", { text: "Fixed versions" }), el("div", { class: "table-wrap" }, [
        el("table", {}, [
          el("thead", {}, [el("tr", {}, [el("th", { text: "PHP branch" }), el("th", { text: "Safe from version" })])]),
          el("tbody", {}, rows),
        ]),
      ]));
    }

    if (r.evidence && r.evidence.length) {
      result.append(el("h3", { text: "What gave it away" }),
        el("ul", { class: "plain" }, r.evidence.map((e) => el("li", { text: e }))));
    }

    if (r.recommendations && r.recommendations.length) {
      result.append(el("h3", { text: "Good to know" }),
        el("div", { class: "notes" }, r.recommendations.map((n) => el("p", { text: n }))));
    }

    const facts = el("dl", { class: "facts" });
    const add = (label, value, cls) => {
      if (value === undefined || value === null || value === "") return;
      facts.append(el("dt", { text: label }), el("dd", { text: String(value), class: cls || "" }));
    };
    add("Address checked", r.final_url, "code");
    add("Server software", r.server);
    add("IP address", r.ip, "code");
    add("HTTP status", r.http_status);
    result.append(el("h3", { text: "Details" }), facts);

    let meta = "Checked " + (r.checked_at || "just now");
    if (r.cached) meta += " (saved result)";
    result.append(el("p", { class: "meta", text: meta + "." }));
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearFormError();
    const host = hostInput.value.trim();
    if (!host) {
      showFormError("Enter the address of your website, for example www.example.ch.");
      hostInput.focus();
      return;
    }
    if (!consent.checked) {
      showFormError("Confirm that you own the website or have the owner's permission.");
      consent.focus();
      return;
    }

    button.disabled = true;
    button.textContent = "Checking…";
    result.hidden = false;
    result.replaceChildren(el("p", { class: "checking", text: "Checking " + host }));

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host: host, consent: true }),
      });
      let data = {};
      try { data = await res.json(); } catch (e) { /* non-JSON error page */ }
      if (!res.ok) {
        result.hidden = true;
        result.replaceChildren();
        showFormError(data.error || "The check failed (error " + res.status + "). Try again later.");
        return;
      }
      render(data);
      result.focus({ preventScroll: true });
      result.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    } catch (e) {
      result.hidden = true;
      result.replaceChildren();
      showFormError("The service could not be reached. Check your connection and try again.");
    } finally {
      button.disabled = false;
      button.textContent = "Check website";
    }
  });

  // "Details" from Check all on shouldipanic.ch: show the result that was just checked.
  // It comes from the server's cache, nothing is sent to the website again.
  if (preset && new URLSearchParams(location.search).get("show") === "1") {
    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host: preset, cached_only: true }),
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!data) return;                 // nothing recent: the address is filled in, check as usual
        result.hidden = false;
        render(data);
        result.focus({ preventScroll: true });
        result.scrollIntoView({ block: "start" });
      })
      .catch(() => {});
  }
})();

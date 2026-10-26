"use strict";

// Everything that comes from the checked website (server header, app names, URLs) is
// inserted with textContent only - never as HTML - so a site can't inject markup here.

(function () {
  const form = document.getElementById("check");
  const hostInput = document.getElementById("host");
  const consent = document.getElementById("consent");
  const button = document.getElementById("go");
  const result = document.getElementById("result");

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "text") node.textContent = v;
      else node.setAttribute(k, v);
    }
    for (const c of children || []) if (c) node.append(c);
    return node;
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
    const h1 = el("p", { class: "verdict" });
    const host = el("span", { class: "host", text: r.host });
    if (!r.reachable) {
      h1.append("We couldn't reach ", host, ".");
      return h1;
    }
    if (!r.php) {
      h1.append(host, " shows no signs of PHP.");
      return h1;
    }
    let text = " runs PHP";
    if (r.php_version) text += " " + r.php_version;
    if (r.apps && r.apps.length) text += " with " + joinList(r.apps);
    h1.append(host, text + ".");
    return h1;
  }

  const STATUS_TITLE = {
    good: "Patched against PHP2Shell",
    bad: "Likely vulnerable to PHP2Shell",
    unknown: "PHP2Shell patch status not visible from outside",
  };

  function render(r) {
    result.replaceChildren();
    result.append(verdictLine(r));

    if (!r.reachable) {
      result.append(el("p", { text: r.error || "The website did not answer." }));
      result.append(el("p", { class: "meta", text: "Check the address and try again later." }));
      return;
    }

    if (r.php && r.php_check) {
      const s = r.php_check.status in STATUS_TITLE ? r.php_check.status : "unknown";
      result.append(el("div", { class: "status " + s }, [
        el("strong", { text: STATUS_TITLE[s] }),
        el("p", { text: r.php_check.text }),
      ]));
    } else if (!r.php) {
      result.append(el("p", { text: "Nothing on the start page points to PHP. It may still use PHP " +
        "and simply not reveal it, which is good practice." }));
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
    result.append(el("h2", { text: "Details" }), facts);

    if (r.evidence && r.evidence.length) {
      result.append(el("h2", { text: "What gave it away" }),
        el("ul", { class: "plain" }, r.evidence.map((e) => el("li", { text: e }))));
    }
    if (r.recommendations && r.recommendations.length) {
      result.append(el("h2", { text: "Recommendations" }),
        el("ul", { class: "plain" }, r.recommendations.map((e) => el("li", { text: e }))));
    }

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
})();

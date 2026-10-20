// nzbd client script. The CSP forbids inline script; this file is the only one.
// htmx is progressive enhancement: every page works without it. Its hardening is also set
// here, so it holds even if the <meta name="htmx-config"> tag is ever dropped from a template.
if (window.htmx && window.htmx.config) {
  var cfg = window.htmx.config;
  cfg.allowEval = false;
  cfg.allowScriptTags = false;
  cfg.includeIndicatorStyles = false; // the CSP forbids the inline <style> htmx would inject
  cfg.historyCacheSize = 0; // no private page snapshots in browser storage
  cfg.refreshOnHistoryMiss = true; // native navigation cancels superseded history loads
  cfg.selfRequestsOnly = true;
}
// Adds the CSRF synchronizer token to every HTMX request (AUTH_SPEC, section CSRF).
document.addEventListener("htmx:configRequest", function (event) {
  var meta = document.querySelector('meta[name="csrf-token"]');
  if (meta && meta.content) {
    event.detail.headers["X-CSRF-Token"] = meta.content;
  }
});
// Selection controls are progressive enhancement: without this script the ordinary forms work.
(function () {
  function selectedRows(form) {
    return form.querySelectorAll('input[type="checkbox"][name="id"]:not(:disabled), input[type="checkbox"][name="file"]:not(:disabled)');
  }
  function sync(form) {
    var rows = selectedRows(form);
    var checked = 0;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].checked) checked++;
    }
    var all = form.querySelectorAll("input.select-all");
    for (var j = 0; j < all.length; j++) {
      all[j].checked = rows.length > 0 && checked === rows.length;
      all[j].indeterminate = checked > 0 && checked < rows.length;
    }
    var buttons = form.querySelectorAll('button[type="submit"]');
    for (var k = 0; k < buttons.length; k++) {
      buttons[k].disabled = checked === 0;
    }
    return checked;
  }
  function reveal() {
    var boxes = document.querySelectorAll("input.select-all");
    for (var i = 0; i < boxes.length; i++) {
      boxes[i].hidden = false;
      var label = boxes[i].closest("label.select-all-control");
      if (label) label.hidden = false;
    }
    var forms = document.querySelectorAll("form.selection-form");
    for (var j = 0; j < forms.length; j++) sync(forms[j]);
  }
  document.addEventListener("change", function (event) {
    var t = event.target;
    if (!t || !t.classList) {
      return;
    }
    var form = t.form;
    if (!form || !form.classList.contains("selection-form")) return;
    if (t.classList.contains("select-all")) {
      var rows = selectedRows(form);
      for (var i = 0; i < rows.length; i++) {
        rows[i].checked = t.checked;
      }
      sync(form);
    } else if (t.type === "checkbox" && (t.name === "id" || t.name === "file")) {
      sync(form);
    }
  });
  // Bulk edits share a form. Enter in Source must choose its own action. Native checkbox
  // Enter can skip a disabled default submit, so prevent that ambiguous action explicitly.
  document.addEventListener("keydown", function (event) {
    var field = event.target;
    if (event.key !== "Enter" || event.isComposing || event.defaultPrevented || !field) return;
    var form = field.form;
    // The selected release inputs are named "id", which shadows form.id in the DOM.
    if (!form || form.getAttribute("id") !== "bulk" || !form.classList.contains("selection-form")) return;
    if (field.type === "checkbox") {
      event.preventDefault();
      return;
    }
    if (field.id !== "bulk-source") return;
    var button = form.querySelector('button[name="action"][value="source"]');
    if (!button) return;
    event.preventDefault();
    form.requestSubmit(button);
  });
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (form && form.classList && form.classList.contains("selection-form") && !sync(form)) {
      event.preventDefault();
      var first = selectedRows(form)[0];
      if (first) first.focus();
    }
  });
  document.addEventListener("DOMContentLoaded", reveal);
  document.addEventListener("htmx:afterSettle", reveal);
  document.addEventListener("pageshow", reveal);
})();
// HTMX restores focused controls by ID. If pagination removes that link, retain
// a useful focus position, but only when navigation still held focus at the swap.
(function () {
  var pending = new WeakMap();
  document.addEventListener("htmx:beforeSwap", function (event) {
    var detail = event.detail;
    var target = detail.target;
    var active = document.activeElement;
    if (!detail.shouldSwap || !detail.xhr || !target ||
        (target.id !== "results" && target.id !== "files" && target.id !== "segments") ||
        !active || active.tagName !== "A" || !active.id || !target.contains(active)) return;
    var pager = active.closest("nav.pager");
    if (!pager && !active.closest("thead")) return;
    pending.set(detail.xhr, { target: target.id, pager: pager ? pager.id : null });
  });
  document.addEventListener("htmx:afterSwap", function (event) {
    var restore = pending.get(event.detail.xhr);
    if (!restore) return;
    pending.delete(event.detail.xhr);
    var active = document.activeElement;
    if (active && active !== document.body && active !== document.documentElement) return;
    var fallback = (restore.pager && document.getElementById(restore.pager)) ||
      document.getElementById(restore.target);
    if (fallback) fallback.focus({ preventScroll: true });
  });
})();
// Failed enhanced navigation must be visible; HTMX leaves 4xx/5xx responses unswapped.
// Use fixed text, never inject the server's error document or request values into HTML.
(function () {
  function notice() {
    return document.getElementById("request-notice");
  }
  function show(message) {
    var el = notice();
    if (!el) return;
    el.textContent = message;
    el.hidden = false;
    el.focus();
  }
  document.addEventListener("htmx:beforeRequest", function () {
    var el = notice();
    if (el) el.hidden = true;
  });
  document.addEventListener("htmx:responseError", function (event) {
    var status = event.detail.xhr.status;
    show(status === 429 ? "Too many requests. Wait a moment, then try again." :
      status === 404 ? "This page is no longer available. Reload the page to continue." :
      "The page could not be loaded. Please try again.");
  });
  document.addEventListener("htmx:sendError", function () {
    show("Could not connect to the server. Check your connection and try again.");
  });
  document.addEventListener("htmx:timeout", function () {
    show("The request timed out. Please try again.");
  });
})();

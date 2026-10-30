/* CanaryGate UI — progressive enhancements only.
 *
 * Every page is server-rendered and every form works without JavaScript
 * (plain POST + redirect). This file adds: mobile navigation, local table
 * filtering, copy-to-clipboard for hashes, print button, file-into-textarea for
 * the spec page, busy feedback and HTMX error surfacing. No data is computed.
 */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    initNavToggle();
    initTableFilters();
    initCopyButtons();
    initPrint();
    initSpecFileLoader();
    initBusyForms();
  });

  /* ------------------------------------------------------------ navigation */
  function initNavToggle() {
    var toggle = document.querySelector("[data-nav-toggle]");
    var nav = document.querySelector("[data-nav]");
    if (!toggle || !nav) return;
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    // Close the mobile menu after following a link.
    nav.addEventListener("click", function (event) {
      if (event.target.closest("a") && nav.classList.contains("is-open")) {
        nav.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* --------------------------------------------------------- table filters */
  function initTableFilters() {
    var inputs = document.querySelectorAll("[data-table-filter]");
    Array.prototype.forEach.call(inputs, function (input) {
      var table = document.querySelector(input.getAttribute("data-table-filter"));
      if (!table) return;
      var rows = table.querySelectorAll("[data-filter-row]");
      var counter = table.closest(".card") && table.closest(".card").querySelector("[data-filter-count]");
      input.addEventListener("input", function () {
        var term = input.value.trim().toLowerCase();
        var shown = 0;
        Array.prototype.forEach.call(rows, function (row) {
          var match = term === "" || row.textContent.toLowerCase().indexOf(term) !== -1;
          row.hidden = !match;
          if (match) shown += 1;
        });
        if (counter) counter.textContent = shown + " / " + rows.length;
      });
    });
  }

  /* ------------------------------------------------------- copy / printing */
  function initCopyButtons() {
    document.addEventListener("click", function (event) {
      var button = event.target.closest("[data-copy]");
      if (!button) return;
      var value = button.getAttribute("data-copy");
      var done = function (ok) {
        var original = button.textContent;
        button.textContent = ok ? "copied" : "select + copy";
        window.setTimeout(function () { button.textContent = original; }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).then(function () { done(true); }, function () { done(false); });
      } else {
        done(false);
      }
    });
  }

  function initPrint() {
    document.addEventListener("click", function (event) {
      if (event.target.closest("[data-print]")) window.print();
    });
  }

  /* -------------------------------------------------- spec file -> textarea */
  function initSpecFileLoader() {
    var input = document.querySelector("[data-spec-file]");
    var textarea = document.querySelector("textarea[name='document']");
    if (!input || !textarea) return;
    input.addEventListener("change", function () {
      var file = input.files && input.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function () {
        textarea.value = String(reader.result || "");
        textarea.focus();
      };
      reader.onerror = function () { flash("Could not read that file locally. Paste the document instead."); };
      reader.readAsText(file);
    });
  }

  /* ------------------------------------------------------- busy feedback */
  function initBusyForms() {
    var forms = document.querySelectorAll("form[method='post']");
    Array.prototype.forEach.call(forms, function (form) {
      form.addEventListener("submit", function () {
        var button = form.querySelector("button[type='submit']");
        if (!button || button.disabled) return;
        button.setAttribute("aria-busy", "true");
        if (!form.hasAttribute("hx-post")) {
          var original = button.textContent;
          button.textContent = "Working…";
          window.setTimeout(function () { button.textContent = original; }, 15000);
        }
      });
    });
  }

  function flash(message) {
    var main = document.getElementById("main");
    if (!main) { window.alert(message); return; }
    var box = document.createElement("div");
    box.className = "alert alert-danger";
    box.setAttribute("role", "alert");
    box.textContent = message;
    main.insertBefore(box, main.firstChild);
  }

  /* -------------------------------------------------------------- HTMX */
  document.body.addEventListener("htmx:beforeSwap", function (event) {
    // Action endpoints answer failures with a human-readable HTML fragment, so
    // render it instead of dropping the response and leaving a dead panel.
    var status = event.detail.xhr && event.detail.xhr.status;
    if (status && status >= 400) {
      event.detail.shouldSwap = true;
      event.detail.isError = false;
    }
  });

  document.body.addEventListener("htmx:sendError", function () {
    flash("Network error: the local server did not respond. Check that it is still running.");
  });

  document.body.addEventListener("htmx:afterRequest", function (event) {
    var button = event.detail.elt;
    if (button && button.removeAttribute) button.removeAttribute("aria-busy");
  });
})();

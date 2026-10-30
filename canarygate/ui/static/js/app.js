/* CanaryGate local UI: small progressive enhancements only.
 *
 * Everything here is optional. The pages are server-rendered and every form
 * works with JavaScript disabled (plain POST + redirect); this file only adds
 * navigation, client-side filtering, file loading into the spec textarea and
 * loading/error feedback.
 */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    initNavToggle();
    initTableFilters();
    initSpecFileLoader();
    initBusyForms();
  });

  /* Mobile navigation ------------------------------------------------------ */
  function initNavToggle() {
    var toggle = document.querySelector("[data-nav-toggle]");
    var nav = document.querySelector("[data-nav]");
    if (!toggle || !nav) return;
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  /* Local table filtering (no request, no state) --------------------------- */
  function initTableFilters() {
    var inputs = document.querySelectorAll("[data-table-filter]");
    Array.prototype.forEach.call(inputs, function (input) {
      var table = document.querySelector(input.getAttribute("data-table-filter"));
      if (!table) return;
      var rows = table.querySelectorAll("[data-filter-row]");
      input.addEventListener("input", function () {
        var term = input.value.trim().toLowerCase();
        Array.prototype.forEach.call(rows, function (row) {
          row.hidden = term !== "" && row.textContent.toLowerCase().indexOf(term) === -1;
        });
      });
    });
  }

  /* Load a chosen file into the spec textarea (no upload, no fetch) -------- */
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
      reader.onerror = function () {
        flash("Could not read that file locally. Paste the document instead.");
      };
      reader.readAsText(file);
    });
  }

  /* Give non-HTMX form submissions a visible working state ---------------- */
  function initBusyForms() {
    var forms = document.querySelectorAll("form");
    Array.prototype.forEach.call(forms, function (form) {
      form.addEventListener("submit", function () {
        var button = form.querySelector("button[type='submit']");
        if (!button) return;
        var original = button.textContent;
        button.dataset.label = original;
        button.textContent = "Working…";
        button.setAttribute("aria-busy", "true");
        // Restore the label if the browser keeps the page (e.g. back button).
        window.setTimeout(function () {
          button.textContent = original;
          button.removeAttribute("aria-busy");
        }, 15000);
      });
    });
  }

  function flash(message) {
    var main = document.getElementById("main");
    if (!main) {
      window.alert(message);
      return;
    }
    var box = document.createElement("div");
    box.className = "alert alert-danger";
    box.setAttribute("role", "alert");
    box.textContent = message;
    main.insertBefore(box, main.firstChild);
  }

  /* HTMX hooks (only used when the request was made by HTMX) --------------- */
  document.body.addEventListener("htmx:beforeSwap", function (event) {
    // Our action endpoints return a human-readable HTML fragment on failure,
    // so render it instead of discarding the response and leaving a dead panel.
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
    if (button && button.getAttribute) {
      button.removeAttribute("aria-busy");
    }
  });
})();

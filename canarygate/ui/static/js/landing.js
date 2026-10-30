/* CanaryGate landing page — the only behaviour is "stop the intro".
 *
 * The page is fully readable with JavaScript disabled: the headline, both
 * buttons and every section are plain HTML, and the CSS `prefers-reduced-motion`
 * rules already pin the scene to its final frame. This script adds the explicit
 * skip control on top of that.
 */
(function () {
  "use strict";

  var root = document.documentElement;
  var button = document.querySelector("[data-skip-intro]");
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)");

  function pin() {
    root.classList.add("is-static");
  }

  if (reduce && reduce.matches) {
    pin();
  }

  function skip() {
    pin();
    if (button) {
      button.textContent = "Intro skipped";
      button.disabled = true;
      button.setAttribute("aria-disabled", "true");
    }
  }

  if (button) {
    button.addEventListener("click", skip);
  }

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      skip();
    }
  });

  // The scene is decorative and finite. When it ends, the progress meter and the
  // skip control disappear; the content was never waiting on them.
  window.setTimeout(function () {
    root.classList.add("intro-done");
  }, 15500);
})();

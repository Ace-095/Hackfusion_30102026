/* Small, honest affordance for the run form: when the judge presses Run, the
 * button says what is happening. The server does the work; this only prevents a
 * double submit and keeps the label truthful. */
(function () {
  "use strict";
  var form = document.querySelector("[data-run-form]");
  if (!form) { return; }
  form.addEventListener("submit", function () {
    var button = form.querySelector("[data-run-button]");
    if (button) {
      button.disabled = true;
      button.textContent = "Starting the security engine…";
    }
    var note = form.querySelector(".run-cta .note");
    if (note) {
      note.textContent = "Connecting to the loopback lab. The next screen shows each request as it completes.";
    }
  });
})();

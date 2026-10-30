/* ==========================================================================
   CanaryGate UI — flight recorder playback engine
   Progressive enhancement only. The server renders every recorded event as a
   complete list; this script turns that list into a stepper when JavaScript is
   available. If it fails, throws or is blocked, the full timeline stays on the
   page and nothing is hidden.
   ========================================================================== */
(function () {
  "use strict";

  var root = document.querySelector("[data-replay]");
  if (!root) return;

  var events = Array.prototype.slice.call(root.querySelectorAll("[data-event]"));
  if (events.length === 0) return;

  var controls = root.querySelector("[data-replay-controls]");
  var toggle = root.querySelector('[data-replay-action="toggle"]');
  var toggleLabel = root.querySelector("[data-replay-toggle-label]");
  var counter = root.querySelector("[data-replay-counter]");
  var announce = root.querySelector("[data-replay-announce]");
  var speed = root.querySelector("[data-replay-speed]");
  var verdict = root.querySelector("[data-replay-verdict]");
  var reduceMotion = window.matchMedia
    ? window.matchMedia("(prefers-reduced-motion: reduce)")
    : { matches: false };

  var index = 0;
  var timer = null;
  var playing = false;

  function offsets() {
    return events.map(function (node) {
      var raw = node.getAttribute("data-offset");
      var value = raw === null || raw === "" ? NaN : parseInt(raw, 10);
      return Number.isFinite(value) ? value : null;
    });
  }
  var gaps = offsets();

  /* Wall-clock gaps drive playback speed, but a 4 ms gap still needs to be
     readable: clamp to 700–2400 ms before applying the speed multiplier. */
  function delayAfter(i) {
    var current = gaps[i];
    var next = gaps[i + 1];
    if (current === null || next === null) return 1200;
    var gap = Math.max(next - current, 0);
    var rate = parseFloat(speed && speed.value ? speed.value : "1") || 1;
    return Math.min(Math.max(gap * 4 + 650, 700), 2400) / rate;
  }

  function describe(node) {
    var step = node.querySelector(".replay-step");
    var title = node.querySelector(".replay-title");
    var path = node.querySelector(".path");
    var method = node.querySelector(".replay-request .chip");
    var status = node.querySelector(".status-chip");
    var actor = node.querySelector(".actor-chip b");
    return [
      step ? step.textContent.trim() : "",
      title ? title.textContent.trim() : "",
      method ? method.textContent.trim() : "",
      path ? path.textContent.trim() : "",
      status ? "status " + status.textContent.trim() : "",
      actor ? "as " + actor.textContent.trim() : ""
    ].filter(Boolean).join(" · ");
  }

  function render(step, announceStep) {
    index = Math.min(Math.max(step, 0), events.length - 1);
    events.forEach(function (node, position) {
      var active = position === index;
      node.classList.toggle("is-active", active);
      node.classList.toggle("is-past", position < index);
      if (active) {
        node.setAttribute("aria-current", "step");
      } else {
        node.removeAttribute("aria-current");
      }
    });

    if (counter) counter.textContent = (index + 1) + " / " + events.length;
    if (verdict) verdict.setAttribute("data-revealed", index === events.length - 1 ? "true" : "false");

    var current = events[index];
    if (announceStep !== false && announce) announce.textContent = describe(current);

    var top = current.getBoundingClientRect().top + window.pageYOffset - 96;
    if (Math.abs(window.pageYOffset - top) > 140) {
      window.scrollTo({ top: Math.max(top, 0), behavior: reduceMotion.matches ? "auto" : "smooth" });
    }
  }

  function stop() {
    playing = false;
    if (timer) {
      window.clearTimeout(timer);
      timer = null;
    }
    if (toggle) toggle.setAttribute("aria-pressed", "false");
    if (toggleLabel) toggleLabel.textContent = "Play";
  }

  function tick() {
    timer = null;
    if (!playing) return;
    if (index >= events.length - 1) {
      stop();
      return;
    }
    render(index + 1);
    timer = window.setTimeout(tick, delayAfter(index));
  }

  function play() {
    if (index >= events.length - 1) render(0);
    playing = true;
    if (toggle) toggle.setAttribute("aria-pressed", "true");
    if (toggleLabel) toggleLabel.textContent = "Pause";
    timer = window.setTimeout(tick, delayAfter(index));
  }

  function step(delta) {
    stop();
    render(index + delta);
  }

  root.addEventListener("click", function (event) {
    var button = event.target.closest("[data-replay-action]");
    if (!button) return;
    var action = button.getAttribute("data-replay-action");
    if (action === "next") step(1);
    else if (action === "prev") step(-1);
    else if (action === "restart") { stop(); render(0); }
    else if (action === "toggle") { if (playing) stop(); else play(); }
  });

  if (speed) {
    speed.addEventListener("change", function () {
      if (playing) {
        window.clearTimeout(timer);
        timer = window.setTimeout(tick, delayAfter(index));
      }
    });
  }

  root.addEventListener("keydown", function (event) {
    var onChildButton = event.target !== root && event.target.closest("button, select, a, summary");
    if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
      if (onChildButton) return;
      event.preventDefault();
      step(event.key === "ArrowRight" ? 1 : -1);
    } else if (event.key === "Home") {
      event.preventDefault();
      stop();
      render(0);
    } else if (event.key === "End") {
      event.preventDefault();
      stop();
      render(events.length - 1);
    } else if (event.key === " " || event.key === "Spacebar") {
      if (onChildButton) return;
      event.preventDefault();
      if (playing) stop(); else play();
    }
  });

  if (controls) controls.hidden = false;
  root.setAttribute("data-enhanced", "true");
  render(0, false);
})();

/* ==========================================================================
   CanaryGate — cover sequence driver

   Two jobs, both optional:
     1. hand the visitor to the interface after the sequence finishes;
     2. draw the ambient background on a canvas.

   If this file never runs, the cover still plays (the beats are CSS), the
   hand-off still happens (<noscript> meta refresh) and both "Enter" links are
   ordinary anchors.
   ========================================================================== */
(function () {
  "use strict";

  var RUN_MS = 10000;                  /* keep in sync with --run in intro.css */
  var DESTINATION = "/ui/";

  var root = document.documentElement;
  root.classList.remove("no-js");

  var reduceMotion = window.matchMedia
    ? window.matchMedia("(prefers-reduced-motion: reduce)")
    : { matches: false, addEventListener: function () {} };

  var progress = document.querySelector("[data-intro-progress]");
  var countdown = document.querySelector("[data-intro-countdown]");

  /* ------------------------------------------------------------- hand-off */
  var done = false;
  function enter() {
    if (done) return;
    done = true;
    /* Announced before navigating so the hand-off is observable (tests,
       debugging) without a global. Carries no data beyond the destination. */
    document.dispatchEvent(new CustomEvent("intro:enter", {
      detail: { destination: DESTINATION }
    }));
    window.location.assign(DESTINATION);
  }

  /* A real anchor usually handles the click itself; this keeps the transition
     consistent and marks the page as leaving so the canvas stops drawing. */
  Array.prototype.forEach.call(
    document.querySelectorAll("[data-intro-enter]"),
    function (link) {
      link.addEventListener("click", function (event) {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
        done = true;
      });
    }
  );

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      event.preventDefault();
      enter();
    }
  });

  /* ----------------------------------------------------------------- clock */
  var start = null;

  function tick(now) {
    if (start === null) start = now;
    var elapsed = now - start;
    var ratio = Math.min(elapsed / RUN_MS, 1);

    if (progress) progress.style.width = (ratio * 100).toFixed(2) + "%";
    if (countdown) {
      var left = Math.max(0, Math.ceil((RUN_MS - elapsed) / 1000));
      countdown.textContent = left > 0
        ? "entering the interface in " + left + "s"
        : "entering the interface";
    }

    if (ratio >= 1) {
      enter();
      return;
    }
    if (!done) window.requestAnimationFrame(tick);
  }

  if (!reduceMotion.matches) {
    window.requestAnimationFrame(tick);
  } else if (countdown) {
    /* Reduced motion: no automatic navigation. The visitor leaves when they
       choose to, using the visible "Enter the interface" button. */
    countdown.textContent = "select “Enter the interface” when ready";
    if (progress) progress.style.width = "100%";
  }

  /* ---------------------------------------------------------------- canvas */
  var canvas = document.querySelector("[data-intro-canvas]");
  if (!canvas || reduceMotion.matches) return;

  var ctx = canvas.getContext("2d");
  if (!ctx) return;

  var width = 0;
  var height = 0;
  var dpr = Math.min(window.devicePixelRatio || 1, 2);
  var particles = [];
  var ripples = [];
  var gateX = 0.62;
  var running = true;
  var frame = null;

  function resize() {
    width = canvas.clientWidth;
    height = canvas.clientHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    seed();
  }

  function seed() {
    var count = Math.max(18, Math.min(46, Math.round(width / 34)));
    particles = [];
    for (var i = 0; i < count; i += 1) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        speed: 0.14 + Math.random() * 0.5,
        len: 6 + Math.random() * 26,
        alpha: 0.06 + Math.random() * 0.22,
        accent: Math.random() < 0.22
      });
    }
  }

  function draw(time) {
    if (!running) return;
    var seconds = time / 1000;

    ctx.clearRect(0, 0, width, height);

    /* the gate: a single vertical reference line the traffic crosses */
    var gx = width * gateX;
    var shimmer = 0.1 + 0.05 * Math.sin(seconds * 1.7);
    var grad = ctx.createLinearGradient(gx, 0, gx, height);
    grad.addColorStop(0, "rgba(76,194,255,0)");
    grad.addColorStop(0.5, "rgba(76,194,255," + shimmer.toFixed(3) + ")");
    grad.addColorStop(1, "rgba(76,194,255,0)");
    ctx.strokeStyle = grad;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(gx, 0);
    ctx.lineTo(gx, height);
    ctx.stroke();

    /* requests crossing the wire */
    for (var i = 0; i < particles.length; i += 1) {
      var p = particles[i];
      p.x += p.speed;
      if (p.x - p.len > width) {
        p.x = -p.len;
        p.y = Math.random() * height;
      }

      /* a particle that crosses the gate leaves a ripple */
      if (p.x >= gx && p.x - p.speed < gx && p.accent) {
        ripples.push({ x: gx, y: p.y, r: 2, alpha: 0.5 });
        if (ripples.length > 14) ripples.shift();
      }

      var line = ctx.createLinearGradient(p.x - p.len, p.y, p.x, p.y);
      line.addColorStop(0, "rgba(76,194,255,0)");
      line.addColorStop(1, p.accent
        ? "rgba(76,194,255," + p.alpha.toFixed(3) + ")"
        : "rgba(168,185,201," + (p.alpha * 0.7).toFixed(3) + ")");
      ctx.strokeStyle = line;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(p.x - p.len, p.y);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
    }

    /* ripples fade out quickly; they mark a crossing, nothing more */
    for (var j = ripples.length - 1; j >= 0; j -= 1) {
      var rip = ripples[j];
      rip.r += 0.9;
      rip.alpha *= 0.955;
      if (rip.alpha < 0.01) { ripples.splice(j, 1); continue; }
      ctx.strokeStyle = "rgba(76,194,255," + rip.alpha.toFixed(3) + ")";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(rip.x, rip.y, rip.r, 0, Math.PI * 2);
      ctx.stroke();
    }

    frame = window.requestAnimationFrame(draw);
  }

  window.addEventListener("resize", resize);
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      running = false;
      if (frame) window.cancelAnimationFrame(frame);
    } else if (!running) {
      running = true;
      frame = window.requestAnimationFrame(draw);
    }
  });

  resize();
  frame = window.requestAnimationFrame(draw);
})();

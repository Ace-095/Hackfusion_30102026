/* ==========================================================================
   CanaryGate — landing page driver

   The sequence itself is CSS. This file only does four things:
     1. runs the clock (progress bar + honest countdown);
     2. hands the visitor to the interface, but only if they have not started
        reading — scrolling, clicking or pressing a key cancels the hand-off;
     3. restarts the sequence on demand;
     4. synthesises a quiet pulse with the Web Audio API, off by default.

   No audio file, no library, no network. If this file never loads, the page is
   still a complete landing page and the <noscript> refresh still hands off.
   ========================================================================== */
(function () {
  "use strict";

  var RUN_MS = 18000;              /* keep in sync with --run in intro.css */
  var DESTINATION = "/ui/";
  var BPM = 100;

  var root = document.documentElement;
  root.classList.remove("no-js");

  var reduceQuery = window.matchMedia
    ? window.matchMedia("(prefers-reduced-motion: reduce)")
    : { matches: false, addEventListener: function () {} };

  /* The visitor can opt back into the motion even when the system asks for
     reduced motion; the class is what the stylesheet keys off. */
  var forced = false;
  function motionAllowed() {
    return forced || !reduceQuery.matches;
  }

  var progress = document.querySelector("[data-intro-progress]");
  var countdown = document.querySelector("[data-intro-countdown]");
  var scenesHost = document.querySelector("[data-intro-scenes]");

  /* ------------------------------------------------------------ hand-off */
  var leaving = false;

  function enter(reason) {
    if (leaving) return;
    leaving = true;
    document.dispatchEvent(new CustomEvent("intro:enter", {
      detail: { destination: DESTINATION, reason: reason || "clock" }
    }));
    window.location.assign(DESTINATION);
  }

  Array.prototype.forEach.call(
    document.querySelectorAll("[data-intro-enter]"),
    function (link) {
      link.addEventListener("click", function (event) {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
        leaving = true;
      });
    }
  );

  /* --------------------------------------------------------------- clock */
  var startedAt = null;
  var reading = false;            /* visitor showed intent to read */
  var frame = null;

  function markReading() {
    if (reading) return;
    reading = true;
    /* Tell the visitor immediately that the clock is no longer steering them. */
    if (countdown) countdown.textContent = "staying on the page — “Enter the interface” when ready";
  }

  ["wheel", "touchstart", "pointerdown", "keydown"].forEach(function (type) {
    window.addEventListener(type, markReading, { passive: true, once: true });
  });
  window.addEventListener("scroll", markReading, { passive: true, once: true });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      event.preventDefault();
      enter("escape");
    } else if (event.key === "r" || event.key === "R") {
      if (event.target && /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName)) return;
      event.preventDefault();
      restart();
    }
  });

  function label(msLeft) {
    var seconds = Math.max(0, Math.ceil(msLeft / 1000));
    return reading
      ? "staying on the page — “Enter the interface” when ready"
      : "entering the interface in " + seconds + "s";
  }

  function tick(now) {
    if (startedAt === null) startedAt = now;
    var elapsed = now - startedAt;
    var ratio = Math.min(elapsed / RUN_MS, 1);

    if (progress) progress.style.width = (ratio * 100).toFixed(2) + "%";
    if (countdown) countdown.textContent = label(RUN_MS - elapsed);

    if (ratio >= 1) {
      if (countdown) countdown.textContent = "staying on the page — “Enter the interface” when ready";
      if (!reading) { enter("clock"); return; }
    }
    if (!leaving) frame = window.requestAnimationFrame(tick);
  }

  function startClock() {
    if (!motionAllowed()) {
      if (countdown) countdown.textContent = "menu is in the bar above — or use “Open the menu”";
      if (progress) progress.style.width = "100%";
      return;
    }
    if (frame) window.cancelAnimationFrame(frame);
    startedAt = null;
    frame = window.requestAnimationFrame(tick);
  }

  /* -------------------------------------------------------------- replay */
  function restart() {
    stopSound();
    if (scenesHost) {
      /* Replacing the subtree restarts every CSS animation from zero without
         touching the stylesheet or duplicating markup. */
      var clone = scenesHost.cloneNode(true);
      scenesHost.parentNode.replaceChild(clone, scenesHost);
      scenesHost = clone;
    }
    reading = false;
    leaving = false;
    if (countdown) countdown.textContent = "entering the interface in " + Math.round(RUN_MS / 1000) + "s";
    if (progress) progress.style.width = "0%";
    document.dispatchEvent(new CustomEvent("intro:replay", { detail: { runtime: RUN_MS } }));
    startClock();
    window.scrollTo({ top: 0, behavior: "auto" });
  }

  var replayButton = document.querySelector("[data-intro-replay]");
  if (replayButton) replayButton.addEventListener("click", restart);

  /* --------------------------------------------------------------- sound
     A synthesised pulse, not a recording. Two oscillators and a filtered
     noise burst on a 100 BPM grid, gain kept deliberately low. Off until the
     visitor asks for it, so nothing plays uninvited.                        */
  var audioCtx = null;
  var master = null;
  var scheduler = null;
  var nextBeat = 0;
  var beatIndex = 0;

  function audioSupported() {
    return Boolean(window.AudioContext || window.webkitAudioContext);
  }

  function kick(time) {
    var osc = audioCtx.createOscillator();
    var gain = audioCtx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(120, time);
    osc.frequency.exponentialRampToValueAtTime(42, time + 0.16);
    gain.gain.setValueAtTime(0.0001, time);
    gain.gain.exponentialRampToValueAtTime(0.55, time + 0.012);
    gain.gain.exponentialRampToValueAtTime(0.0001, time + 0.26);
    osc.connect(gain).connect(master);
    osc.start(time);
    osc.stop(time + 0.3);
  }

  function blip(time, frequency, level) {
    var osc = audioCtx.createOscillator();
    var gain = audioCtx.createGain();
    osc.type = "triangle";
    osc.frequency.setValueAtTime(frequency, time);
    gain.gain.setValueAtTime(0.0001, time);
    gain.gain.exponentialRampToValueAtTime(level, time + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, time + 0.18);
    osc.connect(gain).connect(master);
    osc.start(time);
    osc.stop(time + 0.2);
  }

  var beatTimer = null;
  function flashBeat() {
    /* One short class toggle per beat: the CSS pulse is cheap, and it stops
       the moment the soundtrack does. */
    var el = document.documentElement;
    el.classList.add("beat");
    if (beatTimer) window.clearTimeout(beatTimer);
    beatTimer = window.setTimeout(function () { el.classList.remove("beat"); }, 170);
  }

  function schedule() {
    if (!audioCtx) return;
    var beat = 60 / BPM;
    while (nextBeat < audioCtx.currentTime + 0.25) {
      var lead = Math.max(0, (nextBeat - audioCtx.currentTime) * 1000);
      var isDownbeat = beatIndex % 4 === 0;
      if (isDownbeat) window.setTimeout(flashBeat, lead);
      if (beatIndex % 4 === 0) kick(nextBeat);
      if (beatIndex % 4 === 2) blip(nextBeat, 1568, 0.05);       /* off-beat tick */
      if (beatIndex % 8 === 6) blip(nextBeat, 523.25, 0.045);    /* bar marker */
      nextBeat += beat;
      beatIndex += 1;
    }
  }

  function startSound() {
    if (!audioSupported()) return false;
    try {
      if (!audioCtx) {
        var Ctx = window.AudioContext || window.webkitAudioContext;
        audioCtx = new Ctx();
        master = audioCtx.createGain();
        master.gain.value = 0.07;         /* quiet on purpose */
        master.connect(audioCtx.destination);
      }
      if (audioCtx.state === "suspended") audioCtx.resume();
      nextBeat = audioCtx.currentTime + 0.05;
      beatIndex = 0;
      schedule();
      scheduler = window.setInterval(schedule, 100);
      return true;
    } catch (error) {
      return false;
    }
  }

  function stopSound() {
    if (scheduler) { window.clearInterval(scheduler); scheduler = null; }
    if (beatTimer) { window.clearTimeout(beatTimer); beatTimer = null; }
    document.documentElement.classList.remove("beat");
    if (audioCtx && audioCtx.state === "running") audioCtx.suspend();
  }

  var soundButton = document.querySelector("[data-intro-sound]");
  var soundLabel = document.querySelector("[data-intro-sound-label]");

  if (soundButton) {
    if (!audioSupported()) {
      soundButton.disabled = true;
      soundButton.title = "This browser has no Web Audio support.";
    }
    soundButton.addEventListener("click", function () {
      var on = soundButton.getAttribute("aria-pressed") === "true";
      if (on) {
        stopSound();
        soundButton.setAttribute("aria-pressed", "false");
        if (soundLabel) soundLabel.textContent = "Sound off";
      } else {
        var started = startSound();
        soundButton.setAttribute("aria-pressed", started ? "true" : "false");
        if (soundLabel) soundLabel.textContent = started ? "Sound on" : "Unavailable";
      }
    });
  }

  /* ------------------------------------------------------------- the engine
     Ambient background: request lines travelling across a single gate line.
     Pure decoration; hidden from assistive technology and skipped entirely
     when the visitor prefers reduced motion.                                 */
  var canvas = document.querySelector("[data-intro-canvas]");
  var canvasStarted = false;

  function initCanvas() {
    if (canvasStarted || !canvas || !motionAllowed()) return;
    var ctx = canvas.getContext("2d");
    if (!ctx) return;
    canvasStarted = true;

    var width = 0, height = 0;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var packets = [];
    var ripples = [];
    var running = true;
    var drawFrame = null;
    var gateX = 0.62;

    var resize = function () {
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      packets = [];
      var count = Math.max(16, Math.min(44, Math.round(width / 36)));
      for (var i = 0; i < count; i += 1) {
        packets.push({
          x: Math.random() * width,
          y: Math.random() * height,
          speed: 0.12 + Math.random() * 0.45,
          len: 8 + Math.random() * 30,
          alpha: 0.05 + Math.random() * 0.2,
          accent: Math.random() < 0.2
        });
      }
    };

    var draw = function (time) {
      if (!running) return;
      var seconds = time / 1000;
      ctx.clearRect(0, 0, width, height);

      var gx = width * gateX;
      var shimmer = 0.09 + 0.04 * Math.sin(seconds * 1.6);
      var line = ctx.createLinearGradient(gx, 0, gx, height);
      line.addColorStop(0, "rgba(76,194,255,0)");
      line.addColorStop(0.5, "rgba(76,194,255," + shimmer.toFixed(3) + ")");
      line.addColorStop(1, "rgba(76,194,255,0)");
      ctx.strokeStyle = line;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(gx, 0);
      ctx.lineTo(gx, height);
      ctx.stroke();

      for (var i = 0; i < packets.length; i += 1) {
        var p = packets[i];
        var previous = p.x;
        p.x += p.speed;
        if (p.x - p.len > width) { p.x = -p.len; p.y = Math.random() * height; }

        if (p.accent && previous < gx && p.x >= gx) {
          ripples.push({ x: gx, y: p.y, r: 2, alpha: 0.45 });
          if (ripples.length > 12) ripples.shift();
        }

        var stroke = ctx.createLinearGradient(p.x - p.len, p.y, p.x, p.y);
        stroke.addColorStop(0, "rgba(76,194,255,0)");
        stroke.addColorStop(1, p.accent
          ? "rgba(76,194,255," + p.alpha.toFixed(3) + ")"
          : "rgba(150,170,190," + (p.alpha * 0.6).toFixed(3) + ")");
        ctx.strokeStyle = stroke;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(p.x - p.len, p.y);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
      }

      for (var j = ripples.length - 1; j >= 0; j -= 1) {
        var rip = ripples[j];
        rip.r += 0.85;
        rip.alpha *= 0.958;
        if (rip.alpha < 0.01) { ripples.splice(j, 1); continue; }
        ctx.strokeStyle = "rgba(76,194,255," + rip.alpha.toFixed(3) + ")";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(rip.x, rip.y, rip.r, 0, Math.PI * 2);
        ctx.stroke();
      }

      drawFrame = window.requestAnimationFrame(draw);
    };

    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        running = false;
        if (drawFrame) window.cancelAnimationFrame(drawFrame);
      } else if (!running) {
        running = true;
        drawFrame = window.requestAnimationFrame(draw);
      }
    });

    resize();
    drawFrame = window.requestAnimationFrame(draw);
  }

  /* ------------------------------------------------------- play it anyway
     Some browsers report reduced motion because of an OS setting the visitor
     may not know about. The storyboard stays readable either way; this button
     simply plays the sequence for people who want it.                        */
  var playAnyway = document.querySelector("[data-intro-play-anyway]");
  if (playAnyway) {
    if (!reduceQuery.matches) {
      playAnyway.hidden = true;          /* nothing to opt out of */
    }
    playAnyway.addEventListener("click", function () {
      forced = true;
      document.documentElement.classList.add("force-motion");
      document.dispatchEvent(new CustomEvent("intro:force-motion"));
      playAnyway.hidden = true;
      initCanvas();
      restart();
    });
  }

  initCanvas();
  startClock();
})();

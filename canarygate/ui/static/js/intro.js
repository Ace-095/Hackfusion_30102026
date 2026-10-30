/* ==========================================================================
   CanaryGate — landing page driver

   The sequence is CSS; the film grain, the corridor, the cut flashes and the
   verdict burst are drawn on a canvas underneath it. This file does six things:
     1. runs the clock (progress bar + honest countdown + the reel's own HUD);
     2. draws the canvas layer — a perspective gate corridor that the camera
        flies through, a shutter and colour flash on every cut, and a particle
        burst on the verdict scene;
     3. finds the cut times by reading --sd from the stylesheet, so the picture
        can never drift from the timeline (there is no second schedule here);
     4. hands the visitor to the interface, but only if they have not started
        reading — scrolling, clicking or pressing a key cancels the hand-off;
     5. restarts the sequence on demand;
     6. synthesises a quiet pulse with the Web Audio API, off by default.

   No audio file, no library, no network. If this file never loads, the page is
   still a complete landing page and the <noscript> refresh still hands off.
   ========================================================================== */
(function () {
  "use strict";

  var RUN_MS = 15000;              /* keep in sync with --run in intro.css */
  var DESTINATION = "/ui/";
  /* 120 BPM = one beat every 0.5s, which is the grid every cut in intro.css
     sits on. Change the tempo and the cuts stop landing with the kick. */
  var BPM = 120;

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
    updateHud(elapsed);

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
    if (engineReset) engineReset();
    updateHud(0);
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

  /* The cut lands on the beat, so the sound of it can too: a short, quiet
     tick. Silent unless the visitor turned the soundtrack on. */
  function shutterSound() {
    if (!audioCtx || audioCtx.state !== "running") return;
    try {
      blip(audioCtx.currentTime + 0.001, 2093, 0.03);
    } catch (error) { /* audio is optional; never break the picture for it */ }
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
      /* 120 BPM: a beat every 0.5s, which is exactly the cut grid. Kick on the
         beat, a tick between, a bar marker every four, and the picture pulses
         on the downbeat. */
      var isDownbeat = beatIndex % 4 === 0;
      if (isDownbeat) window.setTimeout(flashBeat, lead);
      if (beatIndex % 2 === 0) kick(nextBeat);
      else blip(nextBeat, 1568, 0.05);
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
     A layered motion-graphics pass drawn underneath the CSS scenes:

       corridor   a perspective gate the camera flies down, wireframe rings
                  recycling forever toward the viewer;
       gate       the single bright line the product is named after;
       packets    requests travelling the rails, rippling where they cross;
       cut        on every scene boundary: a white flash, a shutter that tears
                  the frame into bands, a camera kick, and a two-frame
                  chromatic hop (html.cut) shared with the stylesheet;
       burst      at the verdict scene, particles leaving the chip cluster;
       grain      a pre-rendered noise tile, so large dark areas are never flat.

     Two rules this obeys:
       * decoration only — aria-hidden, and skipped entirely under reduced
         motion, where the storyboard is the whole show;
       * the cut times are read from --sd in the stylesheet. There is no second
         copy of the timeline here, so the canvas cannot drift from the CSS.
  */
  var canvas = document.querySelector("[data-intro-canvas]");
  var canvasStarted = false;
  var engineReset = null;              /* assigned by initCanvas, used by restart */
  var reelWindows = null;

  function sceneWindows() {
    var selectors = [".scene-0", ".scene-words", ".scene-1", ".scene-2", ".scene-3",
                     ".scene-4", ".scene-5", ".scene-6", ".scene-title"];
    var windows = [];
    for (var i = 0; i < selectors.length; i += 1) {
      var el = document.querySelector(selectors[i]);
      if (!el) continue;
      var style = window.getComputedStyle ? window.getComputedStyle(el) : null;
      var start = style ? parseFloat(style.getPropertyValue("--sd")) : NaN;
      if (!isFinite(start)) start = 0;
      windows.push({ start: Math.max(0, start) });
    }
    if (!windows.length) windows.push({ start: 0 });
    return windows;
  }

  function getWindows() {
    if (!reelWindows) reelWindows = sceneWindows();
    return reelWindows;
  }

  function windowAt(windows, seconds) {
    var index = 0;
    for (var i = 0; i < windows.length; i += 1) {
      if (windows[i].start <= seconds + 0.0001) index = i;
    }
    return index;
  }

  /* ------------------------------------------------------- the reel's clock
     Same time base as the progress bar, so the HUD cannot lie about the state
     of the sequence. It reports time and the cut number — never a scan result. */
  var hudTime = document.querySelector("[data-intro-hud-time]");
  var hudScene = document.querySelector("[data-intro-hud-scene]");
  var hudBar = document.querySelector("[data-intro-hud-bar]");

  function timecode(ms) {
    var seconds = Math.max(0, ms) / 1000;
    var mm = Math.floor(seconds / 60);
    var ss = Math.floor(seconds % 60);
    var cc = Math.floor((seconds * 100) % 100);
    return (mm < 10 ? "0" : "") + mm + ":" + (ss < 10 ? "0" : "") + ss +
           "." + (cc < 10 ? "0" : "") + cc;
  }

  function updateHud(elapsed) {
    if (!hudTime && !hudScene && !hudBar) return;
    var windows = getWindows();
    var total = windows.length;
    var index = windowAt(windows, elapsed / 1000) + 1;
    if (hudTime) hudTime.textContent = timecode(Math.min(elapsed, RUN_MS));
    if (hudBar) hudBar.style.width = Math.min(100, (elapsed / RUN_MS) * 100).toFixed(1) + "%";
    if (hudScene) {
      hudScene.textContent = "cut " + (index < 10 ? "0" : "") + index +
                             " / " + (total < 10 ? "0" : "") + total;
    }
  }

  function initCanvas() {
    if (canvasStarted || !canvas || !motionAllowed()) return;
    var ctx = null;
    try { ctx = canvas.getContext("2d"); } catch (error) { ctx = null; }
    if (!ctx) return;                  /* no 2D context (jsdom, old browsers) */
    canvasStarted = true;

    var windows = getWindows();
    var W = 0, H = 0, cx = 0, cy = 0, focal = 1;
    var dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    var rings = [], packets = [], sparks = [];
    var flash = 0, shutter = 0, kick = 0;
    var cutIndex = -1;
    var running = true, drawFrame = null, lastTime = 0, cutTimer = null;
    var grain = null, vignette = null;
    var GATE = 0.62;                   /* where the gate line stands */
    var GRAVITY = 46;

    /* --- a noise tile, generated once: no image is ever downloaded --------- */
    function noiseTile() {
      var size = 96;
      var tile = document.createElement("canvas");
      tile.width = size;
      tile.height = size;
      var tctx = null;
      try { tctx = tile.getContext("2d"); } catch (error) { return null; }
      if (!tctx || !tctx.createImageData) return null;
      var image = tctx.createImageData(size, size);
      for (var i = 0; i < image.data.length; i += 4) {
        var value = 96 + Math.random() * 159;
        image.data[i] = value;
        image.data[i + 1] = value;
        image.data[i + 2] = value;
        image.data[i + 3] = 255;
      }
      tctx.putImageData(image, 0, 0);
      return tile;
    }

    function seedPackets() {
      packets = [];
      var count = Math.max(10, Math.min(26, Math.round(W / 62)));
      for (var i = 0; i < count; i += 1) {
        packets.push({
          lane: Math.floor(Math.random() * 4),
          z: 1 + Math.random() * 24,
          speed: 4.5 + Math.random() * 5,
          accent: Math.random() < 0.3
        });
      }
    }

    function resize() {
      W = canvas.clientWidth || window.innerWidth || 0;
      H = canvas.clientHeight || window.innerHeight || 0;
      if (!W || !H) return;
      canvas.width = Math.max(1, Math.floor(W * dpr));
      canvas.height = Math.max(1, Math.floor(H * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      cx = W * 0.5;
      cy = H * 0.5;
      focal = Math.max(W, H) * 0.55;

      rings = [];
      for (var i = 0; i < 26; i += 1) rings.push({ z: 0.55 + i * 1.12 });

      seedPackets();

      vignette = ctx.createRadialGradient(cx, cy, Math.min(W, H) * 0.16,
                                         cx, cy, Math.max(W, H) * 0.72);
      vignette.addColorStop(0, "rgba(0,0,0,0)");
      vignette.addColorStop(0.62, "rgba(0,0,0,0.22)");
      vignette.addColorStop(1, "rgba(0,0,0,0.62)");

      if (!grain) grain = noiseTile();
    }

    /* lane 0..3 → the four rails of the corridor */
    function lanePoint(lane, z) {
      var scale = focal / z;
      var x = lane === 0 || lane === 3 ? -1 : 1;
      var y = lane < 2 ? -0.6 : 0.6;
      return { x: cx + x * scale * 0.9, y: cy + y * scale * 0.62, s: scale };
    }

    function spawnBurst() {
      var count = 46;
      for (var i = 0; i < count; i += 1) {
        var angle = (Math.PI * 2 * i) / count + Math.random() * 0.2;
        var speed = 90 + Math.random() * 320;
        sparks.push({
          x: cx, y: cy * 0.94,
          vx: Math.cos(angle) * speed,
          vy: Math.sin(angle) * speed * 0.72,
          life: 0.5 + Math.random() * 0.7,
          max: 1.2,
          accent: i % 5 === 0
        });
      }
    }

    function onCut(index) {
      flash = 1;
      shutter = 1;
      kick = 1;
      root.classList.add("cut");
      if (cutTimer) window.clearTimeout(cutTimer);
      cutTimer = window.setTimeout(function () { root.classList.remove("cut"); }, 160);
      if (index === 5) spawnBurst();    /* the verdict scene */
      shutterSound();
    }

    function drawCorridor(dt, seconds) {
      var drift = 4.2 + kick * 9;
      for (var i = 0; i < rings.length; i += 1) {
        rings[i].z -= drift * dt;
        if (rings[i].z < 0.5) rings[i].z += 26 * 1.12;
      }

      /* rails: each ring joined to the next, fading with depth */
      for (var r = 0; r < rings.length - 1; r += 1) {
        var near = rings[r].z;
        var far = rings[r + 1].z;
        var alpha = Math.max(0, 1 - near / 27) * 0.42;
        var shake = Math.sin(seconds * 7 + r) * kick * 3;
        var a0 = lanePoint(0, near), b0 = lanePoint(0, far);
        var a1 = lanePoint(1, near), b1 = lanePoint(1, far);
        var a2 = lanePoint(2, near), b2 = lanePoint(2, far);
        var a3 = lanePoint(3, near), b3 = lanePoint(3, far);

        ctx.strokeStyle = "rgba(76,194,255," + alpha.toFixed(3) + ")";
        ctx.lineWidth = Math.max(0.6, 1.6 - near / 24);
        ctx.beginPath();
        ctx.moveTo(a0.x + shake, a0.y); ctx.lineTo(b0.x + shake, b0.y);
        ctx.moveTo(a1.x + shake, a1.y); ctx.lineTo(b1.x + shake, b1.y);
        ctx.moveTo(a2.x + shake, a2.y); ctx.lineTo(b2.x + shake, b2.y);
        ctx.moveTo(a3.x + shake, a3.y); ctx.lineTo(b3.x + shake, b3.y);
        ctx.stroke();

        /* the gate frame itself: a rectangle the camera flies through */
        if (r < rings.length - 2) {
          ctx.strokeStyle = "rgba(150,180,205," + (alpha * 0.5).toFixed(3) + ")";
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(b0.x, b0.y);
          ctx.lineTo(b1.x, b1.y);
          ctx.lineTo(b2.x, b2.y);
          ctx.lineTo(b3.x, b3.y);
          ctx.closePath();
          ctx.stroke();
        }
      }
    }

    function drawGate(seconds) {
      var gx = W * GATE;
      var breathe = 0.1 + 0.05 * Math.sin(seconds * 1.7) + flash * 0.4;
      var line = ctx.createLinearGradient(gx, 0, gx, H);
      line.addColorStop(0, "rgba(76,194,255,0)");
      line.addColorStop(0.42, "rgba(76,194,255," + breathe.toFixed(3) + ")");
      line.addColorStop(0.58, "rgba(120,220,255," + (breathe * 1.4).toFixed(3) + ")");
      line.addColorStop(1, "rgba(76,194,255,0)");
      ctx.strokeStyle = line;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(gx, 0);
      ctx.lineTo(gx, H);
      ctx.stroke();
    }

    function drawPackets(dt) {
      for (var i = 0; i < packets.length; i += 1) {
        var p = packets[i];
        var before = p.z;
        p.z -= p.speed * dt * (1 + kick * 2.2);
        if (p.z < 0.6) {
          p.z = 22 + Math.random() * 6;
          p.lane = Math.floor(Math.random() * 4);
        }

        var head = lanePoint(p.lane, p.z);
        var tail = lanePoint(p.lane, p.z + 1.4);
        var alpha = Math.max(0.05, Math.min(0.55, 1.4 / p.z));

        ctx.strokeStyle = p.accent
          ? "rgba(120,220,255," + alpha.toFixed(3) + ")"
          : "rgba(150,175,195," + (alpha * 0.5).toFixed(3) + ")";
        ctx.lineWidth = Math.max(1, 2.6 - p.z / 12);
        ctx.beginPath();
        ctx.moveTo(tail.x, tail.y);
        ctx.lineTo(head.x, head.y);
        ctx.stroke();

        /* crossing the gate plane throws a ripple */
        if (p.accent && before > 1.0 && p.z <= 1.0) {
          sparks.push({ x: head.x, y: head.y, vx: 0, vy: 0, life: 0.55, max: 0.55,
                        accent: true, ring: true, r: 2 });
        }
      }
    }

    function drawSparks(dt) {
      for (var i = sparks.length - 1; i >= 0; i -= 1) {
        var s = sparks[i];
        s.life -= dt;
        if (s.life <= 0) { sparks.splice(i, 1); continue; }
        var ratio = Math.max(0, s.life / s.max);
        if (s.ring) {
          s.r += 220 * dt;
          ctx.strokeStyle = "rgba(76,194,255," + (ratio * 0.5).toFixed(3) + ")";
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
          ctx.stroke();
          continue;
        }
        s.vy += GRAVITY * dt * 4;
        var px = s.x;
        var py = s.y;
        s.x += s.vx * dt;
        s.y += s.vy * dt;
        ctx.strokeStyle = s.accent
          ? "rgba(255,226,122," + ratio.toFixed(3) + ")"
          : "rgba(76,194,255," + (ratio * 0.8).toFixed(3) + ")";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(px, py);
        ctx.lineTo(s.x, s.y);
        ctx.stroke();
      }
    }

    function drawTicks(seconds) {
      var step = 38;
      var offset = (seconds * 84) % step;
      ctx.strokeStyle = "rgba(120,150,175,0.18)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (var x = -offset; x < W; x += step) {
        var tall = Math.round(x / step) % 5 === 0;
        ctx.moveTo(x, H - 6);
        ctx.lineTo(x, H - (tall ? 22 : 12));
      }
      ctx.stroke();
    }

    function drawCut() {
      if (flash > 0.01) {
        ctx.fillStyle = "rgba(214,240,255," + (flash * 0.12).toFixed(3) + ")";
        ctx.fillRect(0, 0, W, H);
      }
      if (shutter > 0.02) {
        var bands = 9;
        var bandHeight = H / bands;
        for (var b = 0; b < bands; b += 1) {
          var jitter = (Math.random() - 0.5) * 34 * shutter;
          var alpha = 0.16 + Math.random() * 0.3;
          ctx.fillStyle = "rgba(7,11,16," + (alpha * shutter).toFixed(3) + ")";
          ctx.fillRect(jitter, b * bandHeight, W, bandHeight * 0.46);
        }
      }
    }

    function drawGrain() {
      if (!grain) return;
      var size = 96;
      ctx.save();
      ctx.globalAlpha = 0.05;
      ctx.translate(-Math.random() * size, -Math.random() * size);
      for (var x = 0; x <= W + size; x += size) {
        for (var y = 0; y <= H + size; y += size) {
          ctx.drawImage(grain, x, y);
        }
      }
      ctx.restore();
    }

    function frame(time) {
      if (!running) return;
      if (!lastTime) lastTime = time;
      var dt = Math.min((time - lastTime) / 1000, 0.05);
      lastTime = time;
      var seconds = time / 1000;

      /* The picture asks the stylesheet where it is, instead of keeping its
         own idea of the schedule. */
      var reel = startedAt === null ? 0 : Math.min((time - startedAt) / 1000, RUN_MS / 1000);
      var index = windowAt(windows, reel);
      if (index !== cutIndex) {
        onCut(index);
        cutIndex = index;
      }

      flash = Math.max(0, flash - dt * 6);
      shutter = Math.max(0, shutter - dt * 4.5);
      kick = Math.max(0, kick - dt * 2.4);

      ctx.clearRect(0, 0, W, H);
      drawCorridor(dt, seconds);
      drawGate(seconds);
      drawPackets(dt);
      drawSparks(dt);
      drawTicks(seconds);
      drawCut();
      if (vignette) {
        ctx.fillStyle = vignette;
        ctx.fillRect(0, 0, W, H);
      }
      drawGrain();

      drawFrame = window.requestAnimationFrame(frame);
    }

    /* restart() resets the engine without tearing anything down */
    engineReset = function () {
      cutIndex = -1;
      flash = 0;
      shutter = 0;
      kick = 0;
      sparks = [];
      lastTime = 0;
      root.classList.remove("cut");
    };

    window.addEventListener("resize", function () {
      resize();
      reelWindows = null;              /* the stylesheet may have reflowed */
    });

    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        running = false;
        if (drawFrame) window.cancelAnimationFrame(drawFrame);
      } else if (!running) {
        running = true;
        lastTime = 0;
        drawFrame = window.requestAnimationFrame(frame);
      }
    });

    resize();
    if (!W || !H) return;
    drawFrame = window.requestAnimationFrame(frame);
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

/* CanaryGate landing page.
 *
 * One 15-second motion sequence drawn on a canvas, plus the controls around it.
 * The sequence is decoration: the headline, both calls to action and every
 * section below exist in HTML and are readable with JavaScript disabled.
 *
 * Timeline (matches the brief):
 *   0–3 s   network formation
 *   3–6 s   API request paths travel through the network
 *   6–9 s   an authorization boundary appears; one request is refused
 *   9–12 s  evidence fragments assemble into a report
 *   12–15 s the brand resolves
 *
 * Honesty: the animation is abstract. It draws no status code, no verdict badge
 * and no data, so it cannot be mistaken for a result.
 */
(function () {
  "use strict";

  var DURATION = 15;
  var root = document.documentElement;
  var canvas = document.querySelector("[data-scene-canvas]");
  var skip = document.querySelector("[data-skip-intro]");
  var meter = document.querySelector("[data-intro-bar]");
  var reduceQuery = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;

  // Only claim the canvas when a 2d context really exists. Where it does not
  // (jsdom, old browsers, blocked canvas), the CSS/SVG scene is the story and
  // the page is pinned to its finished frame.
  function canvasAvailable() {
    if (!canvas || typeof canvas.getContext !== "function") { return false; }
    try {
      return !!canvas.getContext("2d");
    } catch (error) {
      return false;
    }
  }
  var hasCanvas = canvasAvailable();
  var staticMode = !!(reduceQuery && reduceQuery.matches) || !hasCanvas;
  if (hasCanvas) { root.classList.add("js"); }
  var start = 0;
  var raf = 0;
  var finished = false;

  function pin() {
    root.classList.add("is-static");
    if (skip) {
      skip.textContent = "Intro skipped";
      skip.disabled = true;
      skip.setAttribute("aria-disabled", "true");
    }
  }

  // ---------------------------------------------------------------- geometry
  var nodes = [];
  var edges = [];
  var packets = [];
  var W = 0, H = 0, DPR = 1;
  var ctx = null;

  function reseed() {
    var count = Math.max(18, Math.min(30, Math.round(W / 58)));
    nodes = [];
    edges = [];
    for (var i = 0; i < count; i += 1) {
      nodes.push({
        x: (0.06 + 0.88 * ((i * 0.6180339887) % 1)) * W,
        y: (0.12 + 0.76 * (((i * 0.3819660113) + 0.17) % 1)) * H,
        r: 1.6 + (i % 3) * 0.9,
        phase: (i * 0.7) % Math.PI * 2
      });
    }
    for (var a = 0; a < nodes.length; a += 1) {
      for (var b = a + 1; b < nodes.length; b += 1) {
        var dx = nodes[a].x - nodes[b].x;
        var dy = nodes[a].y - nodes[b].y;
        if (dx * dx + dy * dy < Math.pow(Math.min(W, H) * 0.19, 2)) {
          edges.push([a, b]);
        }
      }
    }
    packets = [];
    for (var p = 0; p < 7; p += 1) {
      packets.push({ edge: p % Math.max(edges.length, 1), t: (p * 0.19) % 1, speed: 0.34 + (p % 3) * 0.09 });
    }
  }

  function resize() {
    if (!canvas) { return; }
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    var rect = canvas.getBoundingClientRect();
    W = Math.max(rect.width, 320);
    H = Math.max(rect.height, 320);
    canvas.width = Math.round(W * DPR);
    canvas.height = Math.round(H * DPR);
    try {
      ctx = canvas.getContext("2d");
    } catch (error) {
      ctx = null;                       // no canvas engine: the CSS scene stands in
    }
    if (!ctx) {
      staticMode = true;
      return;
    }
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    reseed();
  }

  // ------------------------------------------------------------------- draw
  function ease(x) { return x < 0 ? 0 : x > 1 ? 1 : x * x * (3 - 2 * x); }
  function clamp01(x) { return x < 0 ? 0 : x > 1 ? 1 : x; }
  function band(t, from, to) { return clamp01((t - from) / (to - from)); }

  function drawEdges(t, alpha) {
    var drawn = band(t, 0.4, 3.0);
    ctx.lineWidth = 1;
    for (var i = 0; i < edges.length; i += 1) {
      var e = edges[i];
      var a = nodes[e[0]], b = nodes[e[1]];
      var local = clamp01(drawn * edges.length - i);
      if (local <= 0) { continue; }
      ctx.strokeStyle = "rgba(96, 158, 204, " + (0.16 * alpha * local).toFixed(3) + ")";
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(a.x + (b.x - a.x) * local, a.y + (b.y - a.y) * local);
      ctx.stroke();
    }
  }

  function drawNodes(t, alpha) {
    for (var i = 0; i < nodes.length; i += 1) {
      var n = nodes[i];
      var appear = clamp01((t - 0.2) / 2.2) * nodes.length - i;
      if (appear <= 0) { continue; }
      var glow = 0.35 + 0.25 * Math.sin(t * 1.6 + n.phase);
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(120, 200, 255, " + ((0.5 + glow) * alpha).toFixed(3) + ")";
      ctx.fill();
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + 3.5, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(76, 194, 255, " + (0.12 * alpha).toFixed(3) + ")";
      ctx.stroke();
    }
  }

  function drawPackets(t, alpha) {
    if (t < 3.0 || t > 10.5 || !edges.length) { return; }
    var fade = 1;
    if (t > 6.5) { fade = 0.55; }
    for (var i = 0; i < packets.length; i += 1) {
      var p = packets[i];
      p.t += p.speed * 0.006;
      if (p.t > 1) {
        p.t = 0;
        p.edge = (p.edge + 3) % edges.length;
      }
      var e = edges[p.edge];
      if (!e) { continue; }
      var a = nodes[e[0]], b = nodes[e[1]];
      var x = a.x + (b.x - a.x) * p.t;
      var y = a.y + (b.y - a.y) * p.t;
      var danger = t > 6.2 && i === 0;
      var color = danger ? "255, 107, 107" : "76, 194, 255";
      var grad = ctx.createRadialGradient(x, y, 0, x, y, 12);
      grad.addColorStop(0, "rgba(" + color + ", " + (0.95 * alpha * fade) + ")");
      grad.addColorStop(1, "rgba(" + color + ", 0)");
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(x, y, 12, 0, Math.PI * 2);
      ctx.fill();
      ctx.beginPath();
      ctx.arc(x, y, 2.1, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(255,255,255," + (0.9 * alpha * fade) + ")";
      ctx.fill();
    }
  }

  function drawBoundary(t, alpha) {
    var grow = ease(band(t, 6.2, 7.4));
    if (grow <= 0) { return; }
    var y = H * 0.5;
    var half = (W * 0.42) * grow;
    var x0 = W / 2 - half, x1 = W / 2 + half;
    var grad = ctx.createLinearGradient(x0, y, x1, y);
    grad.addColorStop(0, "rgba(255,107,107,0)");
    grad.addColorStop(0.5, "rgba(255,107,107," + (0.55 * alpha) + ")");
    grad.addColorStop(1, "rgba(255,107,107,0)");
    ctx.strokeStyle = grad;
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    ctx.moveTo(x0, y);
    ctx.lineTo(x1, y);
    ctx.stroke();

    var pulse = (t - 3.2) % 1.6 / 1.6;
    ctx.beginPath();
    ctx.arc(W / 2 + half * 0.42, y, 3 + pulse * 14, 0, Math.PI * 2);
    ctx.strokeStyle = "rgba(255,107,107," + (0.45 * (1 - pulse) * alpha) + ")";
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }

  function drawEvidence(t, alpha) {
    var build = ease(band(t, 9.0, 11.4));
    if (build <= 0) { return; }
    var cardW = Math.min(268, W * 0.34);
    var cardH = 96;
    var cx = W / 2, cy = H * 0.56;
    var left = cx - cardW / 2, top = cy - cardH / 2;

    ctx.save();
    ctx.globalAlpha = 0.9 * alpha * build;
    roundRect(left, top, cardW, cardH, 10);
    ctx.fillStyle = "rgba(9, 18, 27, 0.86)";
    ctx.fill();
    ctx.strokeStyle = "rgba(76, 194, 255, 0.35)";
    ctx.lineWidth = 1;
    ctx.stroke();

    for (var i = 0; i < 4; i += 1) {
      var appear = clamp01((build - i * 0.18) / 0.4);
      if (appear <= 0) { continue; }
      var rowY = top + 20 + i * 19;
      ctx.fillStyle = "rgba(150, 190, 220, " + (0.55 * appear) + ")";
      ctx.fillRect(left + 16, rowY, 54 * appear, 4);
      ctx.fillStyle = "rgba(76, 194, 255, " + (0.75 * appear) + ")";
      ctx.fillRect(left + 82, rowY, (cardW - 108) * appear * (0.5 + 0.12 * i), 4);
    }
    ctx.restore();

    // fragments flying in
    for (var f = 0; f < 3; f += 1) {
      var p = clamp01((t - 9.0 - f * 0.35) / 2.0);
      if (p <= 0) { continue; }
      var sx = W * (0.18 + f * 0.3), sy = H * (0.82 - f * 0.1);
      var x = sx + (left + 30 - sx) * ease(p);
      var y = sy + (top + 24 + f * 19 - sy) * ease(p);
      ctx.fillStyle = "rgba(140, 205, 245, " + (0.5 * (1 - ease(p)) + 0.2) * alpha + ")";
      ctx.fillRect(x, y, 26, 3);
    }
  }

  function drawBrand(t, alpha) {
    var build = ease(band(t, 11.6, 13.4));
    if (build <= 0) { return; }
    ctx.save();
    ctx.globalAlpha = build * alpha;
    var g = ctx.createRadialGradient(W / 2, H * 0.5, 0, W / 2, H * 0.5, Math.min(W, H) * 0.42);
    g.addColorStop(0, "rgba(76, 194, 255, 0.16)");
    g.addColorStop(1, "rgba(76, 194, 255, 0)");
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, W, H);
    ctx.restore();
  }

  function roundRect(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }

  function frame(t) {
    if (!ctx) { return; }
    ctx.clearRect(0, 0, W, H);
    var alpha = 1;
    drawEdges(t, alpha);
    drawNodes(t, alpha);
    drawBoundary(t, alpha);
    drawPackets(t, alpha);
    drawEvidence(t, alpha);
    drawBrand(t, alpha);
  }

  // ---------------------------------------------------------------- control
  function loop(now) {
    if (finished || staticMode) { return; }
    if (!start) { start = now; }
    var t = (now - start) / 1000;
    if (t >= DURATION) {
      frame(DURATION);
      stop(true);
      return;
    }
    frame(t);
    if (meter) { meter.style.width = Math.min(100, (t / DURATION) * 100) + "%"; }
    raf = window.requestAnimationFrame(loop);
  }

  function stop(completed) {
    finished = true;
    if (raf) { window.cancelAnimationFrame(raf); raf = 0; }
    if (completed) {
      root.classList.add("intro-done");
      if (meter) { meter.style.width = "100%"; }
    }
  }

  function skipIntro() {
    stop(false);
    frame(13.0);
    pin();
  }

  if (skip) { skip.addEventListener("click", skipIntro); }
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") { skipIntro(); }
  });
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      stop(false);
    } else if (!finished && !staticMode) {
      start = 0;
      raf = window.requestAnimationFrame(loop);
    }
  });

  window.addEventListener("resize", function () {
    resize();
    if (finished || staticMode) { frame(13.0); }
  });

  if (staticMode) {
    // Reduced motion (or no canvas support): the CSS scene stands in, pinned to
    // its finished frame by `pin()`.
    pin();
    if (hasCanvas) { resize(); frame(13.0); }
  } else {
    resize();
    raf = window.requestAnimationFrame(loop);
  }
})();

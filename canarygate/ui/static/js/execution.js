/* CanaryGate execution view.
 *
 * Polls the job transcript that the server produced from real transport events.
 * It draws nothing the server did not send: every feed line is an event object,
 * and the stage list is advanced by the stage named on those events.
 */
(function () {
  "use strict";

  var root = document.querySelector("[data-job]");
  if (!root) { return; }

  var jobId = root.getAttribute("data-job");
  var since = 0;
  var started = Date.now();
  var finished = false;

  var feed = root.querySelector("[data-feed]");
  var stages = root.querySelectorAll("[data-stages] li");
  var opState = root.querySelector("[data-op-state]");
  var opLast = root.querySelector("[data-op-last]");
  var opNote = root.querySelector("[data-op-note]");
  var opActor = root.querySelector("[data-op-actor]");
  var opOwner = root.querySelector("[data-op-owner]");
  var opPair = root.querySelector("[data-op-pair]");
  var nodeActor = root.querySelector("[data-node-actor]");
  var nodeOwner = root.querySelector("[data-node-owner]");
  var flows = root.querySelectorAll("[data-flow]");
  var elapsed = root.querySelector("[data-elapsed]");
  var title = root.querySelector("[data-engine-title]");
  var sub = root.querySelector("[data-engine-sub]");
  var terminalBox = root.querySelector("[data-terminal]");
  var statRequests = root.querySelector(".engine-stats .stat-value");

  // The server already rendered the events it had; skip them on the first poll.
  var lastSeq = -1;
  Array.prototype.forEach.call(feed ? feed.children : [], function (row, index) {
    lastSeq = index;
  });
  since = lastSeq + 1;

  function tickElapsed() {
    if (finished || !elapsed) { return; }
    elapsed.textContent = ((Date.now() - started) / 1000).toFixed(1) + " s";
  }
  setInterval(tickElapsed, 200);

  function statusClass(code) {
    if (!code) { return ""; }
    if (code >= 500) { return "s-500"; }
    if (code >= 400) { return "s-400"; }
    return "s-200";
  }

  function addEvent(event) {
    if (!feed) { return; }
    var li = document.createElement("li");
    li.className = "ev ev-" + event.kind;
    var time = document.createElement("span");
    time.className = "ev-time mono";
    time.textContent = (event.t_ms / 1000).toFixed(0) + "s";
    var label = document.createElement("span");
    label.className = "ev-label";
    label.textContent = event.label;
    li.appendChild(time);
    li.appendChild(label);
    if (event.status !== undefined && event.status !== null) {
      var st = document.createElement("span");
      st.className = "ev-status mono " + statusClass(event.status);
      st.textContent = event.status;
      li.appendChild(st);
    }
    if (event.detail) {
      var d = document.createElement("span");
      d.className = "ev-detail";
      d.textContent = event.detail;
      li.appendChild(d);
    }
    feed.appendChild(li);
    feed.scrollTop = feed.scrollHeight;

    if (event.kind === "request") {
      if (opLast) {
        opLast.textContent = event.method + " " + event.path + " · " + event.status;
      }
      if (opNote) {
        opNote.textContent = "Received " + event.status + " from " + event.actor +
          " in " + Math.round(event.elapsed_ms) + " ms.";
      }
      if (flows.length) {
        flows[0].classList.add("is-hot");
      }
    }
    if (event.kind === "stage" && event.stage) {
      markStage(event.stage);
      if (event.stage === "pair" && event.actor && event.owner) {
        if (opActor) { opActor.textContent = event.actor; }
        if (opOwner) { opOwner.textContent = event.owner; }
        if (opPair) { opPair.textContent = event.actor + " → " + event.owner; }
        if (nodeActor) { nodeActor.textContent = event.actor; }
        if (nodeOwner) { nodeOwner.textContent = event.owner; }
        if (opState) { opState.textContent = "in progress"; }
      }
    }
    if (event.kind === "result" && flows.length) {
      flows[0].classList.add("is-done");
    }
  }

  function markStage(name) {
    var names = ["queued", "authentication", "identity", "ownership", "authorization",
                 "secure comparison", "interaction", "stored"];
    var target = names.indexOf(name);
    Array.prototype.forEach.call(stages, function (li) {
      var stage = li.getAttribute("data-stage");
      var index = names.indexOf(stage);
      if (index === -1) { return; }
      if (index < target) {
        li.classList.remove("is-active");
        li.classList.add("is-done");
        li.querySelector("em").textContent = "done";
      } else if (index === target) {
        li.classList.add("is-active");
        li.querySelector("em").textContent = "now";
      }
    });
  }

  var TERMINAL = {
    complete: {
      title: "Assessment complete.",
      sub: "stored evidence"
    },
    partial: {
      title: "Assessment partially complete.",
      sub: "some runs stored"
    },
    failed: {
      title: "Assessment did not complete.",
      sub: "no run stored"
    }
  };

  function setText(node, value) {
    if (node) { node.textContent = value; }
  }

  function fillTerminal(snapshot) {
    if (!terminalBox) { return; }
    var state = snapshot.status;
    var copy = TERMINAL[state] || TERMINAL.failed;
    terminalBox.setAttribute("data-terminal", state);
    terminalBox.setAttribute("data-tone", state === "complete" ? "ok" : "warn");
    var alert = terminalBox.querySelector(".alert");
    if (alert) {
      alert.className = "alert " + (state === "complete" ? "alert-ok" : "alert-warn");
    }
    setText(terminalBox.querySelector("[data-terminal-title]"), copy.title);
    var stored = (snapshot.results || []).length;
    var total = (snapshot.steps || []).length;
    setText(terminalBox.querySelector("[data-terminal-detail]"),
      state === "complete"
        ? stored + " of " + total + " runs stored · " + snapshot.requests_sent +
          " requests sent"
        : (snapshot.error || "The engine stopped before storing a run."));

    var failure = snapshot.failure || {};
    var hint = terminalBox.querySelector("[data-terminal-hint]");
    if (hint) {
      if (failure.hint) { hint.textContent = failure.hint; hint.hidden = false; }
      else { hint.hidden = true; }
    }

    var pairs = terminalBox.querySelector("[data-terminal-pairs]");
    if (pairs) {
      while (pairs.firstChild) { pairs.removeChild(pairs.firstChild); }
      (failure.failed_pairs || []).forEach(function (pair) {
        var li = document.createElement("li");
        var name = document.createElement("b");
        name.textContent = pair.label;
        li.appendChild(name);
        li.appendChild(document.createTextNode(" — " + pair.detail));
        pairs.appendChild(li);
      });
      pairs.hidden = !(failure.failed_pairs || []).length;
    }

    var links = terminalBox.querySelectorAll("[data-terminal-link]");
    var run = (snapshot.results || [])[0];
    var primary = (state === "complete" && run && snapshot.kind !== "demo")
      ? "/ui/lab/" + (snapshot.kind === "sci" ? "sci" : "bola") + "/" + run.run_id
      : (state === "failed" ? "/ui/assessment" : "/ui/lab/matrix");
    if (links.length) { links[0].href = primary; }

    var retry = terminalBox.querySelector("[data-retry]");
    if (retry) { retry.hidden = state === "complete"; }
    terminalBox.hidden = false;
  }

  function finish(snapshot) {
    finished = true;
    root.setAttribute("data-status", snapshot.status);
    if (snapshot.requests_sent !== undefined && statRequests) {
      statRequests.textContent = snapshot.requests_sent;
    }
    var state = snapshot.status === "complete" ? "complete"
      : (snapshot.status === "partial" ? "partial" : "failed");
    var heading = TERMINAL[state].title.replace(/\.$/, "");
    if (title) { title.textContent = heading; }
    // The tab must not keep saying "in progress" after the engine stopped.
    document.title = heading + " · CanaryGate";
    if (opState) { opState.textContent = state; }
    if (state === "complete") {
      markStage("stored");
      if (flows.length) { flows[0].classList.add("is-done"); }
    }
    fillTerminal(snapshot);
    if (sub) { sub.textContent = TERMINAL[state].sub; }

    // Only a completed run navigates: a partial or stopped run stays put so the
    // reason and the next step are read, not skipped.
    if (state === "complete") {
      var first = (snapshot.results || [])[0];
      var target = (first && snapshot.kind !== "demo")
        ? "/ui/lab/" + (snapshot.kind === "sci" ? "sci" : "bola") + "/" + first.run_id
        : "/ui/lab/matrix";
      window.setTimeout(function () { window.location.assign(target); }, 1200);
    }
  }

  function poll() {
    if (finished) { return; }
    fetch("/ui/execution/" + encodeURIComponent(jobId) + "/events?since=" + since,
          { headers: { "Accept": "application/json" } })
      .then(function (response) {
        if (!response.ok) { throw new Error("HTTP " + response.status); }
        return response.json();
      })
      .then(function (snapshot) {
        (snapshot.events || []).forEach(addEvent);
        since = snapshot.next;
        if (statRequests && snapshot.requests_sent !== undefined) {
          statRequests.textContent = snapshot.requests_sent;
        }
        if (snapshot.status !== "running") { finish(snapshot); return; }
        window.setTimeout(poll, 400);
      })
      .catch(function () {
        // A transient failure is retried; the page never invents progress.
        if (!finished) { window.setTimeout(poll, 1200); }
      });
  }

  if (root.getAttribute("data-status") === "running") {
    window.setTimeout(poll, 200);
  } else {
    finished = true;
  }
})();

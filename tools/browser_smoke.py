#!/usr/bin/env python3
"""Browser-level smoke test for the interface, run against a real server.

Why this exists
---------------
The pytest suite asserts served HTML. It cannot show that the page's own
JavaScript initialises, that HTMX actually posts a form and swaps the returned
fragment into the DOM, or that the links the browser ends up with point at runs
the API stored. This script drives the real pages in a DOM with scripts enabled
(jsdom) against a real uvicorn server and a real TLS TargetLab, then compares what
the browser saw with the JSON API.

What it is not
--------------
jsdom has no layout engine and no paint step. It proves script execution, DOM
state, HTMX round-trips and link wiring; it says nothing about pixels, CSS
cascade, focus rings or print output. A real browser was not installable in this
environment (no Chromium/Firefox binary; `libnss3`, `libnspr4`, `libnssutil3`,
`libatk` and `libcups` are absent and there is no root to install them).

Requirements
------------
* Node.js (tested with v22) and jsdom 24 (`npm install jsdom`), which is not a
  dependency of the application. Point the script at it with ``--jsdom`` (the
  directory *containing* ``node_modules``) or ``NODE_PATH``.
* The repository's virtualenv, so ``python -m targetlab`` and uvicorn resolve.

Usage
-----
    .venv/bin/python tools/browser_smoke.py --jsdom /tmp/browser-harness

Exit codes: 0 all checks passed, 1 a check failed, 2 the environment cannot run
it (node or jsdom missing). Nothing here touches a network beyond 127.0.0.1.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CERT = ROOT / "tests" / "fixtures" / "tls" / "targetlab-cert.pem"
KEY = ROOT / "tests" / "fixtures" / "tls" / "targetlab-key.pem"


def free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def get(url: str, *, insecure: bool = False, timeout: float = 5.0) -> tuple[int, str]:
    context = None
    if insecure:
        context = ssl.create_default_context(cafile=str(CERT))
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:  # a real status is still an answer
        return exc.code, exc.read().decode("utf-8", "replace")


def wait_for(url: str, *, insecure: bool = False, seconds: float = 30.0) -> None:
    deadline = time.time() + seconds
    last = ""
    while time.time() < deadline:
        try:
            status, _ = get(url, insecure=insecure, timeout=1.0)
            if status < 500:
                return
        except Exception as exc:  # noqa: BLE001 - startup polling
            last = str(exc)
        time.sleep(0.2)
    raise SystemExit(f"server did not answer {url} in time: {last}")


def node_available(jsdom_root: str | None) -> str | None:
    env = dict(os.environ)
    if jsdom_root:
        env["NODE_PATH"] = str(Path(jsdom_root) / "node_modules")
    node = shutil_which("node")
    if not node:
        return None
    probe = subprocess.run([node, "-e", "require('jsdom'); process.stdout.write('ok')"],
                           capture_output=True, text=True, env=env, cwd=jsdom_root or None)
    if probe.returncode != 0 or "ok" not in probe.stdout:
        return None
    return node


def shutil_which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


DRIVER = r"""
const path = require('path');
const { JSDOM, VirtualConsole } = require('jsdom');

const base = process.argv[2];
const labPort = process.argv[3];
const marker = '__SMOKE__';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// jsdom does not implement XPathResult's constants, so htmx's XPath helper throws
// inside jsdom while behaving normally everywhere else. Record it separately from
// real page errors so a genuine regression cannot hide behind it.
const KNOWN_JSDOM_NOISE = /You must provide an XPath result type/;

async function open(url) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => errors.push(String(e.message || e)));
  vc.on('error', (...args) => errors.push(args.join(' ')));
  const dom = await JSDOM.fromURL(url, {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true, virtualConsole: vc,
  });
  const w = dom.window;
  await new Promise((r) => (w.document.readyState === 'complete' ? r() : w.addEventListener('load', r, { once: true })));
  await sleep(150);
  return { dom, w, errors };
}

async function submitAndWait(w, form, panelSelector, pattern, seconds = 120) {
  form.dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true }));
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    const panel = w.document.querySelector(panelSelector);
    const text = panel ? panel.innerHTML : '';
    const match = text.match(pattern);
    if (match) return match[0];
    await sleep(200);
  }
  return null;
}

(async () => {
  const facts = { pages: [], client: {}, runs: {}, errors: [] };

  // 1. Dashboard: scripts run, HTMX is live, nothing external is requested.
  const dash = await open(base + '/ui/');
  const dw = dash.w;
  facts.pages.push({
    path: '/ui/',
    title: dw.document.title,
    h1: (dw.document.querySelector('h1') || {}).textContent?.trim(),
    htmx: !!(dw.window || dw).htmx,
    banner: dw.document.body.innerHTML.includes('Local evidence only'),
    external: !!dw.document.body.innerHTML.match(/(?:src|href)\s*=\s*["'](?:https?:)?\/\//i),
    scripts: dw.document.querySelectorAll('script').length,
  });

  // 2. Client-side behaviour that only exists in the browser: nav toggle + filter.
  const toggle = dw.document.querySelector('[data-nav-toggle]');
  const nav = dw.document.querySelector('[data-nav]');
  if (toggle && nav) {
    toggle.click();
    facts.client.nav_toggle_expanded = toggle.getAttribute('aria-expanded');
    toggle.click();
    facts.client.nav_toggle_restored = toggle.getAttribute('aria-expanded');
  }

  // 3. Fixture scan through the dashboard form (HTMX posts, DOM swaps).
  const fixtureForm = dw.document.querySelector('form[hx-post="/ui/actions/fixture-scan"]');
  const fixtureLink = fixtureForm
    ? await submitAndWait(dw, fixtureForm, '#scan-panel', /\/ui\/scans\/[0-9a-f-]{36}/, 60)
    : null;
  facts.runs.fixture_id = fixtureLink ? fixtureLink.split('/').pop() : null;

  // 4. Endpoints page: the table filter hides non-matching rows.
  const endpoints = await open(base + '/ui/endpoints');
  const filter = endpoints.w.document.querySelector('[data-table-filter]');
  if (filter) {
    const table = endpoints.w.document.querySelector(filter.getAttribute('data-table-filter'));
    const rows = table ? [...table.querySelectorAll('[data-filter-row]')] : [];
    const before = rows.filter((r) => !r.hidden).length;
    const counter = table && table.closest('.card') ? table.closest('.card').querySelector('[data-filter-count]') : null;
    filter.value = 'zzz-nothing-matches';
    filter.dispatchEvent(new endpoints.w.Event('input', { bubbles: true }));
    const after = rows.filter((r) => !r.hidden).length;
    facts.client.table_filter = {
      rows: rows.length, visible_before: before, visible_after: after,
      counter: counter ? counter.textContent.trim() : null,
    };
  }

  // 5. TargetLab: submit each workflow through the page's own form.
  const lab = await open(base + '/ui/lab');
  const lw = lab.w;
  facts.pages.push({
    path: '/ui/lab',
    title: lw.document.title,
    ca_ready: !lw.document.body.innerHTML.includes('CANARYGATE_TARGETLAB_CA is not set'),
  });
  const labRuns = {};
  for (const [name, action, panelPattern, panel] of [
    ['bola', '/ui/actions/lab-bola-scan', /\/ui\/lab\/bola\/[0-9a-f-]{36}/, '#lab-panel'],
    ['sci', '/ui/actions/lab-sci-scan', /\/ui\/lab\/sci\/[0-9a-f-]{36}/, '#lab-panel'],
    ['reset', '/ui/actions/lab-sci-reset', /\/ui\/lab\/reset\/[0-9a-f-]{36}/, '#lab-panel'],
  ]) {
    const page = name === 'bola' ? { w: lw } : await open(base + '/ui/lab');
    const form = page.w.document.querySelector(`form[hx-post="${action}"]`);
    if (!form) { facts.errors.push('missing form for ' + name); continue; }
    form.querySelector('input[name="port"]').value = labPort;
    const link = await submitAndWait(page.w, form, panel, panelPattern, 180);
    labRuns[name] = link ? link.split('/').pop() : null;
    if (page.w !== lw) page.w.close();
  }
  facts.runs.lab = labRuns;

  // 6. The pages the browser was sent to actually contain the stored evidence.
  const bola = await open(`${base}/ui/lab/bola/${labRuns.bola}`);
  facts.pages.push({
    path: '/ui/lab/bola/…',
    h1: (bola.w.document.querySelector('h1') || {}).textContent?.trim(),
    checks: [...new Set([...bola.w.document.querySelectorAll('td,th')]
      .map((n) => n.textContent.trim()).filter((t) => /^LAB-BOLA-0[1-6]$/.test(t)))],
    summary: Object.fromEntries(
      [...bola.w.document.querySelectorAll('section[aria-label="Check summary"] .stat, '
        + 'section[aria-label="Other check outcomes"] .stat')].map((s) => [
        s.querySelector('.stat-label').textContent.trim(),
        Number(s.querySelector('.stat-value').textContent.trim()),
      ])),
    ground_truth: bola.w.document.body.innerHTML.includes('Ground truth'),
  });

  const sci = await open(`${base}/ui/lab/sci/${labRuns.sci}`);
  const sciHtml = sci.w.document.body.innerHTML;
  facts.pages.push({
    path: '/ui/lab/sci/…',
    has_403: sciHtml.includes('403'), has_401: sciHtml.includes('401'), has_200: sciHtml.includes('200'),
    attribution: sciHtml.includes('interaction_induced'),
  });

  const reset = await open(`${base}/ui/lab/reset/${labRuns.reset}`);
  const resetHtml = reset.w.document.body.innerHTML;
  facts.pages.push({
    path: '/ui/lab/reset/…',
    proven: resetHtml.includes('proven'),
    checks: ['RESET-01', 'RESET-02', 'RESET-03', 'RESET-04'].filter((c) => resetHtml.includes(c)),
  });

  // 7a. The TargetLab asset matrix: nine cells, and a selected cell links real evidence.
  const assetMatrix = await open(base + '/ui/lab/matrix');
  const assetTable = assetMatrix.w.document.querySelector('table.matrix');
  const cellLinks = assetTable ? [...assetTable.querySelectorAll('a.cell-link')] : [];
  const selectedMatrix = await open(base + '/ui/lab/matrix?cell=mallapa:BRD-2026-018');
  const selectedCell = selectedMatrix.w.document.querySelector('td.is-selected');
  const runLink = selectedMatrix.w.document.querySelector('a[href*="/ui/lab/bola/"][href*="#LAB-BOLA-"]');
  facts.pages.push({
    path: '/ui/lab/matrix',
    cells: cellLinks.length,
    untested: assetTable ? assetTable.querySelectorAll('.badge-empty').length : -1,
    verdicts: assetTable ? assetTable.querySelectorAll('.badge-confirmed').length : -1,
    selected: selectedCell ? 1 : 0,
    run_link: runLink ? runLink.getAttribute('href') : null,
    detail_run: selectedMatrix.w.document.body.textContent.includes('Source run'),
  });
  assetMatrix.w.close();
  selectedMatrix.w.close();

  // 7b. Matrix and the fixture report.
  const matrix = await open(base + '/ui/matrix');
  const matrixHtml = matrix.w.document.body.innerHTML;
  facts.pages.push({
    path: '/ui/matrix',
    partial: matrixHtml.includes('partial_offline') || matrixHtml.toLowerCase().includes('partial'),
    hatched: matrixHtml.includes('hatched'),
    columns: ['anonymous', 'own resource', 'other account resource', 'role'].filter((c) => matrixHtml.includes(c)),
  });

  if (facts.runs.fixture_id) {
    const report = await open(`${base}/ui/scans/${facts.runs.fixture_id}/report`);
    const reportText = report.w.document.body.textContent;
    facts.pages.push({
      path: '/ui/scans/{id}/report',
      sections: ['executive summary', 'evidence', 'constraint checklist'].filter((s) => reportText.toLowerCase().includes(s)),
      h1: (report.w.document.querySelector('h1') || {}).textContent?.trim(),
    });
    report.w.close();
  }

  for (const page of [dash, endpoints, lab, bola, sci, reset, matrix]) {
    for (const error of page.errors) {
      if (KNOWN_JSDOM_NOISE.test(error)) { facts.known_jsdom_noise = (facts.known_jsdom_noise || 0) + 1; continue; }
      facts.errors.push(error);
    }
    page.w.close();
  }

  process.stdout.write('\n' + marker + JSON.stringify(facts) + '\n');
})().catch((e) => { console.error('DRIVER FAILED', e && e.stack); process.exit(1); });
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--jsdom", default=os.environ.get("NODE_PATH", "").replace("/node_modules", "") or None,
                        help="directory containing node_modules with jsdom")
    parser.add_argument("--keep", action="store_true", help="print the database path and do not delete it")
    args = parser.parse_args(argv)

    node = node_available(args.jsdom)
    if not node:
        print("SKIPPED: node with jsdom is required for the browser smoke test.")
        print("  npm install --prefix /tmp/browser-harness jsdom")
        print("  .venv/bin/python tools/browser_smoke.py --jsdom /tmp/browser-harness")
        return 2

    env = dict(os.environ)
    if args.jsdom:
        env["NODE_PATH"] = str(Path(args.jsdom) / "node_modules")

    lab_port, app_port = free_port(), free_port()
    holder = tempfile.TemporaryDirectory(prefix="canarygate-browser-")
    database = Path(holder.name) / "browser.sqlite3"

    lab = subprocess.Popen(
        [sys.executable, "-m", "targetlab", "--port", str(lab_port),
         "--tls-cert", str(CERT), "--tls-key", str(KEY)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    app_env = {**env, "CANARYGATE_TARGETLAB_CA": str(CERT), "CANARYGATE_DB_PATH": str(database)}
    app = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "canarygate.ui.app:app",
         "--host", "127.0.0.1", "--port", str(app_port), "--log-level", "warning"],
        cwd=ROOT, env=app_env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )

    try:
        wait_for(f"http://127.0.0.1:{app_port}/api/health")
        wait_for(f"https://127.0.0.1:{lab_port}/", insecure=True, seconds=20)
        print(f"servers: app http://127.0.0.1:{app_port} · lab https://127.0.0.1:{lab_port} · db {database}")

        driver = Path(holder.name) / "driver.js"
        driver.write_text(DRIVER, encoding="utf-8")
        run = subprocess.run([node, str(driver), f"http://127.0.0.1:{app_port}", str(lab_port)],
                             capture_output=True, text=True, env=env, cwd=ROOT, timeout=600)
        marker = "__SMOKE__"
        payload = next((line[len(marker):] for line in run.stdout.splitlines()
                        if line.startswith(marker)), None)
        if not payload:
            print("driver produced no result; stdout/stderr follows")
            print(run.stdout[-4000:])
            print(run.stderr[-4000:])
            return 1
        facts = json.loads(payload)

        # Independent comparison: read the same runs from the JSON API.
        api = f"http://127.0.0.1:{app_port}"
        fixture_id = facts["runs"].get("fixture_id")
        api_run = json.loads(get(f"{api}/api/scan/{fixture_id}")[1]) if fixture_id else None
        bola_id = facts["runs"]["lab"].get("bola")
        api_bola = json.loads(get(f"{api}/api/lab-bola-scans/{bola_id}")[1]) if bola_id else None
        sci_id = facts["runs"]["lab"].get("sci")
        api_sci = json.loads(get(f"{api}/api/lab-sci-scans/{sci_id}")[1]) if sci_id else None
        reset_id = facts["runs"]["lab"].get("reset")
        api_reset = json.loads(get(f"{api}/api/lab-sci-resets/{reset_id}")[1]) if reset_id else None
        matrix = json.loads(get(f"{api}/api/authorization-matrix")[1])

        pages = {page["path"]: page for page in facts["pages"]}
        checks: list[tuple[str, bool, str]] = []

        def check(name: str, ok: bool, detail: str = "") -> None:
            checks.append((name, bool(ok), detail))

        dash_facts = pages["/ui/"]
        check("dashboard loads with its own scripts",
              bool(dash_facts.get("htmx")) and bool(dash_facts.get("h1"))
              and "Dashboard" in (dash_facts.get("title") or ""),
              f"title={dash_facts.get('title')!r} h1={dash_facts.get('h1')!r} htmx={dash_facts.get('htmx')}")
        check("dashboard makes no external request", dash_facts.get("external") is False)
        check("banner is present in the browser", dash_facts.get("banner") is True)
        check("nav toggle changes aria-expanded",
              facts["client"].get("nav_toggle_expanded") == "true"
              and facts["client"].get("nav_toggle_restored") == "false",
              str(facts["client"].get("nav_toggle_expanded")) + "→" + str(facts["client"].get("nav_toggle_restored")))
        filt = facts["client"].get("table_filter") or {}
        check("table filter hides non-matching rows",
              filt.get("visible_before", 0) > 0 and filt.get("visible_after") == 0, str(filt))

        check("HTMX fixture form stored a run and linked it",
              bool(fixture_id) and api_run is not None and api_run.get("id") == fixture_id,
              f"run={fixture_id}")
        run_page = pages.get("/ui/scans/{id}/report", {})
        check("fixture report page shows the backend sections",
              len(run_page.get("sections", [])) >= 3, str(run_page.get("sections")))

        bola_page = pages["/ui/lab/bola/…"]
        check("BOLA page lists all six checks", len(bola_page.get("checks", [])) == 6,
              str(bola_page.get("checks")))
        page_summary = bola_page.get("summary") or {}
        api_summary = (api_bola or {}).get("summary") or {}
        expected = {"Checks": api_summary.get("total"), "CONFIRMED": api_summary.get("confirmed"),
                    "SAFE": api_summary.get("safe"), "SUSPECTED": api_summary.get("suspected"),
                    "INCONCLUSIVE": api_summary.get("inconclusive"), "SKIPPED": api_summary.get("skipped")}
        check("BOLA summary on the page equals the API summary",
              bool(expected["Checks"]) and page_summary == expected,
              f"page={page_summary} api={expected}")
        check("BOLA page shows ground truth", bola_page.get("ground_truth") is True)

        sci_page = pages["/ui/lab/sci/…"]
        check("SCI page shows 403, 401 and 200",
              sci_page.get("has_403") and sci_page.get("has_401") and sci_page.get("has_200"))
        check("SCI page shows the backend attribution",
              sci_page.get("attribution") is True
              and api_sci is not None and api_sci.get("attribution") == "interaction_induced",
              str(api_sci and api_sci.get("attribution")))

        reset_page = pages["/ui/lab/reset/…"]
        check("reset proof shows proven and all four checks",
              reset_page.get("proven") is True and len(reset_page.get("checks", [])) == 4,
              str(reset_page.get("checks")))
        check("reset proof matches the API status",
              api_reset is not None and api_reset.get("status") == "proven")

        matrix_page = pages["/ui/matrix"]
        check("matrix shows partial coverage and every column",
              matrix_page.get("partial") is True and len(matrix_page.get("columns", [])) == 4,
              str(matrix_page.get("columns")))
        asset_matrix = pages["/ui/lab/matrix"]
        check("asset matrix renders nine cells",
              asset_matrix.get("cells") == 9,
              f"cells={asset_matrix.get('cells')} untested={asset_matrix.get('untested')}")
        check("selected asset cell links its stored run and check",
              asset_matrix.get("selected") == 1
              and "/ui/lab/bola/" in (asset_matrix.get("run_link") or "")
              and "#LAB-BOLA-" in (asset_matrix.get("run_link") or "")
              and asset_matrix.get("detail_run") is True,
              str(asset_matrix.get("run_link")))
        check("matrix coverage matches the API",
              matrix["coverage"]["scope"] == "partial_offline",
              f"{matrix['coverage']['rows']}x{matrix['coverage']['cells']} tested={matrix['coverage']['tested']}")
        check("no page-level script error", not facts["errors"], str(facts["errors"])[:400])

        width = max(len(name) for name, _, _ in checks)
        failures = 0
        for name, ok, detail in checks:
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<{width}}  {detail}")
            failures += 0 if ok else 1
        noise = facts.get("known_jsdom_noise", 0)
        print(f"\n  {len(checks) - failures}/{len(checks)} browser checks passed"
              f" · {noise} known jsdom-only XPath notice(s) suppressed")
        if args.keep:
            print(f"  database kept: {database}")
            holder = None  # type: ignore[assignment]
        return 0 if failures == 0 else 1
    finally:
        for process in (app, lab):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    raise SystemExit(main())

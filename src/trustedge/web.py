"""A deliberately small local viewer: ``trustedge serve``.

Scope discipline matters here. TrustEdge's value is the analyser and the
report; a heavy web application would add surface area without adding insight.
So this is one file, standard library only, bound to loopback, with no storage
and no state:

* ``GET /``            - an upload page.
* ``POST /api/analyze`` - takes the export JSON in the request body, returns
  the rendered report fragment plus the machine-readable report.
* ``GET /healthz``      - liveness, for the container health check.

The export you drop in is an IAM authorisation export and is sensitive. It is
parsed in memory, never written to disk by this server, and never leaves the
machine: the page makes no third-party requests and the server makes no
outbound connections at all.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Tuple

from . import report as report_module
from .analyzer import TOOL_NAME, TOOL_VERSION, analyze
from .parser import ExportFormatError, parse_export

#: Refuse anything larger. A real authorisation export for a large account is
#: a few megabytes; this is a local tool, not a service.
MAX_BODY_BYTES = 32 * 1024 * 1024

_UPLOAD_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TrustEdge</title>
<style>__CSS__
.drop { border:2px dashed var(--line); border-radius:10px; padding:2.5rem 1.5rem;
  text-align:center; background:#fff; margin:1.5rem 0; }
.drop.over { border-color:#1a4f8b; background:#f0f6ff; }
.drop input { display:block; margin:1rem auto 0; }
.actions { display:flex; gap:.5rem; flex-wrap:wrap; margin:1rem 0; }
.actions button { font:inherit; padding:.45rem 1rem; border-radius:6px;
  border:1px solid var(--line); background:#fff; cursor:pointer; }
.actions button.primary { background:var(--fg); color:#fff; border-color:var(--fg); }
.actions button[disabled] { opacity:.45; cursor:default; }
.note { color:var(--muted); font-size:.85rem; max-width:70ch; }
.error { border-left:4px solid #8b1a1a; background:#fff5f5; padding:.7rem .9rem;
  border-radius:6px; margin:1rem 0; }
#report:empty { display:none; }
</style></head><body>
<header>
  <h1>TrustEdge</h1>
  <p class="tagline">Who outside this account can become an identity inside it,
  how strong is the guard on that door, and what do they get once through?</p>
  <p class="meta">__TOOL__ __VERSION__ &middot; local viewer, loopback only</p>
</header>

<div class="drop" id="drop">
  <strong>Drop an IAM export here</strong>
  <p class="note">Native TrustEdge export, or raw
  <code>aws iam get-account-authorization-details</code> output. Parsed in
  memory on this machine; nothing is written to disk by this server and nothing
  is sent anywhere.</p>
  <input type="file" id="file" accept=".json,application/json">
</div>

<div class="actions">
  <button id="run" class="primary" disabled>Analyse</button>
  <button id="download-json" disabled>Download JSON report</button>
  <button id="download-html" disabled>Download HTML report</button>
  <label class="note"><input type="checkbox" id="internal"> include
  same-account and compute-attachment trust</label>
</div>

<div id="message"></div>
<div id="report"></div>

<script>__JS__</script>
<script>
(function () {
  var fileInput = document.getElementById('file');
  var drop = document.getElementById('drop');
  var runButton = document.getElementById('run');
  var jsonButton = document.getElementById('download-json');
  var htmlButton = document.getElementById('download-html');
  var internal = document.getElementById('internal');
  var message = document.getElementById('message');
  var reportEl = document.getElementById('report');
  var pendingText = null;
  var lastReport = null;

  function setError(text) {
    message.innerHTML = '';
    if (!text) { return; }
    var box = document.createElement('div');
    box.className = 'error';
    box.textContent = text;
    message.appendChild(box);
  }

  function take(file) {
    if (!file) { return; }
    var reader = new FileReader();
    reader.onload = function () {
      pendingText = String(reader.result);
      runButton.disabled = false;
      setError('');
    };
    reader.onerror = function () { setError('Could not read that file.'); };
    reader.readAsText(file);
  }

  fileInput.addEventListener('change', function () { take(fileInput.files[0]); });

  ['dragenter', 'dragover'].forEach(function (name) {
    drop.addEventListener(name, function (event) {
      event.preventDefault();
      drop.classList.add('over');
    });
  });
  ['dragleave', 'drop'].forEach(function (name) {
    drop.addEventListener(name, function (event) {
      event.preventDefault();
      drop.classList.remove('over');
    });
  });
  drop.addEventListener('drop', function (event) {
    if (event.dataTransfer && event.dataTransfer.files.length) {
      take(event.dataTransfer.files[0]);
    }
  });

  runButton.addEventListener('click', function () {
    if (!pendingText) { return; }
    runButton.disabled = true;
    setError('');
    reportEl.innerHTML = '<p class="note">Analysing&hellip;</p>';
    fetch('/api/analyze?include_internal=' + (internal.checked ? '1' : '0'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: pendingText
    }).then(function (response) {
      return response.json().then(function (payload) {
        return { status: response.status, payload: payload };
      });
    }).then(function (result) {
      runButton.disabled = false;
      if (!result.payload || result.payload.ok !== true) {
        reportEl.innerHTML = '';
        setError((result.payload && result.payload.error) ||
                 ('Analysis failed with status ' + result.status));
        return;
      }
      reportEl.innerHTML = result.payload.html;
      trustedgeWireFilters();
      lastReport = result.payload.report;
      jsonButton.disabled = false;
      htmlButton.disabled = false;
    }).catch(function (error) {
      runButton.disabled = false;
      reportEl.innerHTML = '';
      setError('Request failed: ' + error);
    });
  });

  function saveBlob(text, type, name) {
    var url = URL.createObjectURL(new Blob([text], { type: type }));
    var link = document.createElement('a');
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  jsonButton.addEventListener('click', function () {
    if (!lastReport) { return; }
    saveBlob(JSON.stringify(lastReport, null, 2), 'application/json',
             'trustedge-report.json');
  });

  htmlButton.addEventListener('click', function () {
    if (!reportEl.innerHTML) { return; }
    var page = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
      '<title>TrustEdge report</title><style>' +
      document.querySelector('style').textContent + '</style></head><body>' +
      reportEl.innerHTML + '</body></html>';
    saveBlob(page, 'text/html', 'trustedge-report.html');
  });
})();
</script>
</body></html>
"""


def _upload_page() -> str:
    return (
        _UPLOAD_PAGE.replace("__CSS__", report_module.HTML_CSS)
        .replace("__JS__", report_module.HTML_FILTER_JS)
        .replace("__TOOL__", TOOL_NAME)
        .replace("__VERSION__", TOOL_VERSION)
    )


class TrustEdgeHandler(BaseHTTPRequestHandler):
    server_version = "TrustEdge/" + TOOL_VERSION
    #: Set by :func:`serve` so the handler can honour --quiet.
    quiet = False

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        if not self.quiet:
            super().log_message(fmt, *args)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # This tool only ever renders data the operator just handed it, but a
        # restrictive policy costs nothing and keeps an injected string in an
        # export from reaching the network.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; connect-src 'self'; img-src 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: dict) -> None:
        self._send(
            status,
            json.dumps(payload).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    # -- routes -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(
                200, _upload_page().encode("utf-8"), "text/html; charset=utf-8"
            )
            return
        if path == "/healthz":
            self._send_json(200, {"ok": True, "tool": TOOL_NAME, "version": TOOL_VERSION})
            return
        self._send_json(404, {"ok": False, "error": "not found: %s" % path})

    def do_POST(self) -> None:  # noqa: N802
        path, _, query = self.path.partition("?")
        if path != "/api/analyze":
            self._send_json(404, {"ok": False, "error": "not found: %s" % path})
            return

        body, error = self._read_body()
        if error is not None:
            self._send_json(413 if "too large" in error else 400, {"ok": False, "error": error})
            return

        try:
            document = json.loads(body.decode("utf-8"))
        except UnicodeDecodeError:
            self._send_json(
                400, {"ok": False, "error": "Request body is not valid UTF-8."}
            )
            return
        except ValueError as exc:
            self._send_json(
                400, {"ok": False, "error": "Not valid JSON: %s" % exc}
            )
            return

        include_internal = "include_internal=1" in query

        try:
            export, issues = parse_export(document, source="uploaded export")
            result = analyze(
                export,
                issues=issues,
                input_path="uploaded export",
                include_internal=include_internal,
            )
        except ExportFormatError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:  # pragma: no cover - defensive
            self._send_json(
                500,
                {
                    "ok": False,
                    "error": "Unexpected analyser error (%s: %s). Please open an "
                    "issue with a synthetic export that reproduces it."
                    % (type(exc).__name__, exc),
                },
            )
            return

        self._send_json(
            200,
            {
                "ok": True,
                "html": report_module.render_html_fragment(result),
                "report": result.to_dict(),
            },
        )

    def _read_body(self) -> Tuple[bytes, Optional[str]]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return b"", "Missing Content-Length header."
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            return b"", "Malformed Content-Length header."
        if length <= 0:
            return b"", "Empty request body."
        if length > MAX_BODY_BYTES:
            return b"", "Request body too large (limit %d bytes)." % MAX_BODY_BYTES
        return self.rfile.read(length), None


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def build_server(host: str = "127.0.0.1", port: int = 8765, quiet: bool = False) -> _Server:
    handler = type("BoundHandler", (TrustEdgeHandler,), {"quiet": quiet})
    return _Server((host, port), handler)


def serve(host: str = "127.0.0.1", port: int = 8765, quiet: bool = False) -> int:
    """Run the local viewer until interrupted."""
    server = build_server(host=host, port=port, quiet=quiet)
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    print(
        "TrustEdge viewer on http://%s:%d  (loopback only unless --host was "
        "changed; Ctrl-C to stop)" % (bound_host, bound_port)
    )
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "WARNING: binding to %s exposes this viewer beyond this machine. An "
            "IAM authorisation export is sensitive and this server has no "
            "authentication." % host
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.shutdown()
        server.server_close()
    return 0


__all__ = ["serve", "build_server", "TrustEdgeHandler", "MAX_BODY_BYTES"]

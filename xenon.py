#!/usr/bin/env python3
"""
xenon — encrypted remote execution server.

Receives signed POST requests, verifies an Ed25519 signature over an
expiry timestamp, and executes the requested operation:

  POST /readFile    header X-File-Path (base64 path)  -> raw file bytes
  POST /writeFile   header X-File-Path (base64 path)  -> writes raw body, returns "ok"
  POST /execShell   body {"command": "..."}           -> blocking, returns {"stdout","stderr"}

All three require header X-Signature = base64( ed25519_signature(expiry) + expiry )
where expiry is a unix timestamp string. If the signature is missing, invalid,
or the timestamp has passed, the request is rejected with 403.

GET /                        dashboard listing currently-executing commands
GET /api/jobs                JSON list of running jobs (live output)
POST /api/kill/<job_id>      kill a running job (entire process tree/group)

Usage:  ./server [port]      (default port: 64920)

Cross-platform: Linux, macOS, Windows. Uses the platform default shell
(/bin/sh on POSIX via shell=True, cmd.exe on Windows).

On POSIX, BOTH stdout and stderr are attached to pseudo-terminals so stdio
is line-buffered (like an interactive terminal) and the dashboard can show
live output — several shells (e.g. dash) block-buffer non-tty streams, which
would otherwise hide stderr until process exit. On Windows (no pty module)
both streams use plain pipes, so buffered output may only appear at exit.

A job whose shell has exited but whose background children still hold the
pty open remains in the dashboard (marked "shell exited") until those
children exit or are killed; /execShell returns the output captured so far.
"""

import base64
import os
import signal
import subprocess
import sys
import threading
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import Flask, Response, jsonify, request, send_file

# --------------------------------------------------------------------------
# crypto
# --------------------------------------------------------------------------

# Embedded Ed25519 public key (raw 32 bytes). Only requests signed by the
# matching private key are accepted. Deliberately NOT read from the
# environment — the key is part of the binary.
PUBLIC_KEY = bytes.fromhex("11561b09b5cce1e9da467e2d618149a61d0993caf4445bd09678cd4d2b6765bb")


def decrypt(ciphertext: bytes, publicKey: bytes) -> bytes:
    """Verify the Ed25519 signature over `msg` and return the plaintext."""
    sig, msg = ciphertext[:64], ciphertext[64:]
    Ed25519PublicKey.from_public_bytes(publicKey).verify(sig, msg)
    return msg


def verify_signature():
    """Return the expiry unix timestamp (int) from X-Signature, or None if
    the header is missing, malformed, unsigned by the embedded key, or not an
    int timestamp."""
    raw = request.headers.get("X-Signature")
    if not raw:
        return None
    try:
        blob = base64.b64decode(raw, validate=True)
        if len(blob) < 64:
            return None
        msg = decrypt(blob, PUBLIC_KEY)  # raises InvalidSignature if bad
        return int(msg.strip().decode("utf-8"))
    except Exception:
        return None


def require_signature():
    """Return a 403 response tuple on failure, else None."""
    ts = verify_signature()
    if ts is None or ts < time.time():
        return jsonify(error="forbidden"), 403
    return None


# --------------------------------------------------------------------------
# job registry (used by /execShell and the dashboard)
# --------------------------------------------------------------------------

IS_WINDOWS = os.name == "nt"

JOBS = {}
JOBS_LOCK = threading.Lock()


class Job:
    def __init__(self, command: str):
        self.id = uuid.uuid4().hex[:10]
        self.command = command
        self.started = time.time()
        self.stdout_buf = bytearray()
        self.stderr_buf = bytearray()
        self.proc = None
        self.reader_threads = []
        self.lock = threading.Lock()

    def _pump_pipe(self, stream, buf: bytearray):
        """Read a plain pipe to EOF into buf."""
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            with self.lock:
                buf.extend(chunk)
        try:
            stream.close()
        except Exception:
            pass

    def _pump_pty(self, fd, buf: bytearray):
        """Read a pty master fd until every slave-side fd is closed, into
        buf. Normalizes \\r\\n to \\n (pty line discipline)."""
        while True:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break  # EIO when all child-side fds are closed
            if not data:
                break
            data = data.replace(b"\r\n", b"\n")
            with self.lock:
                buf.extend(data)
        try:
            os.close(fd)
        except OSError:
            pass

    def snapshot(self):
        with self.lock:
            out = bytes(self.stdout_buf).decode("utf-8", errors="replace")
            err = bytes(self.stderr_buf).decode("utf-8", errors="replace")
        return out, err

    @property
    def shell_exited(self):
        return self.proc is not None and self.proc.poll() is not None


def _detach_watchdog(job):
    """Keep a finished shell's job in the registry (visible in the
    dashboard) until its pty readers finish — i.e. until background
    children that inherited the pty are gone — then remove it."""
    def _watch():
        for t in job.reader_threads:
            t.join()
        with JOBS_LOCK:
            JOBS.pop(job.id, None)
    threading.Thread(target=_watch, daemon=True).start()


def spawn(command: str) -> Job:
    """Start `command` in the default shell in its own process group,
    streaming stdout/stderr into a Job."""
    job = Job(command)
    kwargs = dict(
        shell=True,
        stdin=subprocess.DEVNULL,
        close_fds=True,
    )
    if IS_WINDOWS:
        # No pty on Windows: plain pipes (buffered output may only appear
        # at process exit). Own process group for tree kills.
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
        masters = {}
    else:
        # Own session => we can kill the whole process group.
        kwargs["start_new_session"] = True
        # Attach BOTH stdout and stderr to ptys so stdio is line-buffered
        # (several shells block-buffer non-tty streams). Two separate ptys
        # keep the streams apart.
        import pty
        import termios
        masters = {}
        for stream in ("stdout", "stderr"):
            master_fd, slave_fd = pty.openpty()
            try:
                # Disable output post-processing so we receive raw bytes
                # (no \n -> \r\n translation by the line discipline).
                attrs = termios.tcgetattr(slave_fd)
                attrs[1] &= ~termios.OPOST
                termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
            except termios.error:
                pass
            kwargs[stream] = slave_fd
            masters[stream] = (master_fd, slave_fd)

    proc = subprocess.Popen(command, **kwargs)
    job.proc = proc
    if not IS_WINDOWS:
        try:
            job.pgid = os.getpgid(proc.pid)  # == proc.pid (own session)
        except OSError:
            job.pgid = None
    else:
        job.pgid = None
    with JOBS_LOCK:
        JOBS[job.id] = job

    if IS_WINDOWS:
        t_out = threading.Thread(target=job._pump_pipe, args=(proc.stdout, job.stdout_buf), daemon=True)
        t_err = threading.Thread(target=job._pump_pipe, args=(proc.stderr, job.stderr_buf), daemon=True)
    else:
        mo, so = masters["stdout"]
        me, se = masters["stderr"]
        os.close(so)  # parent only needs the master fds
        os.close(se)
        t_out = threading.Thread(target=job._pump_pty, args=(mo, job.stdout_buf), daemon=True)
        t_err = threading.Thread(target=job._pump_pty, args=(me, job.stderr_buf), daemon=True)
    job.reader_threads = [t_out, t_err]
    t_out.start()
    t_err.start()
    return job


def kill_job(job: Job) -> bool:
    """Kill the job's entire process tree.

    POSIX: SIGKILL to the process group recorded at spawn time — this
    reaches orphaned background children even after the shell itself has
    exited (the group persists while any member is alive). Returns False
    only if the group is already gone.

    Windows: taskkill /F /T on the shell. If the shell already exited,
    orphaned children cannot be targeted and False is returned.
    """
    proc = job.proc
    if IS_WINDOWS:
        if proc is None or proc.poll() is not None:
            return False
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, timeout=15,
            )
            return True
        except Exception:
            return False
    pgid = job.pgid
    if pgid is None:
        return False
    try:
        os.killpg(pgid, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return False  # group already gone (job will be reaped by watchdog)
    except Exception:
        return False


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def file_path_from_header():
    raw = request.headers.get("X-File-Path")
    if not raw:
        return None
    try:
        p = base64.b64decode(raw, validate=True).decode("utf-8")
    except Exception:
        return None
    return p or None


# --------------------------------------------------------------------------
# flask app
# --------------------------------------------------------------------------

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # 1MB max request body


@app.errorhandler(413)
def too_large(_e):
    return jsonify(error="request body exceeds 1MB limit"), 413


@app.route("/readFile", methods=["POST"])
def read_file():
    deny = require_signature()
    if deny:
        return deny
    p = file_path_from_header()
    if p is None:
        return jsonify(error="missing or invalid X-File-Path header (base64)"), 400
    if not os.path.isfile(p):
        return jsonify(error="file not found"), 404
    try:
        return send_file(p, mimetype="application/octet-stream", as_attachment=False)
    except OSError as e:
        return jsonify(error=f"cannot read file: {e}"), 500


@app.route("/writeFile", methods=["POST"])
def write_file():
    deny = require_signature()
    if deny:
        return deny
    p = file_path_from_header()
    if p is None:
        return jsonify(error="missing or invalid X-File-Path header (base64)"), 400
    data = request.get_data()
    try:
        parent = os.path.dirname(os.path.abspath(p))
        os.makedirs(parent, exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
    except (OSError, ValueError) as e:
        return jsonify(error=f"cannot write file: {e}"), 500
    return "ok", 200


@app.route("/execShell", methods=["POST"])
def exec_shell():
    deny = require_signature()
    if deny:
        return deny
    body = request.get_json(silent=True, force=True)  # force: accept JSON regardless of Content-Type
    if not isinstance(body, dict) or not isinstance(body.get("command"), str) or not body["command"].strip():
        return jsonify(error="body must be JSON with a non-empty string field 'command'"), 400
    job = spawn(body["command"])
    job.proc.wait()
    # Short grace for the last stream bytes. If background children still
    # hold the pty open, keep the job in the registry (watchdog) and return
    # what we have instead of blocking forever.
    for t in job.reader_threads:
        t.join(timeout=2.0)
    if all(not t.is_alive() for t in job.reader_threads):
        with JOBS_LOCK:
            JOBS.pop(job.id, None)
    else:
        _detach_watchdog(job)
    out, err = job.snapshot()
    return jsonify(stdout=out, stderr=err)


@app.route("/api/jobs", methods=["GET"])
def api_jobs():
    now = time.time()
    with JOBS_LOCK:
        jobs = list(JOBS.values())
    out = []
    for job in jobs:
        so, se = job.snapshot()
        out.append({
            "id": job.id,
            "command": job.command,
            "pid": job.proc.pid if job.proc else None,
            "started": job.started,
            "elapsed": round(now - job.started, 1),
            "stdout": so,
            "stderr": se,
            "shell_exited": job.shell_exited,
        })
    return jsonify(jobs=out)


@app.route("/api/kill/<job_id>", methods=["POST"])
def api_kill(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        return jsonify(error="job not found (already finished?)"), 404
    if not kill_job(job):
        return jsonify(error="job already finished"), 409
    return jsonify(ok=True)


# --------------------------------------------------------------------------
# dashboard
# --------------------------------------------------------------------------

DASHBOARD_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>xenon \\u2014 running commands</title>
<style>
  body { background:#0d1117; color:#e6edf3; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin:0; padding:24px; }
  h1 { font-size:20px; margin:0 0 4px; }
  .sub { color:#8b949e; font-size:13px; margin-bottom:20px; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:8px; margin-bottom:16px; display:grid; grid-template-columns: 5fr 7fr; overflow:hidden; }
  .panel { padding:14px 16px; min-width:0; }
  .panel.left { border-right:1px solid #30363d; }
  .src { background:#010409; border:1px solid #21262d; border-radius:6px; padding:10px; font-size:12px; white-space:pre-wrap; word-break:break-word; max-height:280px; overflow:auto; margin:0 0 12px; }
  .src .prompt { color:#3fb950; }
  .meta { color:#8b949e; font-size:12px; line-height:1.7; }
  .meta b { color:#c9d1d9; font-weight:600; }
  .elapsed { color:#3fb950; font-weight:bold; }
  .badge { display:inline-block; background:#30363d; color:#e3b341; border-radius:4px; padding:1px 8px; font-size:11px; margin-left:8px; vertical-align:middle; }
  pre.out { background:#010409; border:1px solid #21262d; border-radius:6px; padding:10px; font-size:12px; white-space:pre-wrap; word-break:break-all; max-height:280px; overflow:auto; margin:6px 0 14px; min-height:34px; }
  .label { font-size:11px; color:#8b949e; text-transform:uppercase; letter-spacing:.05em; }
  .kill { background:#da3633; color:#fff; border:none; border-radius:6px; padding:8px 16px; cursor:pointer; font-family:inherit; font-size:13px; margin-top:12px; }
  .kill:hover { background:#f85149; }
  .kill:disabled { background:#21262d; color:#8b949e; cursor:default; }
  .empty { color:#8b949e; padding:40px; text-align:center; border:1px dashed #30363d; border-radius:8px; }
  @media (max-width: 860px) {
    .card { grid-template-columns: 1fr; }
    .panel.left { border-right:none; border-bottom:1px solid #30363d; }
  }
</style>
</head>
<body>
<h1>xenon</h1>
<div class="sub">currently executing shell commands &mdash; auto-refreshes every second</div>
<div id="jobs"><div class="empty">loading&hellip;</div></div>
<script>
const $jobs = document.getElementById('jobs');
function fmtElapsed(s) {
  if (s < 60) return s.toFixed(1) + 's';
  const m = Math.floor(s/60), r = Math.floor(s%60);
  if (m < 60) return m + 'm ' + r + 's';
  const h = Math.floor(m/60);
  return h + 'h ' + (m%60) + 'm ' + r + 's';
}
function fmtTime(ts) { return new Date(ts*1000).toLocaleString(); }
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
async function tick() {
  try {
    const r = await fetch('/api/jobs');
    const data = await r.json();
    if (!data.jobs.length) {
      $jobs.innerHTML = '<div class="empty">no commands currently executing</div>';
      return;
    }
    $jobs.innerHTML = data.jobs.map(j => `
      <div class="card">
        <div class="panel left">
          <pre class="src"><span class="prompt">$ </span>${esc(j.command)}</pre>
          <div class="meta">
            <div>job: <b>${esc(j.id)}</b>${j.shell_exited ? '<span class="badge">shell exited &mdash; background children still running</span>' : ''}</div>
            <div>pid: <b>${j.pid ?? '\\u2014'}</b></div>
            <div>started: ${fmtTime(j.started)}</div>
            <div>elapsed: <span class="elapsed">${fmtElapsed(j.elapsed)}</span></div>
          </div>
          <button class="kill" id="k-${esc(j.id)}">kill</button>
        </div>
        <div class="panel right">
          <div class="label">stdout</div>
          <pre class="out">${j.stdout ? esc(j.stdout) : '&nbsp;'}</pre>
          <div class="label">stderr</div>
          <pre class="out">${j.stderr ? esc(j.stderr) : '&nbsp;'}</pre>
        </div>
      </div>`).join('');
    data.jobs.forEach(j => document.getElementById('k-' + j.id)
      .addEventListener('click', () => killJob(j.id)));
  } catch (e) {
    $jobs.innerHTML = '<div class="empty">failed to reach server: ' + esc(String(e)) + '</div>';
  }
}
async function killJob(id) {
  const btn = document.getElementById('k-' + id);
  btn.disabled = true; btn.textContent = 'killing\\u2026';
  try {
    const r = await fetch('/api/kill/' + encodeURIComponent(id), {method:'POST'});
    btn.textContent = r.ok ? 'killed \\u2713' : 'failed (' + r.status + ')';
  } catch (e) { btn.textContent = 'failed'; }
}
tick();
setInterval(tick, 1000);
</script>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def dashboard():
    return Response(DASHBOARD_HTML, mimetype="text/html")


# --------------------------------------------------------------------------
# entrypoint
# --------------------------------------------------------------------------

DEFAULT_PORT = 64920


def main():
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"invalid port: {sys.argv[1]!r}", file=sys.stderr)
            sys.exit(1)
    if not (0 < port < 65536):
        print(f"port out of range: {port}", file=sys.stderr)
        sys.exit(1)
    print(f"xenon execution server listening on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, threaded=True)


if __name__ == "__main__":
    main()

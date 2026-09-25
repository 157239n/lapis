#!/usr/bin/env python3
"""
radon — self-contained remote-execution server + forwarding proxy.

radon is a drop-in superset of xenon: it executes commands ITSELF (the
built-in local engine: dual-pty stdout/stderr, Job registry, orphaned-
background-children watchdog, process-group kills, dashboard) AND it can
forward any request to other radon/xenon-compatible servers listed in an
optional JSON config file. One RadonClient works against radon and against
xenon-compatible servers.

  POST /readFile    headers X-File-Path (base64 abs path) + X-Server
                    (base64 name, omit/empty -> default); no body
                                                     -> raw file bytes
  POST /writeFile   headers X-File-Path + X-Server; RAW BINARY body
                    (no encoding, 1 MB cap)                   -> "ok"
  POST /execShell   JSON {"command": str, "server": str?,
                          "timeout": num?}                    -> {"stdout","stderr"}
  POST /alive       JSON {"server": str?}                     -> {"alive": bool}
  GET  /api/servers                                                -> {"servers": [{"name","descr"}]}

Dashboard (only when --dashboard is given; otherwise 404):
  GET  /                        dark HTML dashboard of running jobs
  GET  /api/jobs                JSON list of running jobs (local + forwarded)
  POST /api/kill/<job_id>       kill a job: local = whole process group;
                                forwarded = abort flag (upstream keeps running)

`server` names: the built-in local engine is registered as "local" (unless
disabled with --disableLocal or overridden by a "local" entry in the config
file). Config entries add forward targets by name. When `server` is omitted
or empty, radon routes to its DEFAULT server; when no default exists
(--disableLocal with no config, or a config whose only entry is "local"
combined with --disableLocal... see README) the request gets
400 {"error": "no default server; specify 'server'"}; a non-empty unknown
name gets 404 {"error": "unknown server: X"}.

Request authentication is OPTIONAL (-pk): when a public key is given, the
four action endpoints (/readFile, /writeFile, /execShell, /alive) require a
valid X-Signature header — base64(ed25519_signature(expiry) || expiry),
exactly xenon's scheme — verified against that key with a not-yet-past
expiry. GETs (and the dashboard, when enabled) never require it.

Config file (-sc): JSON object mapping server names to targets:

  {
    "[name]": {
      "server":  "host:port"          (or a full http:// or https:// URL,
                                       used verbatim; no scheme -> http://)
      "privkey": "[64 hex chars]"     (optional; absent = unauthenticated
                                       remote, no X-Signature sent)
      "descr":   "[human label]"      (optional, default "")
    }, ...
  }

A "local" entry OVERRIDES the built-in engine: the local engine is not
started and "local" routes to that remote.

Timeout semantics: a numeric `timeout` on /execShell against the LOCAL
engine caps the wait and KILLS THE WHOLE PROCESS GROUP on expiry (502).
The same timeout forwarded to a remote only ABORTS THE REQUEST when it
expires — the upstream command keeps running (there is no way to signal
it). Documented in README.

Usage:  python3 server.py [-p PORT] [-pk PUBKEY-HEX] [-sc CONFIG.json]
                            [--disableLocal] [--dashboard]

  -p/--port        actual TCP port (NOT an offset), default 40210
  -pk/--pubkey     optional hex Ed25519 public key (64 chars); enables
                   request authentication on the action endpoints
  -sc/--serverConf optional path to the JSON config file (see above)
  --disableLocal   do not start the local execution engine (forward-only)
  --dashboard      enable the job dashboard routes (off by default)
"""

import argparse
import base64
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

from flask import Flask, Response, jsonify, request, send_file

# --------------------------------------------------------------------------
# global state (set in main())
# --------------------------------------------------------------------------

# name -> {"type": "local", "descr": str}
#      or {"type": "forward", "url": str, "privkey": bytes|None, "descr": str}
SERVERS = {}
DEFAULT_SERVER = None      # name, or None when no default exists
LOCAL_ENABLED = False      # True when the built-in local engine is active
DASHBOARD_ENABLED = False  # --dashboard flag
AUTH_PUBLIC_KEY = None     # bytes, or None = unauthenticated mode

MAX_BODY = 1024 * 1024     # 1 MB request-body cap (same as xenon)
SIG_TTL = 300              # signature expiry window, seconds (xenon's scheme)


def die(msg: str):
    print(f"radon: {msg}", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# crypto helpers
# --------------------------------------------------------------------------

def _lazy_ed25519():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    return Ed25519PrivateKey, Ed25519PublicKey


def parse_pubkey_hex(hexstr: str) -> bytes:
    """Validate a 64-char hex Ed25519 public key; return the 32 raw bytes."""
    try:
        key = bytes.fromhex(hexstr)
    except ValueError:
        raise ValueError("not valid hex")
    if len(key) != 32:
        raise ValueError("must be 64 hex chars (32 bytes)")
    # sanity-check it is a decodable ed25519 public key
    _lazy_ed25519()[1].from_public_bytes(key)
    return key


def parse_privkey_hex(hexstr: str) -> bytes:
    """Validate a 64-char hex Ed25519 private key; return the 32 raw bytes."""
    try:
        key = bytes.fromhex(hexstr)
    except ValueError:
        raise ValueError("not valid hex")
    if len(key) != 32:
        raise ValueError("must be 64 hex chars (32 bytes)")
    _lazy_ed25519()[0].from_private_bytes(key)
    return key


# --------------------------------------------------------------------------
# config file loading
# --------------------------------------------------------------------------

def normalize_url(s: str) -> str:
    """A configured "server" value: with a scheme (http://, https://) it is
    used verbatim as the base URL; without a scheme, http:// is prefixed."""
    s = s.strip()
    if s.startswith("http://") or s.startswith("https://"):
        return s.rstrip("/")
    return "http://" + s.rstrip("/")


def load_server_conf(path: str) -> dict:
    """Load and validate the optional JSON config file. Exits with a clear
    message (code 1) on any problem. Returns {name: entry_dict} where each
    entry is {"server": normalized_url, "privkey": bytes|None, "descr": str}
    in file order."""
    if not os.path.isfile(path):
        die(f"config file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except OSError as e:
        die(f"cannot read config file {path}: {e}")
    try:
        conf = json.loads(raw)
    except json.JSONDecodeError as e:
        die(f"config file {path} is not valid JSON: {e}")
    if not isinstance(conf, dict):
        die(f"config file {path} must be a JSON object mapping names to entries")
    out = {}
    for name, entry in conf.items():
        if not isinstance(name, str) or not name:
            die(f"config file {path}: server names must be non-empty strings")
        if not isinstance(entry, dict):
            die(f"config entry '{name}' must be a JSON object")
        if "server" not in entry or not isinstance(entry["server"], str) \
                or not entry["server"].strip():
            die(f"config entry '{name}' is missing the required 'server' field "
                f"(host:port or http(s):// URL)")
        url = normalize_url(entry["server"])
        privkey = None
        if "privkey" in entry:
            pv = entry["privkey"]
            if not isinstance(pv, str):
                die(f"config entry '{name}': 'privkey' must be a hex string")
            try:
                privkey = parse_privkey_hex(pv)
            except ValueError as e:
                die(f"config entry '{name}': bad 'privkey' ({e})")
        descr = entry.get("descr", "")
        if not isinstance(descr, str):
            die(f"config entry '{name}': 'descr' must be a string")
        out[name] = {"url": url, "privkey": privkey, "descr": descr}
    return out


# --------------------------------------------------------------------------
# local execution engine (ported from xenon/server.py)
# --------------------------------------------------------------------------

IS_WINDOWS = os.name == "nt"

JOBS = {}
JOBS_LOCK = threading.Lock()


class Job:
    """One operation under execution, local or forwarded.

    Local jobs have proc/pgid/reader_threads and stream live into their
    buffers. Forwarded jobs have proc=None, pgid=None, forward_to=<name>,
    and (for execShell) their buffers are populated when the upstream
    responds — no live streaming, because the upstream /execShell blocks.
    Both kinds live in the SAME JOBS registry so the dashboard shows
    everything; each forwarded request registers one."""

    def __init__(self, command: str, forward_to: str | None = None):
        self.id = uuid.uuid4().hex[:10]
        self.command = command
        self.started = time.time()
        self.stdout_buf = bytearray()
        self.stderr_buf = bytearray()
        self.proc = None
        self.pgid = None
        self.reader_threads = []
        self.lock = threading.Lock()
        self.forward_to = forward_to           # None = local job
        self.kill_flag = threading.Event()     # set by /api/kill
        self.killed = False

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

    def set_output(self, stdout: str, stderr: str):
        """Populate both buffers at once (used for forwarded execShell jobs
        when the upstream responds)."""
        with self.lock:
            self.stdout_buf.extend(stdout.encode("utf-8", "replace"))
            self.stderr_buf.extend(stderr.encode("utf-8", "replace"))

    def snapshot(self):
        with self.lock:
            out = bytes(self.stdout_buf).decode("utf-8", errors="replace")
            err = bytes(self.stderr_buf).decode("utf-8", errors="replace")
        return out, err

    @property
    def shell_exited(self):
        return self.proc is not None and self.proc.poll() is not None

    @property
    def is_forwarded(self):
        return self.forward_to is not None


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
    streaming stdout/stderr into a Job (dual pty on POSIX, pipes on
    Windows — same structure as xenon)."""
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
    """Kill a job.

    Local (POSIX): SIGKILL to the process group recorded at spawn time —
    reaches orphaned background children even after the shell itself has
    exited (the group persists while any member is alive). Returns False
    only if the group is already gone.
    Local (Windows): taskkill /F /T on the shell.
    Forwarded: sets the kill flag so the forwarding code treats the
    (eventual) upstream result as aborted and returns 502 to the caller.
    The UPSTREAM command keeps running — there is no channel to stop it."""
    if job.is_forwarded:
        job.kill_flag.set()
        return True
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


class LocalTimeout(Exception):
    """Raised when a local command's wait cap expired (its process group
    was already SIGKILLed) or a forwarded wait cap expired (request
    aborted, upstream keeps running)."""

    def __init__(self, timeout: float, forwarded: bool = False):
        self.timeout = timeout
        self.forwarded = forwarded
        if forwarded:
            super().__init__(f"forwarded command timed out after {timeout}s")
        else:
            super().__init__(f"local command timed out after {timeout}s")


def run_local_command(command: str, timeout: float | None) -> tuple[str, str]:
    """Spawn a local job, block until its shell exits (capped by `timeout`),
    and return (stdout, stderr).

    On timeout the WHOLE PROCESS GROUP is SIGKILLed locally (no zombie /
    surviving children) and LocalTimeout is raised — cleaner than leaving a
    zombie behind. (Forwarded timeouts, by contrast, only abort OUR request;
    the upstream command keeps running.) The job is removed from the
    registry on the happy path, or left to the orphaned-background-children
    watchdog when background children still hold the ptys open (same
    pattern as xenon)."""
    job = spawn(command)
    timed_out = False
    try:
        if timeout is None:
            job.proc.wait()
        else:
            try:
                job.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Cap expired: kill the entire process group locally so no
                # zombie/surviving children linger, then report the timeout.
                if not IS_WINDOWS and job.pgid is not None:
                    try:
                        os.killpg(job.pgid, signal.SIGKILL)
                    except OSError:
                        pass
                try:
                    job.proc.kill()
                except OSError:
                    pass
                try:
                    job.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                timed_out = True
                raise LocalTimeout(timeout, forwarded=False)
    finally:
        if timed_out:
            # Kill the group, drain whatever the readers captured, drop the
            # job. (Reader threads get EIO once the group is gone.)
            for t in job.reader_threads:
                t.join(timeout=3.0)
            with JOBS_LOCK:
                JOBS.pop(job.id, None)
        else:
            # Happy path: if background children still hold the ptys open,
            # keep the job via the watchdog, else remove it.
            for t in job.reader_threads:
                t.join(timeout=2.0)
            if all(not t.is_alive() for t in job.reader_threads):
                with JOBS_LOCK:
                    JOBS.pop(job.id, None)
            else:
                _detach_watchdog(job)
    out, err = job.snapshot()
    return out, err


# --------------------------------------------------------------------------
# forwarding to remote radon/xenon-compatible servers
# --------------------------------------------------------------------------

class UpstreamError(Exception):
    """A remote server answered with a non-2xx status."""

    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body
        super().__init__(f"upstream error {status}")


class UpstreamUnreachable(Exception):
    """Could not reach the remote server at all (refused/reset)."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"cannot reach upstream: {reason}")


class UpstreamTimeout(Exception):
    """The socket wait to/from the remote server expired."""

    def __init__(self):
        super().__init__("upstream timed out")


class ForwardedKill(Exception):
    """The caller killed a pending forwarded job via /api/kill/<id>; the
    forwarding code converts this into a 502 for the caller. The upstream
    command keeps running (it cannot be stopped from here)."""


def _sign_header(privkey: bytes) -> str:
    """xenon's X-Signature scheme: base64(ed25519_signature(expiry) ||
    expiry), expiry = now + SIG_TTL."""
    Ed25519PrivateKey, _ = _lazy_ed25519()
    key = Ed25519PrivateKey.from_private_bytes(privkey)
    msg = str(int(time.time() + SIG_TTL)).encode()
    return base64.b64encode(key.sign(msg) + msg).decode()


def _classify(err: Exception):
    """Normalize urllib/socket errors into UpstreamError /
    UpstreamUnreachable / UpstreamTimeout. Always raises."""
    if isinstance(err, urllib.error.HTTPError):
        raise UpstreamError(err.code, err.read()) from None
    if isinstance(err, urllib.error.URLError):
        reason = err.reason
        if isinstance(reason, (socket.timeout, TimeoutError)):
            raise UpstreamTimeout() from None
        desc = str(reason) if reason else "connection failed"
        raise UpstreamUnreachable(desc) from None
    if isinstance(err, (socket.timeout, TimeoutError)):
        raise UpstreamTimeout() from None
    if isinstance(err, OSError):
        raise UpstreamUnreachable(str(err) or type(err).__name__) from None
    raise err


def _upstream_request(method: str, base_url: str, privkey: bytes | None,
                      path: str, body: bytes | None, headers: dict | None,
                      timeout: float | None) -> bytes:
    """Send one HTTP request to a remote server, signing with `privkey` when
    given (only ever on POSTs — GETs are open on xenon/radon). Returns the
    response body bytes; raises UpstreamError / UpstreamUnreachable /
    UpstreamTimeout on failure."""
    h = dict(headers) if headers else {}
    if body is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/json"
    if privkey is not None and method == "POST":
        h["X-Signature"] = _sign_header(privkey)
    req = urllib.request.Request(base_url + path, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as e:
        _classify(e)


def _upstream_post(base_url, privkey, path, body, headers, timeout):
    return _upstream_request("POST", base_url, privkey, path, body, headers, timeout)


def _upstream_get(base_url, path, timeout):
    return _upstream_request("GET", base_url, None, path, None, None, timeout)


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class _ForwardedOp:
    """Context manager: registers a Job for a forwarded request (so the
    dashboard shows everything, marked with forward_to), runs the upstream
    call, honors the kill flag, and removes the job when done (success or
    failure) — the same registry lifecycle local jobs have."""

    def __init__(self, name: str, command: str):
        self.name = name
        self.command = command
        self.job = Job(command, forward_to=name)

    def __enter__(self):
        with JOBS_LOCK:
            JOBS[self.job.id] = self.job
        return self

    def __exit__(self, exc_type, exc, tb):
        with JOBS_LOCK:
            JOBS.pop(self.job.id, None)
        if exc_type is None and self.job.kill_flag.is_set():
            # The upstream call succeeded, but the caller killed this job
            # while we were waiting: treat the result as aborted.
            self.job.killed = True
            raise ForwardedKill()
        return False


def forward_read_file(name: str, path: str) -> bytes:
    entry = SERVERS[name]
    with _ForwardedOp(name, f"readFile {path}"):
        return _upstream_post(entry["url"], entry["privkey"], "/readFile", b"",
                              {"X-File-Path": b64(path)}, timeout=60.0)


def forward_write_file(name: str, path: str, data: bytes) -> None:
    entry = SERVERS[name]
    with _ForwardedOp(name, f"writeFile {path}"):
        _upstream_post(entry["url"], entry["privkey"], "/writeFile", data,
                       {"X-File-Path": b64(path)}, timeout=60.0)


def forward_exec_shell(name: str, command: str, timeout: float | None) -> tuple[str, str]:
    """Forward an execShell to a remote server.

    Registers a Job (marked forward_to=<name>) in the SAME registry as
    local jobs so the dashboard shows it, and removes it when the request
    completes. The upstream /execShell blocks, so there is no live
    streaming — the job's stdout/stderr populate when the upstream responds.

    `timeout` caps OUR socket wait; on expiry we raise LocalTimeout
    (forwarded=True) and the upstream command KEEPS RUNNING. A /api/kill
    during the wait sets job.kill_flag; when the upstream returns we then
    raise ForwardedKill so the caller gets a 502."""
    entry = SERVERS[name]
    with _ForwardedOp(name, command) as op:
        try:
            data = _upstream_post(entry["url"], entry["privkey"], "/execShell",
                                  json.dumps({"command": command}).encode(),
                                  None, timeout=timeout)
        except UpstreamTimeout:
            # The upstream /execShell blocks until the command finishes, so
            # a socket timeout here means OUR wait cap fired (with
            # timeout=None there is no socket timeout at all). The request
            # is aborted; the upstream command KEEPS RUNNING.
            raise LocalTimeout(timeout, forwarded=True) from None
        parsed = json.loads(data)
        out = str(parsed.get("stdout", ""))
        err_ = str(parsed.get("stderr", ""))
        # Populate the job's buffers so the dashboard shows the result for
        # the instant between the upstream response and job removal.
        op.job.set_output(out, err_)
    return out, err_


def forward_alive(name: str) -> bool:
    """Probe a remote server the way xenon/radon health checks work:
    GET /api/jobs (open on both). Never raises — any failure is False."""
    entry = SERVERS[name]
    try:
        _upstream_get(entry["url"], "/api/jobs", timeout=10.0)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# request authentication (optional, xenon's X-Signature scheme)
# --------------------------------------------------------------------------

def _verify_signature() -> bool:
    """True when request-auth is disabled, or the X-Signature header is a
    valid ed25519_signature(expiry) signed by AUTH_PUBLIC_KEY whose expiry
    (unix timestamp) has not passed — exactly xenon's scheme."""
    if AUTH_PUBLIC_KEY is None:
        return True
    raw = request.headers.get("X-Signature")
    if not raw:
        return False
    try:
        blob = base64.b64decode(raw, validate=True)
        if len(blob) < 64:
            return False
        sig, msg = blob[:64], blob[64:]
        _, Ed25519PublicKey = _lazy_ed25519()
        Ed25519PublicKey.from_public_bytes(AUTH_PUBLIC_KEY).verify(sig, msg)
        expiry = int(msg.strip().decode("utf-8"))
        return expiry > time.time()
    except Exception:
        return False


def _forbidden():
    return jsonify(error="forbidden"), 403


# --------------------------------------------------------------------------
# server resolution
# --------------------------------------------------------------------------

def _no_default():
    return jsonify(error="no default server; specify 'server'"), 400


def _unknown(server: str):
    return jsonify(error=f"unknown server: {server}"), 404


def resolve_server(server) -> tuple[str | None, tuple | None]:
    """Resolve a requested server name to a registered one.

    Returns (name, None) on success or (None, error_response) otherwise.
    Rules:
      - missing/""           -> the default server (400 when there is none)
      - "local" not registered (engine disabled, no config "local" entry)
                             -> 400 "no default server; specify 'server'"
                             (the reserved name is unavailable, not merely
                             unknown)
      - non-empty unknown    -> 404 "unknown server: X"
      - non-string           -> 400
    """
    if server is None or server == "":
        if DEFAULT_SERVER is not None:
            return DEFAULT_SERVER, None
        return None, _no_default()
    if not isinstance(server, str):
        return None, (jsonify(error="'server' must be a string (omit or use \"\" for the default)"), 400)
    if server in SERVERS:
        return server, None
    if server == "local":
        return None, _no_default()
    return None, _unknown(server)


def _server_from_header() -> tuple[str | None, tuple | None]:
    """X-Server header: base64-encoded name. Missing -> default; invalid
    base64 -> 400; decodes to "" -> default; otherwise as resolve_server."""
    raw = request.headers.get("X-Server")
    if raw is None or raw == "":
        return resolve_server("")
    try:
        server = base64.b64decode(raw, validate=True).decode("utf-8")
    except Exception:
        return None, (jsonify(error="invalid X-Server header (base64)"), 400)
    return resolve_server(server)


def _path_from_header() -> str | None:
    """X-File-Path header: base64-encoded absolute path. None when missing
    or invalid."""
    raw = request.headers.get("X-File-Path")
    if not raw:
        return None
    try:
        p = base64.b64decode(raw, validate=True).decode("utf-8")
    except Exception:
        return None
    return p or None


def _get_json_body():
    body = request.get_json(silent=True, force=True)
    return body if isinstance(body, dict) else None


def _bad(msg: str):
    return jsonify(error=msg), 400


# --------------------------------------------------------------------------
# upstream failure -> 502 mapping (no key may ever leak)
# --------------------------------------------------------------------------

def _upstream_502(name: str, exc: Exception):
    """Map a failure of a forwarded request to 502 JSON. Messages are fixed
    strings + the server name — never the request body, config, or keys."""
    if isinstance(exc, UpstreamError):
        detail = ""
        try:
            detail = str(json.loads(exc.body).get("error", ""))[:300]
        except Exception:
            pass
        msg = f"upstream error: {detail}" if detail \
            else f"upstream returned status {exc.status}"
        return jsonify(error=msg, upstream_status=exc.status, server=name), 502
    if isinstance(exc, LocalTimeout):
        if exc.forwarded:
            msg = (f"timed out after {exc.timeout}s (request aborted; "
                   f"upstream command keeps running)")
        else:
            msg = f"timed out after {exc.timeout}s (process group killed)"
        return jsonify(error=msg, server=name), 502
    if isinstance(exc, ForwardedKill):
        return jsonify(error="killed (upstream command keeps running)",
                       server=name), 502
    if isinstance(exc, UpstreamTimeout):
        return jsonify(error=f"timed out reaching server '{name}'",
                       server=name), 502
    if isinstance(exc, UpstreamUnreachable):
        return jsonify(error=f"cannot reach server '{name}': {exc.reason}",
                       server=name), 502
    return jsonify(error=f"cannot reach server '{name}'", server=name), 502


# --------------------------------------------------------------------------
# flask app
# --------------------------------------------------------------------------

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY


@app.errorhandler(413)
def too_large(_e):
    return jsonify(error=f"request body exceeds {MAX_BODY // 1024}KB limit"), 413


def _local_read_file(path: str):
    if not os.path.isfile(path):
        return jsonify(error="file not found"), 404
    try:
        return send_file(path, mimetype="application/octet-stream", as_attachment=False)
    except OSError:
        return jsonify(error="cannot read file"), 500


def _local_write_file(path: str, data: bytes):
    try:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
    except (OSError, ValueError):
        return jsonify(error="cannot write file"), 500
    return "ok", 200


@app.route("/readFile", methods=["POST"])
def read_file():
    if not _verify_signature():
        return _forbidden()
    path = _path_from_header()
    if path is None:
        return _bad("missing or invalid X-File-Path header (base64)")
    server, err = _server_from_header()
    if err:
        return err
    if SERVERS[server]["type"] == "local":
        return _local_read_file(path)
    try:
        data = forward_read_file(server, path)
    except (UpstreamError, UpstreamUnreachable, UpstreamTimeout,
            LocalTimeout, ForwardedKill) as e:
        return _upstream_502(server, e)
    return Response(data, mimetype="application/octet-stream")


@app.route("/writeFile", methods=["POST"])
def write_file():
    if not _verify_signature():
        return _forbidden()
    path = _path_from_header()
    if path is None:
        return _bad("missing or invalid X-File-Path header (base64)")
    server, err = _server_from_header()
    if err:
        return err
    data = request.get_data()
    if SERVERS[server]["type"] == "local":
        return _local_write_file(path, data)
    try:
        forward_write_file(server, path, data)
    except (UpstreamError, UpstreamUnreachable, UpstreamTimeout,
            LocalTimeout, ForwardedKill) as e:
        return _upstream_502(server, e)
    return "ok", 200


@app.route("/execShell", methods=["POST"])
def exec_shell():
    if not _verify_signature():
        return _forbidden()
    body = _get_json_body()
    if body is None:
        return _bad("body must be a JSON object")
    command = body.get("command")
    if not isinstance(command, str) or not command.strip():
        return _bad("missing required field 'command' (non-empty string)")
    server, err = resolve_server(body.get("server", ""))
    if err:
        return err
    timeout = body.get("timeout", None)
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float))):
        return _bad("'timeout' must be a number (or omitted)")
    if SERVERS[server]["type"] == "local":
        try:
            out, err_ = run_local_command(command, timeout)
        except LocalTimeout as e:
            return _upstream_502(server, e)
    else:
        try:
            out, err_ = forward_exec_shell(server, command, timeout)
        except (UpstreamError, UpstreamUnreachable, UpstreamTimeout,
                LocalTimeout, ForwardedKill) as e:
            return _upstream_502(server, e)
    return jsonify(stdout=out, stderr=err_)


@app.route("/alive", methods=["POST"])
def alive():
    if not _verify_signature():
        return _forbidden()
    # Body is optional JSON; an empty body is treated as {}.
    raw = request.get_data()
    if raw:
        body = _get_json_body()
        if body is None:
            return _bad("body must be a JSON object")
    else:
        body = {}
    server, err = resolve_server(body.get("server", ""))
    if err:
        return err
    if SERVERS[server]["type"] == "local":
        is_alive = True
    else:
        is_alive = forward_alive(server)
    return jsonify(alive=is_alive)


@app.route("/api/servers", methods=["GET"])
def api_servers():
    # name and descr ONLY — never url, key, or any config internals.
    # Always open, no auth.
    return jsonify(servers=[{"name": name, "descr": SERVERS[name]["descr"]}
                            for name in SERVERS])


# --------------------------------------------------------------------------
# dashboard routes (only when --dashboard is given)
# --------------------------------------------------------------------------

@app.route("/api/jobs", methods=["GET"])
def api_jobs():
    if not DASHBOARD_ENABLED:
        return jsonify(error="dashboard disabled"), 404
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
            "forward_to": job.forward_to,   # None for local jobs
        })
    return jsonify(jobs=out)


@app.route("/api/kill/<job_id>", methods=["POST"])
def api_kill(job_id):
    if not DASHBOARD_ENABLED:
        return jsonify(error="dashboard disabled"), 404
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        return jsonify(error="job not found (already finished?)"), 404
    if not kill_job(job):
        return jsonify(error="job already finished"), 409
    return jsonify(ok=True)


DASHBOARD_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>radon \\u2014 running commands</title>
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
  .fwd { color:#58a6ff; }
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
<h1>radon</h1>
<div class="sub">currently executing shell commands (local + forwarded) &mdash; auto-refreshes every second</div>
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
            <div>job: <b>${esc(j.id)}</b>${j.forward_to ? `<span class="badge fwd">forwarding &rarr; ${esc(j.forward_to)}</span>` : ''}${j.shell_exited ? '<span class="badge">shell exited &mdash; background children still running</span>' : ''}</div>
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
    if not DASHBOARD_ENABLED:
        return jsonify(error="dashboard disabled"), 404
    return Response(DASHBOARD_HTML, mimetype="text/html")


# --------------------------------------------------------------------------
# entrypoint
# --------------------------------------------------------------------------

DEFAULT_PORT = 40210


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="server.py",
        description="radon — self-contained remote-execution server + "
                    "forwarding proxy (drop-in superset of xenon).")
    p.add_argument("-p", "--port", type=str, default=str(DEFAULT_PORT),
                   help=f"actual TCP port to listen on (not an offset), "
                        f"default {DEFAULT_PORT}")
    p.add_argument("-pk", "--pubkey", type=str, default=None, metavar="PUBKEY-HEX",
                   help="optional 64-char hex Ed25519 public key; when given, "
                        "the four action endpoints require a valid X-Signature")
    p.add_argument("-sc", "--serverConf", type=str, default=None,
                   metavar="FILE",
                   help="optional path to a JSON config file with other "
                        "radon/xenon-compatible servers to forward to")
    p.add_argument("--disableLocal", action="store_true",
                   help="do not start the built-in local execution engine "
                        "(forward-only mode)")
    p.add_argument("--dashboard", action="store_true",
                   help="enable the job dashboard routes (GET /, GET /api/jobs, "
                        "POST /api/kill/<id>); disabled by default")
    return p


def main():
    global SERVERS, DEFAULT_SERVER, LOCAL_ENABLED, DASHBOARD_ENABLED
    global AUTH_PUBLIC_KEY

    args = build_parser().parse_args()

    # --- port ---------------------------------------------------------
    try:
        port = int(args.port)
    except (TypeError, ValueError):
        die(f"bad port: {args.port!r} (must be an integer)")
    if not (0 < port < 65536):
        die(f"bad port: {port} (must be in 1..65535)")

    # --- public key (request auth) -------------------------------------
    if args.pubkey is not None:
        try:
            AUTH_PUBLIC_KEY = parse_pubkey_hex(args.pubkey)
        except ValueError as e:
            die(f"bad public key: {e} (must be 64 hex chars / 32 bytes)")
        mode = "authenticated (X-Signature required on action endpoints)"
    else:
        mode = "unauthenticated"

    # --- config file ----------------------------------------------------
    conf = {}
    if args.serverConf is not None:
        conf = load_server_conf(args.serverConf)

    # --- conflict: --disableLocal and a "local" config entry ------------
    if args.disableLocal and "local" in conf:
        die("conflict: --disableLocal is mutually exclusive with a 'local' "
            "entry in the config file (a 'local' entry overrides the built-in "
            "engine, so both cannot apply)")

    # --- build the server set -------------------------------------------
    # Order: "local" first (engine or override), then config entries in
    # file order (skipping "local" when it is the override).
    if "local" in conf:
        # Override: the built-in engine is NOT started; "local" forwards.
        SERVERS["local"] = {"type": "forward", "url": conf["local"]["url"],
                            "privkey": conf["local"]["privkey"],
                            "descr": conf["local"]["descr"] or "overridden local server"}
        LOCAL_ENABLED = False
        for name, e in conf.items():
            if name == "local":
                continue
            SERVERS[name] = {"type": "forward", "url": e["url"],
                             "privkey": e["privkey"], "descr": e["descr"]}
    elif args.disableLocal:
        LOCAL_ENABLED = False
        for name, e in conf.items():
            SERVERS[name] = {"type": "forward", "url": e["url"],
                             "privkey": e["privkey"], "descr": e["descr"]}
    else:
        LOCAL_ENABLED = True
        SERVERS["local"] = {"type": "local", "descr": "radon local engine"}
        for name, e in conf.items():
            if name == "local":
                continue
            SERVERS[name] = {"type": "forward", "url": e["url"],
                             "privkey": e["privkey"], "descr": e["descr"]}

    # --- default server ---------------------------------------------------
    if "local" in conf:
        DEFAULT_SERVER = "local"
    elif LOCAL_ENABLED:
        DEFAULT_SERVER = "local"
    elif conf:
        DEFAULT_SERVER = next(iter(conf))
    else:
        DEFAULT_SERVER = None

    DASHBOARD_ENABLED = bool(args.dashboard)

    names = ", ".join(SERVERS) if SERVERS else "(none)"
    print(f"radon listening on 0.0.0.0:{port} — servers: {names} — "
          f"default: {DEFAULT_SERVER or '(none)'} — {mode}"
          + (" — dashboard ON" if DASHBOARD_ENABLED else " — dashboard off"),
          flush=True)
    app.run(host="0.0.0.0", port=port, threaded=True)


if __name__ == "__main__":
    main()

from k1lib.imports import *
import inspect, functools, traceback, tempfile

app = web.Flask(__name__)

def toolCatchErr(func):
    original_signature = inspect.signature(func); original_annotations = dict(getattr(func, "__annotations__", {})); original_defaults = getattr(func, "__defaults__", None); original_kwdefaults = getattr(func, "__kwdefaults__", None)
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try: res = func(*args, **kwargs)
        except Exception as e: return json.dumps({"resultType": "error", "result": f"{type(e)}\n{e}\n{traceback.format_exc()}", "note": "Is there an error? If yes, think about how to fix it and then go do it"})
        try: res["resultType"]; res["success"] = True; return json.dumps(res)
        except: pass
        return json.dumps({"resultType": f"{type(res).__name__}", "result": res.hex() if type(res) == bytes else res, "success": True})
    wrapper.__signature__ = original_signature; wrapper.__annotations__ = original_annotations; wrapper.__defaults__ = original_defaults; wrapper.__kwdefaults__ = original_kwdefaults; return wrapper

os.chdir("/tmp")

@app.route("/api/exec", methods=["POST"])
@toolCatchErr
def api_exec(js):
    with k1.timer() as t: out, err = None | cli.cmd(js["cmd"], mode=0) | apply("\n".join)
    return {"resultType": "str", "result": out, "stderr": err, "execDuration": t(), "note": "if errors out, retry using other commands until successful"}

extraPyBegin = """import matplotlib.pyplot as plt; import uuid
def _patched_show(*args, **kwargs): fname = f"/tmp/plot_{uuid.uuid4().hex}.png"; plt.savefig(fname); print(f"[saved plot] {fname}. Use .displayFile() to display to the end user. DO NOT USE MARKDOWN IMAGE TAG"); plt.close()
plt.show = _patched_show\n\n"""
extraPyEnd = """\nprint("python script finished without errors")\n"""

@app.route("/api/runPy", methods=["POST"])
@toolCatchErr
def api_runPy(js):
    fn = (extraPyBegin + js["contents"] + extraPyEnd) | cli.file(tempfile.mkstemp(suffix=".py")[1])
    with k1.timer() as t: out, err = None | cli.cmd(f"python {fn}", mode=0) | apply("\n".join)
    return {"resultType": "str", "result": out, "stderr": err, "execDuration": t(), "note": "if errors out, retry using other commands until successful"}

@app.route("/api/writeFile", methods=["POST"])
@toolCatchErr
def api_writeFile(js): js["contents"] | fromBase64(text=False) | file(os.path.expanduser(js["fileName"]), mkdir=True); return True

@app.route("/api/readFile", methods=["POST"])
def api_readFile(js):
    try:
        with open(os.path.expanduser(js["fileName"]), "rb") as f: return f.read()
    except Exception as e: return f"Exception: {type(e)}\n{e}", 500, {}

@app.route("/api/error", methods=["POST"])
def api_error(js): raise Exception("Random error")





from flask import request, Response, abort; import httpx
HOP_IN  = {"host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade", "content-length"}
HOP_OUT = {"content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"}
def forward(target_url):
    client = httpx.Client(timeout=httpx.Timeout(30.0, read=None))
    req = client.build_request(request.method, target_url, headers={k: v for k, v in request.headers if k.lower() not in HOP_IN}, content=request.get_data() or None)
    try: resp = client.send(req, stream=True)
    except (httpx.ConnectError, httpx.ConnectTimeout): client.close(); return Response("webapp not reachable", status=502)
    out_headers = {k: v for k, v in resp.headers.items() if k.lower() not in HOP_OUT}
    def gen():
        try: yield from resp.iter_bytes()
        finally: resp.close(); client.close()
    return Response(gen(), status=resp.status_code, headers=out_headers)
@app.route("/app/<int:port>",  defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/app/<int:port>/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/app/<int:port>/<path:path>", methods=["GET", "POST"])
def apps(port, path):
    if not (9000 <= port <= 9999): abort(400)
    url = f"http://127.0.0.1:{port}/{path}"
    if request.query_string: url += "?" + request.query_string.decode("latin-1")
    return forward(url)



import os, re, time, shutil, signal, subprocess, sys; from pathlib import Path
APPS_DIR = Path("/apps")
PROTECTED_PORTS = {80, 81}   # container's own services — never touch these
BIND_TIMEOUT  = 15.0         # how long app_run waits for the new app to bind
GRACE         = 5.0          # seconds between SIGTERM and SIGKILL


# ---------- helpers ----------

def _find_pid_on_port(port: int):
    """PID of the process LISTENING on `port`, or None. Pure /proc, no lsof/fuser."""
    target = f"{port:04X}"; inodes = set()
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try: lines = open(f).read().splitlines()[1:]
        except OSError: continue
        for line in lines:
            p = line.split(); local, state, inode = p[1], p[3], p[9]  # 0A = LISTEN
            if local.rsplit(":", 1)[1].upper() == target and state == "0A": inodes.add(inode)
    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit(): continue
        try:
            for fd in os.listdir(f"/proc/{pid_dir}/fd"):
                try: link = os.readlink(f"/proc/{pid_dir}/fd/{fd}")
                except OSError: continue
                m = re.fullmatch(r"socket:\[(\d+)\]", link)
                if m and m.group(1) in inodes: return int(pid_dir)
        except (PermissionError, FileNotFoundError): continue
    return None
def _descendants(root_pid: int):
    """All descendant PIDs of root_pid (for killing apps not started with setsid)."""
    kids = {}
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try: stat = open(f"/proc/{p}/stat").read(); ppid = int(stat.split(") ")[1].split()[1])  # comm can contain spaces
        except (OSError, IndexError): continue
        kids.setdefault(ppid, []).append(int(p))
    out, stack = [], [root_pid]
    while stack:
        cur = stack.pop()
        for c in kids.get(cur, []): out.append(c); stack.append(c)
    return out
def _terminate(pid: int) -> bool:
    """SIGTERM the app's process tree, wait GRACE seconds, escalate to SIGKILL."""
    pgid = os.getpgid(pid)
    if pgid == pid:  # we started it (setsid) -> kill the whole group
        def hit(sig):
            try: os.killpg(pgid, sig)
            except (ProcessLookupError, PermissionError): pass
    else:            # model started it from a shell -> kill pid + descendants
        targets = [pid, *set(_descendants(pid))]
        def hit(sig):
            for p in targets:
                try: os.kill(p, sig)
                except (ProcessLookupError, PermissionError): pass
    hit(signal.SIGTERM); deadline = time.time() + GRACE
    while time.time() < deadline:
        time.sleep(0.2)
        try: os.kill(pid, 0)
        except ProcessLookupError: return True
    hit(signal.SIGKILL); time.sleep(0.2)
    try: os.kill(pid, 0); return False
    except ProcessLookupError: return True
# ---------- the four methods ----------
def app_status(port: int) -> bool:
    """True if something is listening on `port`."""
    if port in PROTECTED_PORTS: return True
    return _find_pid_on_port(port) is not None
@app.route("/appControl/<int:port>/status")
def _app_status(port): return str(app_status(port))
def app_run(port: int) -> bool:
    """Start /apps/{port}/main.py if not already running.

    Returns True if the app is (or will be) running:
      - already listening            -> True immediately
      - process alive but slow bind  -> True after BIND_TIMEOUT
      - missing main.py / crashed    -> False
    """
    if port in PROTECTED_PORTS: return True, "Port is reserved"
    if app_status(port): return True, "Port occupied. If you have started the app up yourself before calling webapp_run(), then everything's good"
    app_dir = APPS_DIR / str(port); main = app_dir / "main.py"
    if not main.is_file(): return False, "No main.py file"
    app_dir.mkdir(parents=True, exist_ok=True); log = open(app_dir / "app.log", "ab")
    proc = subprocess.Popen([sys.executable, "main.py"], cwd=app_dir, env={**os.environ, "PORT": str(port), "SERVER": f"https://lapis.aigu.vn/app/{port}"}, stdout=log, stderr=log, start_new_session=True)   # convention: app reads os.environ["PORT"]
    log.close(); (app_dir / ".pid").write_text(str(proc.pid)); deadline = time.time() + BIND_TIMEOUT
    while time.time() < deadline:
        if proc.poll() is not None: print(); return False, "Crashed on startup"
        if app_status(port): return True, "Success, bounded"
        time.sleep(0.25)
    return proc.poll() is None, "Later poll"
@app.route("/appControl/<int:port>/run")
def _app_run(port):
    ok, status = app_run(port); log = ""; time.sleep(2) # sleep to wait for it to startup
    app_log = APPS_DIR/str(port)/"app.log"; os.system(f"rm -f /apps/{port}/noautostart")
    return json.dumps({"ok": ok, "status": status, "pid": _find_pid_on_port(port), "tail": app_tail(port), "url": f"https://lapis.aigu.vn/app/{port}"}), 200, {"Content-Type": "application/json"}
def app_stop(port: int) -> bool:
    """Stop whatever is listening on `port`. True if it's stopped (or was already)."""
    if port in PROTECTED_PORTS: return False
    "" | file(f"/apps/{port}/noautostart", mkdir=True)
    pid = _find_pid_on_port(port)
    if pid is None: return True
    _terminate(pid); return _find_pid_on_port(port) is None       # authoritative: is the port actually free?
@app.route("/appControl/<int:port>/stop")
def _app_stop(port): pid = _find_pid_on_port(port); return json.dumps({"stopped": app_stop(port), "pid": pid})
def app_remove(port: int) -> bool:
    """Stop the app, delete /apps/{port}. Best-effort, always returns True."""
    if port in PROTECTED_PORTS: return True
    try: app_stop(port)
    except Exception as e: print(f"[app_remove] stop failed for {port}: {e}", file=sys.stderr)
    app_dir = APPS_DIR / str(port)
    def onerror(func, path, exc):
        try: os.chmod(path, 0o700); func(path)
        except Exception: pass
    try:
        if app_dir.exists(): shutil.rmtree(app_dir, onerror=onerror)
    except Exception as e: print(f"[app_remove] rmtree failed for {port}: {e}", file=sys.stderr)
    return True
@app.route("/appControl/<int:port>/remove")
def _app_remove(port): return str(app_remove(port))
def app_tail(port: int, n: int = 4000) -> list:
    """Last `n` characters of the app's log, split into lines.

    Returns [] if there's no log yet (app never ran, or was removed).
    Only reads the tail of the file, so it stays cheap even for big logs.
    """
    log = APPS_DIR / str(port) / "app.log"
    try: size = log.stat().st_size
    except (FileNotFoundError, OSError): return []
    if size == 0: return []
    with open(log, "rb") as f: f.seek(max(0, size - n)); raw = f.read()   # jump straight to the tail; read only `n` bytes
    lines = raw.decode("utf-8", "replace").splitlines()
    if (size - n) > 0 and len(lines) > 1: lines = lines[1:] # If the file is bigger than `n`, our window started mid-file, so the first line is a fragment of a line that began earlier -> drop it.
    return lines
@app.route("/appControl/<int:port>/tail")
def _app_tail(port): return "\n".join(app_tail(port))
@app.route("/appControl/<int:port>/readme")
def app_readme(port):
    path = APPS_DIR/str(port)/"readme.md"
    if not os.path.exists(path): return ""
    with open(path, "r") as f: return f.read()
def allPorts(): return [int(x.split("/")[-1]) for x in ls("/apps")]
def apps_status():
    res = []
    for port in allPorts():
        readme = app_readme(port)
        res.append({"port": port, "name": app_name(readme, port), "status": app_status(port), "tail": _app_tail(port), "readme": readme, "url": f"https://lapis.aigu.vn/app/{port}", "controlUrl": f"https://lapis.aigu.vn/appControl/{port}"})
    res.sort(key=lambda x: (not x["status"], x["port"])); return res
@app.route("/appControl/status")
def _apps_status(): return json.dumps(apps_status()), 200, {"Content-Type": "application/json"}
def _app_autostart():
    for port in allPorts():
        if not os.path.exists(APPS_DIR/str(port)/"noautostart"): app_run(port)
threading.Thread(target=_app_autostart, daemon=True).start()
@app.route("/appControl/freePort")
def app_freePort(): # grabs a free port. Just check folder existence
    ports = allPorts(); picks = []
    for i in range(9000, 9999): # why do all this? So that it picks a random port from the next available 50 slots, so that collisions where agent 1 has not created the folder yet is less likely
        if len(picks) > 50: break
        if i not in ports: picks.append(i)
    return picks | randomize(None) | item() | aS(str)

def app_name(readme: str, port: int) -> str:
    """First markdown header (line starting with '#'), ignoring fenced code blocks."""
    in_fence = False
    for line in readme.splitlines():
        s = line.strip()
        if s.startswith("```"): in_fence = not in_fence; continue
        if in_fence: continue
        if s.startswith("#"):
            name = s.lstrip("#").strip()
            if name: return name
    return f"App {port}"
@app.route("/")
def index(): web.redirect("/apps")
@app.route("/apps")
def apps_page():
    with open("/code/apps.html") as f: appsHtml = f.read()
    return appsHtml.replace("__APPS__", json.dumps(apps_status())), 200, {"Content-Type": "text/html"}

app.flask()
app.run(host="0.0.0.0", port="80")











from k1lib.imports import *
import inspect, functools, traceback, tempfile


settings.cred.sql.nConn = 3
db = sql("/dbs/main.db", mode="lite", manage=True, backups=["daily", "weekly"])["default"]

db.query("""
CREATE TABLE IF NOT EXISTS apps (
    id           INTEGER primary key autoincrement,
    port         INTEGER,
    domain       TEXT,    -- domain on lapis.aigu.vn
    title        TEXT,    -- site's title
    public       BOOL,
    createdTime  INTEGER
);""")
db.query("CREATE INDEX IF NOT EXISTS idx_apps_port ON apps(port)")
db.query("""
CREATE TABLE IF NOT EXISTS perms ( -- every time webapp_run() executes, log the triple if not exist
    id           INTEGER primary key autoincrement,
    appId        INTEGER,
    userId       INTEGER,
    chatId       INTEGER,
    modifiedTime INTEGER
);""")

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

def loginGuard(cookies):
    state = cookies.get("state", None)
    if state is None: web.redirect(f"https://ai.aigu.vn/login?token=" + k1.aes_encrypt_json({"url": f"https://lapis.aigu.vn/authIn", "tokenDuration": 86400, "timeout": int(time.time()) + 20}))
    state = k1.aes_decrypt_json(state)
    return state["userId"]
def appGuard(cookies, port):
    userId = loginGuard(cookies)
    res = db.query("select userId from perms p join apps a on p.appId = a.id where a.port = ? order by p.id limit 1", port)
    print(f"appGuard, userId {userId}, res {res}")
    if len(res) == 0: web.unauthorized()
    if res[0][0] != userId: web.unauthorized()
def adminGuard(cookies):
    if loginGuard(cookies) != 1: web.unauthorized()

def sendAiServer(userId, js): return requests.post(f"{aiServer}/ingest?token=" + k1.aes_encrypt_json({"serverName": "yt", "userId": userId, "timeout": int(time.time()) + 20}), json=js, timeout=(10, 300))

@app.route("/auth/<serverName>")
def auth(cookies, serverName):
    app = None
    try: app = db["apps"].lookup(port=int(serverName))
    except: app = db["apps"].lookup(domain=serverName)
    if app is None: web.unauthorized()
    if app.public: return "ok"
    res = db.query("select userId from perms where appId = ?", app.id)
    if len(res) == 0: web.unauthorized()
    state = cookies.get("state", None)
    if state is None: web.unauthorized()
    state = k1.aes_decrypt_json(state)
    if state["userId"] != res[0][0]: web.unauthorized()
    return "ok"
from flask import make_response
@app.route("/authIn")
def authIn(args):
    token = args.get('token', default=None)
    if not token: web.notFound()
    userId = k1.aes_decrypt_json(token)["userId"]; r = make_response("", 302); r.headers["Location"] = "/"
    r.set_cookie(key="state", value=k1.aes_encrypt_json({"userId": userId}), max_age=86400, path="/", domain="lapis.aigu.vn", httponly=True, secure=True, samesite="Lax"); return r

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
def updateNginx(port:int):
    domain = db["apps"].lookup(port=port).domain
    f"""server {{ listen 81; server_name {port} {domain or ""};
        location / {{ auth_request /check_auth; proxy_pass http://127.0.0.1:{port}; proxy_set_header Host $host; }}
        location = /check_auth {{ internal; proxy_pass http://127.0.0.1:80/auth/$server_name; proxy_connect_timeout 1s; proxy_read_timeout    2s; }} }}""" | file(f"/nginx/{port}.conf")
    None | cmd("nginx -c /code/nginx.conf -s reload")
def app_run(port: int) -> bool:
    """Start /apps/{port}/main.py if not already running.

    Returns True if the app is (or will be) running:
      - already listening            -> True immediately
      - process alive but slow bind  -> True after BIND_TIMEOUT
      - missing main.py / crashed    -> False
    """
    if port in PROTECTED_PORTS: return True, "Port is reserved"
    updateNginx(port)
    if app_status(port): return True, "Port occupied. If you have started the app up yourself before calling webapp_run(), then everything's good"
    app_dir = APPS_DIR / str(port); main = app_dir / "main.py"
    if not main.is_file(): return False, "No main.py file"
    app_dir.mkdir(parents=True, exist_ok=True); log = open(app_dir / "app.log", "ab")
    proc = subprocess.Popen([sys.executable, "main.py"], cwd=app_dir, env=os.environ, stdout=log, stderr=log, start_new_session=True)   # convention: app reads os.environ["PORT"]
    log.close(); (app_dir / ".pid").write_text(str(proc.pid)); deadline = time.time() + BIND_TIMEOUT
    while time.time() < deadline:
        if proc.poll() is not None: print(); return False, "Crashed on startup"
        if app_status(port): return True, "Success, bounded"
        time.sleep(0.25)
    return proc.poll() is None, "Later poll"
@app.route("/appControl/<int:port>/run", methods=["POST"])
def _app_run(port, js):
    js = k1.aes_decrypt_json(js["payload"]); app = db["apps"].lookup(port=port)
    if app is None: app = db["apps"].insert(port=port, domain=None, title=None, public=False, createdTime=int(time.time()))
    perm = db["perms"].lookup(appId=app.id)
    if perm is not None and perm.userId != js["userId"]: return {"ok": False, "status": "This webapp belongs to another user, can't start it"}
    perm = db["perms"].lookup(appId=app.id, userId=js["userId"], chatId=js["chatId"])
    if perm is None: perm = db["perms"].insert(appId=app.id, userId=js["userId"], chatId=js["chatId"])
    perm.modifiedTime = int(time.time()); ok, status = app_run(port); log = ""; time.sleep(2) # sleep to wait for it to startup
    app_log = APPS_DIR/str(port)/"app.log"; os.system(f"rm -f /apps/{port}/noautostart")
    return json.dumps({"ok": ok, "status": status, "pid": _find_pid_on_port(port), "tail": app_tail(port), "url": f"https://{port}.lapis.aigu.vn"}), 200, {"Content-Type": "application/json"}
@app.route("/appConLapis/<int:port>/run", guard=appGuard)
def _app_run_2(port): ok, status = app_run(port); log = ""; time.sleep(2); app_log = APPS_DIR/str(port)/"app.log"; os.system(f"rm -f /apps/{port}/noautostart"); return "ok"

def app_stop(port: int) -> bool:
    """Stop whatever is listening on `port`. True if it's stopped (or was already)."""
    if port in PROTECTED_PORTS: return False
    "" | file(f"/apps/{port}/noautostart", mkdir=True)
    pid = _find_pid_on_port(port)
    if pid is None: return True
    _terminate(pid); return _find_pid_on_port(port) is None       # authoritative: is the port actually free?
@app.route("/appControl/<int:port>/stop", methods=["POST"])
def _app_stop(port, js):
    js = k1.aes_decrypt_json(js["payload"]); app = db["apps"].lookup(port=port)
    if app is None: web.notFound()
    perm = db["perms"].lookup(appId=app.id)
    if perm is not None and perm.userId != js["userId"]: return {"ok": False, "status": "This webapp belongs to another user, can't stop it"}
    pid = _find_pid_on_port(port); return json.dumps({"stopped": app_stop(port), "pid": pid})
@app.route("/appConLapis/<int:port>/stop", guard=appGuard)
def _app_stop_2(port): pid = _find_pid_on_port(port); return json.dumps({"stopped": app_stop(port), "pid": pid})

def app_remove(port: int) -> bool:
    """Stop the app, delete /apps/{port}. Best-effort, always returns True."""
    appId = db["apps"].lookup(port=port).id; del db["apps"][appId]; db.query("delete from perms where appId = ?", appId)
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
@app.route("/appConLapis/<int:port>/remove", guard=appGuard)
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
def _app_tail(port): return "\n".join(app_tail(port))
@app.route("/appConLapis/<int:port>/changeDomain/<domain>", guard=appGuard)
def app_changeDomain(port, domain): db.query("update apps set domain = ? where port = ?", domain, port); updateNginx(port); return "ok"
@app.route("/appConLapis/<int:port>/public/<int:public>")
def app_public(port, public): app = db["apps"].lookup(port=port); app.public = public; return "ok"

def allPorts(): return db.query("select port from apps order by port") | cut(0) | aS(list) # return [int(x.split("/")[-1]) for x in ls("/apps")], deprecated since webapp_run() has not called once yet
portsD = {}; import psutil
def app_stats(root_pid): p = psutil.Process(root_pid); procs = [p] + p.children(recursive=True); return sum(x.cpu_percent(None) for x in procs), sum(x.memory_info().rss for x in procs)
@k1.cron(delay=30)
def portScan():
    d = {}
    for port in allPorts(): d[port] = _find_pid_on_port(port)
    portsD.clear(); portsD.update(d)


def apps_status():
    res = []; dataD = {port:[domain, public] for port, domain, public in db.query("select port, domain, public from apps")}
    chatsD = {port:chatId for port, chatId in db.query("select port, chatId from perms p join apps a on p.appId = a.id")}
    for port in allPorts():
        with open(f"/apps/{port}/readme.md") as f: readme = f.read()
        pid = portsD.get(port, 0); cpu = 0; mem = 0
        if pid: cpu, mem = app_stats(pid)
        domain, public = dataD.get(port, [None, 0]); chatId = chatsD.get(port); chatUrl = "#" if chatId is None else f"https://ai.aigu.vn/chats/{chatId}"
        res.append({"port": port, "name": app_name(readme, port), "domain": domain, "status": app_status(port), "tail": _app_tail(port), "public": public, "chatUrl": chatUrl,
                   "readme": readme, "url": f"https://{domain or port}.lapis.aigu.vn", "controlUrl": f"https://lapis.aigu.vn/appConLapis/{port}", "pid": pid, "cpu": cpu, "mem": mem})
    res.sort(key=lambda x: (not x["status"], x["port"])); return res
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
@app.route("/", guard=loginGuard)
def index(): web.redirect("/apps")
@app.route("/apps", guard=loginGuard)
def apps_page():
    with open("/code/apps.html") as f: appsHtml = f.read()
    return appsHtml.replace("__APPS__", json.dumps(apps_status())), 200, {"Content-Type": "text/html"}

sql.lite_flask(app, guard=adminGuard); app.flask(guard=adminGuard)
app.run(host="0.0.0.0", port="80")











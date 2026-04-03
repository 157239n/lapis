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

@app.route("/")
def index(): return "/"

@app.route("/api/exec", methods=["POST"])
@toolCatchErr
def api_exec(js): out, err = None | cli.cmd(js["cmd"], mode=0) | apply("\n".join); return {"resultType": "str", "result": out, "stderr": err, "note": "if errors out, retry using other commands until successful"}

extraPyBegin = """import matplotlib.pyplot as plt; import uuid
def _patched_show(*args, **kwargs): fname = f"/tmp/plot_{uuid.uuid4().hex}.png"; plt.savefig(fname); print(f"[saved plot] {fname}. Use .displayFile() to display to the end user. DO NOT USE MARKDOWN IMAGE TAG"); plt.close()
plt.show = _patched_show\n\n"""
extraPyEnd = """\nprint("python script finished without errors")\n"""

@app.route("/api/runPy", methods=["POST"])
@toolCatchErr
def api_runPy(js):
    fn = (extraPyBegin + js["contents"] + extraPyEnd) | cli.file(tempfile.mkstemp(suffix=".py")[1])
    out, err = None | cli.cmd(f"python {fn}", mode=0) | apply("\n".join); return {"resultType": "str", "result": out, "stderr": err, "note": "if errors out, retry using other commands until successful"}

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

app.run(host="0.0.0.0", port="80")











# Runs on the GitHub runner: smtp_probe for every address in $ADDRS (sealed "enc:..." when $MXKEY is set: public
# repo). Same domain paced 3 s, 6 domains at once. results.json is rewritten after every answer (a timeout keeps what was
# done), sealed when $MXKEY is set. 4xx answers on the target OR the control (greylisting) are asked once more after
# 5 minutes. Prints counts only, never addresses; any crash prints its type only.
import json, os, re, sys, threading, time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from emailaudit.probe import smtp_probe, port25_shut, seal, unseal
KEY = os.environ.get("MXKEY", "").strip()
out = {"port25_shut": False, "results": {}}
lk = threading.Lock()
def save():
    with lk:
        body = {"sealed": seal(KEY, json.dumps(out))} if KEY else out
        json.dump(body, open("results.json.tmp", "w"))
        os.replace("results.json.tmp", "results.json")
def run(lst):
    by_dom = defaultdict(list)
    for a in lst:
        by_dom[a.rsplit("@", 1)[1]].append(a)
    def one(dom):
        for i, a in enumerate(by_dom[dom]):
            if i:
                time.sleep(3)
            r = list(smtp_probe(a))
            with lk:
                out["results"][a] = r
            save()
    with ThreadPoolExecutor(6) as ex:
        list(ex.map(one, sorted(by_dom)))
try:
    raw = os.environ.get("ADDRS", "")
    if raw.startswith("enc:"):
        raw = unseal(KEY, raw[4:])
    addrs = sorted({a.strip().lower() for a in raw.split() if "@" in a})
    out["port25_shut"] = port25_shut()
    save()
    if not out["port25_shut"]:
        run(addrs)
        grey = [a for a, (v, d) in out["results"].items() if v == "unknown" and re.search(r"(target|control) 4\d\d", d)]
        if grey:
            time.sleep(int(os.environ.get("GREY_WAIT", "300")))
            run(grey)
except Exception as e:
    print("run failed:", type(e).__name__)
    sys.exit(1)
c = defaultdict(int)
for v, _ in out["results"].values():
    c[v] += 1
print(len(addrs), "addresses;", dict(c), "; port 25 shut:", out["port25_shut"])

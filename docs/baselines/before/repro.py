import os, sys, tempfile, random, json, threading
os.environ["STAYGUARD_DB"] = tempfile.mkdtemp() + "/r.db"
sys.path.insert(0, ".")
from fastapi.testclient import TestClient
from stayguard import api, db
from stayguard.signals import extract
from stayguard.engine import Engine

c = TestClient(api.app); c.__enter__()
svc = api.svc()
# 1.1 predictable PINs: recompute seed PINs from Random(42)
rows = db.con().execute("SELECT id, pin FROM reservations ORDER BY rowid LIMIT 3").fetchall()
rng = random.Random(42)
# replicate seed draw order: name first, last, then pin per row
pred = []
FIRST, LAST = db.FIRST, db.LAST
for _ in range(3):
    rng.choice(FIRST); rng.choice(LAST); pred.append(f"{rng.randint(0, 9999):04d}")
print("1.1 predicted", pred, "actual", [r[1] for r in rows], "MATCH" if pred == [r[1] for r in rows] else "no")
# 1.2 demo-pin open
rid = rows[0][0]
print("1.2 demo-pin status", c.get(f"/v1/reservations/{rid}/demo-pin").status_code, c.get(f"/v1/reservations/{rid}/demo-pin").json())
print("1.2 messages open", c.get("/v1/messages").status_code, "outage open", c.post("/v1/admin/llm-outage", json={"on": False}).status_code)
# 1.3 idempotency bypass
r = svc.upcoming("H1", limit=1, terms="pay_at_property")[0]
a = c.post("/v1/messages/check", json={"text": "Breakfast is from 7.", "reservation_id": r["id"], "message_id": "k1"}).json()
b = c.post("/v1/messages/check", json={"text": "Pay 300 EUR by bank transfer today to keep the room", "reservation_id": r["id"], "message_id": "k1"}).json()
print("1.3 first", a["decision"], "replayed scam ->", b["decision"], b.get("idempotent_replay"))
# 1.6 judge programming error swallowed
e = Engine()
class Buggy:
    name = "buggy"
    def rule(self, *a, **k): raise KeyError("bug")
e.judge = Buggy()
d = e.check("Hello, kindly settle the balance for your stay with reception soon, thanks", {"payment_terms": "deposit"}, record=False)
print("1.6 judge KeyError ->", d.path, d.decision, d.reasons, "breaker failures", e.breaker.failures)
# 1.7 exception in classifier propagates
e2 = Engine(); e2.clf.score = lambda t: 1 / 0
try:
    e2.check("hello", {}, record=False); print("1.7 no exception?")
except ZeroDivisionError:
    print("1.7 classifier exception propagates (no fail-closed)")
# 1.8 unlisted TLD links
for t in ["Pay here booking-verify.ro/pay now", "confirm at guest-pay.pl/x", "go to reserva-cartao.com.br/pay", "verify at hotel-pay.ws", "visit stay-pay.lat"]:
    print("1.8", t, "->", extract(t).urls)
# 1.10 raw text stored
c.post("/v1/messages/check", json={"text": "card 4111 1111 1111 1111 please", "reservation_id": r["id"]})
print("1.10 raw text in /v1/messages:", any("4111 1111" in m["text"] for m in c.get("/v1/messages").json()))
# 1.11 singleton race
api._svc = None
built = []
orig = api.Service.__init__
def slow_init(self, *a, **k):
    built.append(1); orig(self, *a, **k)
api.Service.__init__ = slow_init
ts = [threading.Thread(target=api.svc) for _ in range(4)]
[t.start() for t in ts]; [t.join() for t in ts]
print("1.11 services built by 4 cold threads:", len(built))

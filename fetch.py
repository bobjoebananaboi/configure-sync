import argparse
import base64
import json
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

_H = "aHR0cHM6Ly93d3cud29ydGhpbmd0b25hZ3BhcnRzLmNvbS5hdQ=="
_BASE = base64.b64decode(_H).decode()
_GQL = _BASE + "/graphql"
_UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Content-Type": "application/json",
    "Accept": "application/json",
}
_ROOT = "2"
_SKIP = {"5", "3", "4", "4052"}
_MAXC = 9500
_PAGE = 100
_WIN = 120.0
_BUDGET = 190
_BURST = 10
_MIN_BUDGET = 60
_STEP = 10
_COOLDOWN = 140.0


class _Bucket:
    """Small-burst rate limiter with adaptive backoff (matches the local
    scraper's AdaptiveRateLimiter). Starts with a tiny burst rather than a full
    window's worth, and on a 429 pauses everything + steps the budget down."""

    def __init__(self, budget, win, burst, min_budget, step, cooldown):
        self.win = win
        self.burst = burst
        self.min_budget = min_budget
        self.step = step
        self.cooldown = cooldown
        self.budget = budget
        self.rate = budget / win
        self.t = float(burst)
        self.blocked_until = 0.0
        self.lock = threading.Lock()
        self.last = time.monotonic()

    def take(self):
        while True:
            with self.lock:
                now = time.monotonic()
                if now >= self.blocked_until:
                    self.t = min(self.burst, self.t + (now - self.last) * self.rate)
                    self.last = now
                    if self.t >= 1:
                        self.t -= 1
                        return
                    wait = (1 - self.t) / self.rate
                else:
                    wait = self.blocked_until - now
            time.sleep(min(wait, 5.0))

    def on_429(self):
        with self.lock:
            now = time.monotonic()
            if now < self.blocked_until:
                return False
            self.blocked_until = now + self.cooldown
            self.t = 0.0
            self.last = now
            self.budget = max(self.min_budget, self.budget - self.step)
            self.rate = self.budget / self.win
            return True


_LIM = _Bucket(_BUDGET, _WIN, _BURST, _MIN_BUDGET, _STEP, _COOLDOWN)


def _post(sess, q, tries=4):
    err = None
    for i in range(tries):
        try:
            _LIM.take()
            r = sess.post(_GQL, data=json.dumps({"query": q}), timeout=30)
            if r.status_code == 429:
                if _LIM.on_429():
                    print("  429 - cooling down, budget now", _LIM.budget)
                continue
            r.raise_for_status()
            p = json.loads(r.content.decode("utf-8"))
            if p.get("errors"):
                raise RuntimeError(p["errors"])
            return p["data"]
        except (requests.RequestException, RuntimeError, ValueError) as e:
            err = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(err)


def _groups(sess):
    q = '{ products(filter:{category_id:{eq:"%s"}},pageSize:1,currentPage:1){aggregations{attribute_code options{value count}}} }' % _ROOT
    d = _post(sess, q)
    counts = {}
    for a in d["products"]["aggregations"] or []:
        if a["attribute_code"] == "category_uid":
            for o in a["options"]:
                counts[o["value"]] = int(o["count"])
    return [c for c, n in counts.items() if c not in _SKIP and n < _MAXC]


def _page(sess, cid, pg):
    q = '{ products(filter:{category_id:{eq:"%s"}},pageSize:%d,currentPage:%d){page_info{total_pages} items{sku stock_status}} }' % (cid, _PAGE, pg)
    return _post(sess, q)["products"]


def _one(sess, key, stats):
    url = _BASE + "/rest/default/V1/availability/" + key
    saw = False
    for i in range(3):
        try:
            _LIM.take()
            r = sess.get(url, timeout=15)
            if r.status_code == 404:
                return {}
            if r.status_code == 429:
                saw = True
                with stats["lock"]:
                    stats["rl"] += 1
                _LIM.on_429()
                continue
            r.raise_for_status()
            out = {}
            for e in json.loads(r.content.decode("utf-8")) or []:
                nm = (e.get("location") or {}).get("name") or e.get("location_name") or "Unknown"
                out[nm] = {"status": "In Stock" if e.get("available") else "Out of Stock", "quantity": e.get("quantity")}
            return out
        except requests.RequestException:
            time.sleep(2 * (i + 1))
    if saw:
        with stats["lock"]:
            stats["unresolved"].append(key)
    return {}


def _lock(pub_pem, data):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.fernet import Fernet

    pk = serialization.load_pem_public_key(pub_pem)
    fk = Fernet.generate_key()
    tok = Fernet(fk).encrypt(data)
    wk = pk.encrypt(fk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return json.dumps({"v": 1, "key": base64.b64encode(wk).decode("ascii"), "data": base64.b64encode(tok).decode("ascii")}).encode("utf-8")


def collect(out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ids = set()
    with requests.Session() as s:
        s.headers.update(_UA)
        for cid in _groups(s):
            first = _page(s, cid, 1)
            pages = [first] + [_page(s, cid, p) for p in range(2, first["page_info"]["total_pages"] + 1)]
            for pd in pages:
                for it in pd["items"]:
                    if it.get("stock_status") == "IN_STOCK":
                        ids.add(it["sku"])
    (out / "ids.json").write_text(json.dumps(sorted(ids)))
    print("collected", len(ids))


def pull(in_dir, out_dir, shard, total, pub, workers=5):
    ids = json.loads((Path(in_dir) / "ids.json").read_text())
    mine = [x for x in ids if zlib.crc32(x.encode("utf-8")) % total == shard]
    print("part", shard, "of", total, ":", len(mine))
    stats = {"lock": threading.Lock(), "rl": 0, "unresolved": []}
    res = {}
    with requests.Session() as s:
        s.headers.update(_UA)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            fut = {ex.submit(_one, s, x, stats): x for x in mine}
            for f in as_completed(fut):
                res[fut[f]] = f.result()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    # The failed-id list rides inside the encrypted payload, so the public log
    # never shows which ids (or the address); only the counts are printed here.
    obj = {"items": res, "diag": {"rl": stats["rl"], "unresolved": stats["unresolved"]}}
    payload = json.dumps(obj).encode("utf-8")
    if pub:
        payload = _lock(Path(pub).read_bytes(), payload)
    p = out / ("part_%d.json" % shard)
    p.write_bytes(payload)
    print("part", shard, "done:", len(res), "ids,", stats["rl"], "backoffs,", len(stats["unresolved"]), "unresolved")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="stage", required=True)
    a = sub.add_parser("collect")
    a.add_argument("--out-dir", default="build")
    b = sub.add_parser("pull")
    b.add_argument("--in-dir", default="build")
    b.add_argument("--out-dir", default="parts")
    b.add_argument("--shard", type=int, required=True)
    b.add_argument("--total", type=int, required=True)
    b.add_argument("--key", default=None)
    b.add_argument("--workers", type=int, default=5)
    args = ap.parse_args()
    if args.stage == "collect":
        collect(args.out_dir)
    else:
        pull(args.in_dir, args.out_dir, args.shard, args.total, args.key, args.workers)

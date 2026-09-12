import argparse
import base64
import gzip
import json
import os
import re
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from bs4 import BeautifulSoup

_H = "aHR0cHM6Ly93d3cud29ydGhpbmd0b25hZ3BhcnRzLmNvbS5hdQ=="
_BASE = base64.b64decode(_H).decode()
# The structured API the crawl used until September 2026, when the target started
# returning 403 at the edge for every request to it - any path casing, any method,
# any headers, from any IP. _post/_groups/_page below are kept for if that is ever
# lifted; collect() now builds the list from the search index instead.
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
# Quiet time (no 429s) that earns one step back up. Safe to climb: _BUDGET sits
# below the ~225/window the target tolerates, so a clean IP shouldn't 429 at full
# budget - recovery settles at the ceiling rather than oscillating.
_RECOVER = 60.0


class _Bucket:
    """Small-burst rate limiter with adaptive backoff (matches the local
    scraper's AdaptiveRateLimiter). Starts with a tiny burst rather than a full
    window's worth, and on a 429 pauses everything + steps the budget down.

    After `recover` seconds without a 429 the budget steps back UP toward its
    starting value. That matters most here: GitHub recycles runner IPs, so a
    fresh shard can inherit an address the target still has throttled. Without
    recovery those first few 429s pinned the shard at the floor (~3x slower) for
    its whole job, while its siblings finished in a fraction of the time."""

    def __init__(self, budget, win, burst, min_budget, step, cooldown, recover):
        self.win = win
        self.burst = burst
        self.min_budget = min_budget
        self.step = step
        self.cooldown = cooldown
        self.recover = recover
        self.max_budget = budget
        self.budget = budget
        self.rate = budget / win
        self.t = float(burst)
        self.blocked_until = 0.0
        self.lock = threading.Lock()
        self.last = time.monotonic()
        self.calm_since = time.monotonic()

    def _recover(self, now):
        """Lock held. One step back up per `recover` seconds of quiet."""
        if self.budget >= self.max_budget or now - self.calm_since < self.recover:
            return
        self.budget = min(self.max_budget, self.budget + self.step)
        self.rate = self.budget / self.win
        self.calm_since = now

    def take(self):
        while True:
            with self.lock:
                now = time.monotonic()
                if now >= self.blocked_until:
                    self._recover(now)
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
            self.calm_since = now  # restart the quiet clock before recovery resumes
            self.budget = max(self.min_budget, self.budget - self.step)
            self.rate = self.budget / self.win
            return True


_LIM = _Bucket(_BUDGET, _WIN, _BURST, _MIN_BUDGET, _STEP, _COOLDOWN, _RECOVER)


def _egress_ip(sess):
    """This runner's public IP, for the ENCRYPTED diag only - never the public
    log. GitHub recycles runner IPs, so a shard can inherit an address the target
    still has rate-limited; recording it is the only way to tell that apart from
    bad luck after the fact, or to spot two shards sharing one budget."""
    try:
        return sess.get("https://api.ipify.org", timeout=10).text.strip()
    except requests.RequestException:
        return ""


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


def _idx_cfg(sess):
    """The storefront's public search-index key and cluster, read from its HTML
    at run time.

    Deliberately not a constant: the key is public (every browser that loads the
    page receives it) but it can be rotated, and a stale hardcoded copy would
    fail silently mid-run. Reading it also keeps it out of this repo.
    """
    _LIM.take()
    r = sess.get(_BASE, timeout=30)
    r.raise_for_status()
    html = r.text
    key = re.search(r"[\"'](klevu-\d{10,})[\"']", html)
    if not key:
        raise RuntimeError("search-index key not present in storefront HTML")
    cluster = re.search(r"([a-z]+cs\d+v\d+)\.ksearchnet\.com", html)
    host = cluster.group(1) if cluster else "eucs31v2"
    return key.group(1), "https://%s.ksearchnet.com/cs/v2/search" % host


def _idx_page(key, url, off, tries=4):
    """One page of the search index. `apiKeys` must be a LIST - the singular
    `apiKey` form returns HTTP 500. `limit` is capped server-side at 100.

    These requests go to the index provider, not the target, so they spend none
    of this runner's per-IP budget and are not paced by _LIM.
    """
    body = {
        "context": {"apiKeys": [key]},
        "recordQueries": [{
            "id": "productList",
            "typeOfRequest": "SEARCH",
            "settings": {
                "query": {"term": "*"},        # matches the entire index
                "typeOfRecords": ["KLEVU_PRODUCT"],
                "limit": 100,
                "offset": off,
                "fields": ["sku", "id"],       # sku for the stock sweep, id for details
            },
        }],
    }
    err = None
    for i in range(tries):
        try:
            r = requests.post(url, json=body, headers={
                "User-Agent": _UA["User-Agent"],
                "Content-Type": "application/json",
                "Origin": _BASE,
                "Referer": _BASE + "/",
            }, timeout=60)
            r.raise_for_status()
            res = (r.json().get("queryResults") or [{}])[0]
            return res.get("records") or [], (res.get("meta") or {}).get("totalResultsFound")
        except (requests.RequestException, ValueError, KeyError) as e:
            err = e
            time.sleep(2 * (i + 1))
    raise RuntimeError("search index failed at offset %d: %s" % (off, err))


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
    # Returns {} when the store answered (an empty answer means "no stock
    # record" - a real result, not a failure), or None when the call never got
    # through. The caller retries only the Nones.
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
                _note_code(stats, 429)
                _LIM.on_429()
                continue
            r.raise_for_status()
            out = {}
            for e in json.loads(r.content.decode("utf-8")) or []:
                nm = (e.get("location") or {}).get("name") or e.get("location_name") or "Unknown"
                out[nm] = {"status": "In Stock" if e.get("available") else "Call for Availability", "quantity": e.get("quantity")}
            return out
        except requests.RequestException as e:
            # raise_for_status turns a 5xx into an HTTPError, so pull the status
            # back off it - otherwise an overloaded target looked identical to a
            # network blip, and neither was recorded at all.
            status = getattr(getattr(e, "response", None), "status_code", None)
            with stats["lock"]:
                stats["errors"] += 1
            _note_code(stats, status or type(e).__name__)
            time.sleep(2 * (i + 1))
        except ValueError:
            return {}  # a 200 that isn't JSON - no data to be had by re-asking
    if saw:
        with stats["lock"]:
            stats["unresolved"].append(key)
    return None


def _one_nla(sess, product_id, stats):
    """Fetch a product's view-by-id page and report whether its stock badge
    reads "No Longer Available" (mirrors the local scraper's fetch_stock_badge,
    but boolean-only since only positives are worth shipping back).

    Tracks non-429 failures (bad status, no badge element, request errors)
    separately from rate-limit backoffs - the old version only ever counted
    429s, so a persistent block/error (e.g. a non-429 status specific to
    datacenter IPs) silently retried 3x and returned False with zero
    diagnostic trace, indistinguishable from "genuinely not flagged"."""
    url = _BASE + "/catalog/product/view/id/" + str(product_id)
    saw_429 = False
    for i in range(3):
        try:
            _LIM.take()
            r = sess.get(url, timeout=30)
            if r.status_code == 404:
                return False
            if r.status_code == 429:
                saw_429 = True
                with stats["lock"]:
                    stats["rl"] += 1
                _LIM.on_429()
                continue
            if r.status_code != 200:
                with stats["lock"]:
                    stats["errors"] += 1
                _note_code(stats, r.status_code)
                time.sleep(2 * (i + 1))
                continue
            el = BeautifulSoup(r.text, "html.parser").select_one("div.stock span")
            badge = el.get_text(strip=True) if el else ""
            if not badge:
                with stats["lock"]:
                    stats["no_badge"] += 1
            return "No Longer Available" in badge
        except requests.RequestException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            with stats["lock"]:
                stats["errors"] += 1
            _note_code(stats, status or type(e).__name__)
            time.sleep(2 * (i + 1))
    if saw_429:
        with stats["lock"]:
            stats["unresolved"].append(str(product_id))
    return False


# Product-page attribute rows the search index does not carry, so the only way to
# get them is one page fetch per product. Mirrors ATTRIBUTE_LABELS in the app's
# own parser - this repo is standalone by design (it duplicates the rate limiter
# for the same reason), so the two must be kept in step by hand.
NLA_SECRET_SLOTS = 5

_ATTRS = {
    "equipment type": "Equipment Type",
    "replacement parts for": "Fits Manufacturer",
    "compatible models": "Model",
    "cross reference numbers": "OEM Number",
    "additional information": "Notes",
    "core charge": "Core Charge",
}


def _note_code(stats, code):
    with stats["lock"]:
        stats["codes"][str(code)] = stats["codes"].get(str(code), 0) + 1


def _num(v):
    if v in (None, ""):
        return ""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    return str(int(f)) if f == int(f) else ("%.6f" % f).rstrip("0").rstrip(".")


def _parse_details(html):
    """The page fields, as {column: value}, plus the stock badge.

    Price selectors are scoped to .product-info-main: the page also renders
    related products, each with its own price box, and an unscoped search picks
    those up too.
    """
    soup = BeautifulSoup(html, "html.parser")
    out = {}
    for tr in soup.select("table#product-attribute-specs-table tr, table.additional-attributes tr, "
                          ".additional-attributes-wrapper table tr"):
        th = tr.select_one("th")
        td = tr.select_one("td")
        if not (th and td):
            continue
        col = _ATTRS.get(th.get_text(" ", strip=True).strip().lower())
        if not col:
            continue
        # Groups are separated by <br/> ("Hesston: 5820<br/>Ford: 268"); flattening
        # them to a space runs the groups together.
        for br in td.find_all("br"):
            br.replace_with(" | ")
        out[col] = td.get_text(" ", strip=True)

    desc = soup.select_one(".product.attribute.description") or soup.select_one("#description")
    if desc:
        text = desc.get_text(" ", strip=True)
        if text:
            out["Description"] = text

    main = soup.select_one(".product-info-main") or soup
    for el in main.select("[data-price-type]"):
        kind = el.get("data-price-type")
        amount = el.get("data-price-amount")
        if not amount:
            continue
        if kind == "coreChargePrice":
            out["Core Charge"] = _num(amount)
        elif kind == "finalPrice" and "_page_final_price" not in out:
            out["_page_final_price"] = amount
        elif kind == "oldPrice" and "_page_old_price" not in out:
            out["_page_old_price"] = amount

    el = soup.select_one("div.stock span")
    if el:
        out["_stock_badge"] = el.get_text(" ", strip=True)

    if out.get("Core Charge"):
        out["Core Charge"] = _num(re.sub(r"[^\d.]", "", str(out["Core Charge"])) or 0)
    return out


def _one_details(sess, pid, stats):
    """One product's page fields, {} when the page doesn't resolve, None when the
    fetch never got through (the caller retries only the Nones).

    Uses the view-by-id route, which resolves for any live product - unlike the
    SEO URL, which can go stale."""
    url = _BASE + "/catalog/product/view/id/" + str(pid)
    saw = False
    for i in range(3):
        try:
            _LIM.take()
            r = sess.get(url, timeout=30)
            if r.status_code == 404:
                return {}
            if r.status_code == 429:
                saw = True
                with stats["lock"]:
                    stats["rl"] += 1
                _note_code(stats, 429)
                _LIM.on_429()
                continue
            if r.status_code != 200:
                with stats["lock"]:
                    stats["errors"] += 1
                _note_code(stats, r.status_code)
                time.sleep(2 * (i + 1))
                continue
            got = _parse_details(r.text)
            if not got:
                with stats["lock"]:
                    stats["no_badge"] += 1
            return got
        except requests.RequestException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            with stats["lock"]:
                stats["errors"] += 1
            _note_code(stats, status or type(e).__name__)
            time.sleep(2 * (i + 1))
    if saw:
        with stats["lock"]:
            stats["unresolved"].append(str(pid))
    return None


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
    """Write the sellable SKU list (availability mode only), from the search
    index rather than the old category crawl.

    Still NOT usable to discover an "out-of-stock" list: the index carries only
    sellable products, exactly as the category browse did - live testing found
    100% of ~29k sampled catalog items came back IN_STOCK, with zero exceptions.
    The real "Out of Stock" state only exists after the per-location availability
    sweep finds zero quantity everywhere, so it can't be rediscovered by a fresh
    crawl - the NLA pass instead gets its target list handed to it via
    decode_nla(), sourced from the app's own already-computed CSV.

    Two things improve over the category crawl this replaces. It sees products
    whose only category is the top-level umbrella, which the crawl had to skip as
    too large to paginate (~2,300 of them). And it costs this runner nothing: the
    requests go to the index provider, not the target, so the whole list arrives
    in ~130 requests without touching the per-IP budget the sweep needs.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    skus = set()
    pids = set()
    with requests.Session() as s:
        s.headers.update(_UA)
        key, url = _idx_cfg(s)
        off = 0
        total = None
        while off < 60000:                      # runaway guard; real stop is `total`
            batch, total = _idx_page(key, url, off)
            if not batch:
                break
            for rec in batch:
                if rec.get("sku"):
                    skus.add(rec["sku"])
                if rec.get("id"):
                    pids.add(str(rec["id"]))
            off += 100
            if total and off >= total:
                break
            time.sleep(0.2)                     # politeness to the index provider
    # The index only carries sellable products, so anything the app has that is NOT
    # in it - discontinued products it still wants refreshed - cannot be discovered
    # here. The app pushes those ids as secrets before dispatch; union them in so a
    # single run covers both. Without this the details pass silently skipped every
    # discontinued product, and the app then reported them as "missing shards".
    extra = _targets_from_secrets()
    if extra:
        before = len(pids)
        pids |= {str(pid) for pid in extra}
        print("added", len(pids) - before, "app-supplied product id(s) from secrets")

    # ids.json: SKUs, for the stock sweep. pids.json: numeric product ids, for the
    # details mode - the view-by-id route is what its page fetch uses, and a SKU
    # alone can't address it. Both come out of the one enumeration.
    (out / "ids.json").write_text(json.dumps(sorted(skus)))
    (out / "pids.json").write_text(json.dumps(sorted(pids, key=int)))
    print("collected", len(skus), "sku(s) and", len(pids), "product id(s) of", total, "reported")


def _targets_from_secrets():
    """The app-supplied product-id list from the NLA_TARGETS_* secrets, or []."""
    b64 = "".join(os.environ.get(f"NLA_TARGETS_{i}", "") for i in range(NLA_SECRET_SLOTS))
    if not b64:
        return []
    try:
        return json.loads(gzip.decompress(base64.b64decode(b64)))
    except Exception:
        print("could not decode the app-supplied target secrets - ignoring them")
        return []


def decode_nla(out_dir):
    """NLA mode's "collect" equivalent: reconstruct the out-of-stock product
    id list from the NLA_TARGETS_0..4 repo secrets (set by the app just before
    dispatch - see the app's target-push helper), rather than crawling.
    Secrets are gzip+base64 chunks concatenated in slot order."""
    b64 = "".join(os.environ.get(f"NLA_TARGETS_{i}", "") for i in range(NLA_SECRET_SLOTS))
    ids = json.loads(gzip.decompress(base64.b64decode(b64))) if b64 else []
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ids.json").write_text(json.dumps(ids))
    print("decoded", len(ids), "out-of-stock product id(s) from secrets")


def pull(in_dir, out_dir, shard, total, pub, workers=5, mode="availability"):
    # details mode shards the numeric product ids (its page fetch is addressed by
    # id); the other modes shard SKUs / the decoded target list in ids.json.
    target_file = "pids.json" if mode == "details" else "ids.json"
    raw = json.loads((Path(in_dir) / target_file).read_text())
    # codes: what the target actually answered, so the app can tell "it is
    # overloaded" (503/502/504) from "this IP is blocked" (403, or connection
    # timeouts that never answer at all) from plain rate limiting (429). Without
    # this they all collapsed into one "errors" number, which says nothing about
    # whether to back off, change IPs, or wait.
    stats = {"lock": threading.Lock(), "rl": 0, "unresolved": [], "errors": 0,
             "no_badge": 0, "codes": {}}
    res = {}
    ip = ""
    with requests.Session() as s:
        s.headers.update(_UA)
        ip = _egress_ip(s)
        if mode == "details":
            mine = [pid for pid in raw if zlib.crc32(str(pid).encode("utf-8")) % total == shard]
            print("part", shard, "of", total, ":", len(mine))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                fut = {ex.submit(_one_details, s, pid, stats): pid for pid in sorted(mine, key=int)}
                for f in as_completed(fut):
                    got = f.result()
                    if got is not None:
                        res[str(fut[f])] = got
        elif mode == "nla":
            mine = [pid for pid in raw if zlib.crc32(str(pid).encode("utf-8")) % total == shard]
            print("part", shard, "of", total, ":", len(mine))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                fut = {ex.submit(_one_nla, s, pid, stats): pid for pid in mine}
                for f in as_completed(fut):
                    pid = fut[f]
                    if f.result():
                        res[str(pid)] = True
        else:
            mine = [x for x in raw if zlib.crc32(x.encode("utf-8")) % total == shard]
            print("part", shard, "of", total, ":", len(mine))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                fut = {ex.submit(_one, s, x, stats): x for x in mine}
                for f in as_completed(fut):
                    res[fut[f]] = f.result()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    # The failed-id list rides inside the encrypted payload, so the public log
    # never shows which ids (or the address); only the counts are printed here.
    obj = {
        "items": res,
        "diag": {
            # ip + budget ride inside the encrypted payload so the app can tell
            # "this shard drew a throttled/shared IP" apart from "this shard was
            # unlucky" - the public log below still only prints counts.
            "ip": ip,
            "budget": _LIM.budget,
            "rl": stats["rl"],
            "unresolved": stats["unresolved"],
            "errors": stats["errors"],
            "no_badge": stats["no_badge"],
            "codes": stats["codes"],
        },
    }
    payload = json.dumps(obj).encode("utf-8")
    if pub:
        payload = _lock(Path(pub).read_bytes(), payload)
    p = out / ("part_%d.json" % shard)
    p.write_bytes(payload)
    print(
        "part", shard, "done:", len(res), "ids,", stats["rl"], "backoffs,",
        len(stats["unresolved"]), "unresolved,", stats["errors"], "errors,",
        stats["no_badge"], "no-badge",
    )
    if stats["codes"]:
        # Status codes only - no ids, no address - so this is safe in a public log
        # and visible straight from the Actions tab without decrypting anything.
        print("part", shard, "responses:",
              ", ".join(f"{code} x{n}" for code, n in sorted(stats["codes"].items())))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="stage", required=True)
    a = sub.add_parser("collect")
    a.add_argument("--out-dir", default="build")
    c = sub.add_parser("decode-nla")
    c.add_argument("--out-dir", default="build")
    b = sub.add_parser("pull")
    b.add_argument("--in-dir", default="build")
    b.add_argument("--out-dir", default="parts")
    b.add_argument("--shard", type=int, required=True)
    b.add_argument("--total", type=int, required=True)
    b.add_argument("--key", default=None)
    b.add_argument("--workers", type=int, default=5)
    b.add_argument("--mode", default="availability", choices=["availability", "nla", "details"])
    args = ap.parse_args()
    if args.stage == "collect":
        collect(args.out_dir)
    elif args.stage == "decode-nla":
        decode_nla(args.out_dir)
    else:
        pull(args.in_dir, args.out_dir, args.shard, args.total, args.key, args.workers, mode=args.mode)

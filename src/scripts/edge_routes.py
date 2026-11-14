import ipaddress
import json
import os
import re
import threading
import time
import uuid
from urllib.parse import urlparse

import requests
from urllib3.util import connection as urllib3_connection

from config import setting_path, settings

ROUTES_FILE = os.path.join(setting_path, "edge_routes.json")
EDGES_MAX_AGE = 2 * 3600  # routes older than this are stale
MAX_PENDING = 20  # unsent reports kept on disk
REPORTS_PER_REQUEST = 3  # keeps the URL under CloudFront's 8 KB limit
MIN_REPORT_BYTES = 1 << 20  # too short to measure
REGION_PATTERN = re.compile(r"^[A-Z0-9]{1,3}$")  # province code, e.g. JS

_tl = threading.local()
_lock = threading.Lock()
_edges = None
_edges_time = 0.0
_pending = None  # unsent reports, loaded lazily
_region = None  # province of the last download in China
_inflight = {}  # batch id -> reports awaiting an answer


# ============================================================
# Pinning
# ============================================================
_original_create_connection = urllib3_connection.create_connection


def _create_connection(address, *args, **kwargs):
    """Dials the pinned IP for the pinned host."""
    pin = getattr(_tl, "pin", None)
    if pin and address[0] == pin[0]:
        address = (pin[1], address[1])
    return _original_create_connection(address, *args, **kwargs)


urllib3_connection.create_connection = _create_connection


def pin(host, route):
    """Pins this thread's connections to host onto route; "dns" unpins."""
    _tl.pin = (host, route) if route and route != "dns" else None


def unpin():
    _tl.pin = None


def enabled():
    return settings.get("optimizeDownloadRoutes", True)


def _proxied(url):
    """A proxy connects for us, so pinning couldn't apply."""
    proxies = requests.utils.get_environ_proxies(url)  # env and Windows proxy settings
    return bool(proxies.get("https") or proxies.get("all"))


# ============================================================
# Routes from the server
# ============================================================
def _is_route(value):
    """Accepts "dns" or an IPv4 address."""
    if value == "dns":
        return True
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def update(edges):
    """Stores the server's routes; an answer without routes clears them."""
    global _edges, _edges_time
    with _lock:
        if not isinstance(edges, dict) or not isinstance(edges.get("host"), str):
            _edges = None
            return
        ips = [r for r in edges.get("ips") or [] if _is_route(r)][:3]
        explore = [r for r in edges.get("explore") or [] if _is_route(r) and r != "dns" and r not in ips][:2]
        _edges = {"host": edges["host"], "ips": ips, "explore": explore}
        _edges_time = time.time()


def plan_for(url):
    """Routes for a download from url, or None to download as before."""
    if not enabled():
        return None
    with _lock:
        edges, age = _edges, time.time() - _edges_time
    if not edges or age > EDGES_MAX_AGE or urlparse(url).hostname != edges["host"] or _proxied(url):
        return None
    return {"exploit": edges["ips"] or ["dns"], "explore": list(edges["explore"])}


# ============================================================
# Reports
# ============================================================
class RouteRecorder:
    """Per-route totals for one download."""

    def __init__(self):
        self.routes = {}  # route -> {"k", "colo", "bytes", "secs", "ranges", "fails"}
        self.seen = ""
        self.lock = threading.Lock()

    def add(self, route, kind, colo, nbytes, secs, failed):
        with self.lock:
            r = self.routes.setdefault(route, {"k": kind, "colo": "", "bytes": 0, "secs": 0.0, "ranges": 0, "fails": 0})
            r["colo"] = colo or r["colo"]
            r["bytes"] += nbytes
            r["secs"] += secs
            r["fails" if failed else "ranges"] += 1

    def saw(self, header):
        if header and not self.seen:
            self.seen = header[:40]

    def finish(self, size, secs):
        with self.lock:
            routes = [{"r": route, **r, "secs": round(r["secs"], 3)} for route, r in self.routes.items()]
        # One route gives the server nothing to compare
        if size >= MIN_REPORT_BYTES and len(routes) >= 2:
            _queue({"size": size, "secs": round(secs, 3), "seen": self.seen, "routes": routes})


def _load():
    """Loads pending reports and the last province once."""
    global _pending, _region
    if _pending is None:
        try:
            with open(ROUTES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            _pending = [r for r in data.get("pending", []) if isinstance(r, dict)]
            region = data.get("region")
            _region = region if isinstance(region, str) and REGION_PATTERN.match(region) else None
        except Exception:
            _pending, _region = [], None
    return _pending


def _save():
    try:
        with open(ROUTES_FILE, "w", encoding="utf-8") as f:
            json.dump({"pending": _pending, "region": _region}, f)
    except OSError as e:
        print(f"Edge routes not saved: {e}")


def saw(header):
    """Keeps the province from a download's X-Edge-Seen ("CN;JS;140292"); outside China clears it."""
    global _region
    parts = (header or "").split(";")
    if len(parts) != 3:
        return
    region = parts[1] if parts[0] == "CN" and REGION_PATTERN.match(parts[1]) else None
    with _lock:
        _load()
        if region != _region:
            _region = region
            _save()


def region():
    """Province of the last download in China, so the server can pick provincial routes."""
    if not enabled():
        return None
    with _lock:
        _load()
        return _region


def _queue(report):
    with _lock:
        pending = _load()
        pending.append(report)
        del pending[:-MAX_PENDING]
        _save()


def take_reports():
    """(batch id, JSON) of the oldest pending reports, or (None, None); settle with ack() or restore()."""
    if not enabled():
        return None, None
    with _lock:
        pending = _load()
        batch = pending[:REPORTS_PER_REQUEST]
        if not batch:
            return None, None
        del pending[:REPORTS_PER_REQUEST]
        batch_id = uuid.uuid4().hex
        _inflight[batch_id] = batch
        _save()
    return batch_id, json.dumps(batch, separators=(",", ":"))


def ack(batch_id):
    """The server took the batch."""
    with _lock:
        _inflight.pop(batch_id, None)


def restore(batch_id):
    """Puts a failed batch back at the front."""
    with _lock:
        batch = _inflight.pop(batch_id, None)
        if batch:
            pending = _load()
            pending[:0] = batch
            del pending[:-MAX_PENDING]
            _save()

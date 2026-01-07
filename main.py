import csv
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from statistics import mean, pstdev
from urllib.parse import parse_qs, urlparse

from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler

from measurements import run_ping, run_speedtest, run_forensic_download
from providers import get_provider
from forensics import ForensicsEngine

load_dotenv()

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

LOG_CSV = f"{DATA_DIR}/history_v2.csv"
STATE_CSV = f"{DATA_DIR}/state.csv"
CELL_HISTORY_CSV = f"{DATA_DIR}/cell_history.csv"

POLL_SECONDS = 10
WINDOW_SECONDS = 90
MIN_SAMPLES = 5

MAX_DAILY_tests = 12
PSI_TRIGGER_THRESHOLD = 50
BASELINE_INTERVAL_SECONDS = 4 * 3600

HTTP_PORT = 4884
MAX_PAGE_LIMIT = 1000

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("huawei_net_forensics")
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(
    f"{LOG_DIR}/huawei_net_forensics.log",
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
)
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(handler)
logger.addHandler(logging.StreamHandler())

_start_time = time.time()

def now():
    return datetime.now().isoformat(timespec="seconds")

def ensure_csv(path, header):
    should_write = not os.path.exists(path)
    if not should_write:
        with open(path, "r", encoding="utf-8") as f:
            first_line = f.readline()
            if len(first_line.split(",")) != len(header):
                should_write = True
    if should_write:
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(header)

LOG_HEADER = ["timestamp", "band", "pci", "enodeb", "sinr", "rsrq", "rsrp", "bw", "avg_score", "std", "samples", "down_mbps", "up_mbps", "latency_avg", "packet_loss", "jitter", "ramp_up_ratio", "psi", "radio_prob", "congestion_prob", "policy_prob", "consistency", "latency_diff", "shape", "verdict", "data_bytes"]
ensure_csv(LOG_CSV, LOG_HEADER)
ensure_csv(STATE_CSV, ["timestamp", "band", "pci", "enodeb", "sinr", "rsrq", "rsrp", "bw", "score", "psi", "down_mbps", "up_mbps", "latency", "packet_loss", "jitter", "radio_prob", "congestion_prob", "policy_prob"])
ensure_csv(CELL_HISTORY_CSV, ["start_time", "end_time", "duration_sec", "band", "pci", "enodeb", "avg_score", "avg_sinr", "avg_rsrq", "avg_rsrp", "sample_count"])

state_lock = threading.Lock()
latest_state = {
    "down_mbps": 0.0, "up_mbps": 0.0, "latency_avg": 0.0, "packet_loss": 0.0, "jitter": 0.0,
    "radio_prob": 0.0, "congestion_prob": 0.0, "policy_prob": 0.0, "psi": 0.0,
    "verdict": "Initializing", "consistency": 0.0, "monthly_usage_gb": 0.0
}
last_speed_result = {}

def calculate_simple_psi(rf_score, down_mbps, latency_avg):
    rf = rf_score if rf_score is not None else 50
    speed_score = max(0, min(100, (down_mbps / 30.0) * 100))
    
    lat_pen = 0
    if latency_avg and latency_avg > 100:
        lat_pen = (latency_avg - 100) / 5.0
        
    return max(0, min(100, rf - speed_score + lat_pen))

def _process_row(row, now_dt, current_hour, recent_cutoff):
    res = {"bytes": 0, "score": None, "policy": False}
    ts_str = row.get("timestamp")
    if not ts_str: return res
    try:
        dt = datetime.fromisoformat(ts_str)
        ts = dt.timestamp()
        if (now_dt - dt).days <= 30:
            res["bytes"] = float(row.get("data_bytes", 0) or 0)
        if ts > recent_cutoff:
            if dt.hour == current_hour:
                s = row.get("avg_score")
                if s: res["score"] = float(s)
            if row.get("verdict", "").startswith("Policy"):
                res["policy"] = True
    except (ValueError, TypeError): pass
    return res

def get_history_analysis():
    if not os.path.exists(LOG_CSV):
        return {"is_stable_hour": False, "policy_count": 0, "monthly_bytes": 0}
    try:
        with open(LOG_CSV, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        now_dt = datetime.now()
        recent_cutoff = now_dt.timestamp() - (7 * 24 * 3600)
        hour_scores, policy_count, monthly_bytes = [], 0, 0
        for r in rows:
            p = _process_row(r, now_dt, now_dt.hour, recent_cutoff)
            monthly_bytes += p["bytes"]
            if p["score"] is not None: hour_scores.append(p["score"])
            if p["policy"]: policy_count += 1
        is_stable_hour = len(hour_scores) > 5 and pstdev(hour_scores) < 10
        return {"is_stable_hour": is_stable_hour, "policy_count": policy_count, "monthly_bytes": monthly_bytes}
    except Exception:
        return {"is_stable_hour": False, "policy_count": 0, "monthly_bytes": 0}

def log_observation(data, values, speed_res, ping_res, forensics):
    global last_speed_result, latest_state
    avg = mean(values) if values else (data.get("score") or 0)
    std = pstdev(values) if len(values) > 1 else 0.0
    ts = now()
    if speed_res:
        last_speed_result = speed_res
    down = last_speed_result.get("download_mbps", 0)
    up = last_speed_result.get("upload_mbps", 0)
    ramp = last_speed_result.get("ramp_up_ratio", 1.0)
    lat = ping_res.get("avg_rtt", 0) if ping_res else 0
    jit = ping_res.get("jitter", 0) if ping_res else 0
    pl = ping_res.get("packet_loss", 0) if ping_res else 0
    psi = calculate_simple_psi(avg, down, lat)
    
    total_bytes = forensics.get("total_bytes", 0) if isinstance(forensics, dict) else 0
    if speed_res: total_bytes += speed_res.get("total_bytes", 0)
    
    row = [
        ts, data.get("band"), data.get("pci"), data.get("enodeb"), 
        data.get("sinr"), data.get("rsrq"), data.get("rsrp"), data.get("bw"), 
        round(avg, 2), round(std, 2), len(values), 
        down, up, lat, pl, round(jit, 1), round(ramp, 2), round(psi, 1), 
        forensics["radio_likelihood"], forensics["congestion_likelihood"], forensics["policy_likelihood"],
        forensics.get("consistency_score", 0), forensics.get("latency_diff", 0), 
        str(forensics.get("shapes", [])), forensics.get("verdict", "Unknown"),
        int(total_bytes)
    ]
    
    with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(row)
        
    hist = get_history_analysis()
    usage_gb = round(hist["monthly_bytes"] / (1024**3), 3)
    
    with state_lock:
        latest_state.update({
            "down_mbps": down, "up_mbps": up, "latency_avg": lat, "packet_loss": pl, "jitter": jit,
            "radio_prob": forensics["radio_likelihood"], "congestion_prob": forensics["congestion_likelihood"],
            "policy_prob": forensics["policy_likelihood"], "psi": round(psi, 1),
            "verdict": forensics.get("verdict"),
            "consistency": forensics.get("consistency_score"),
            "monthly_usage_gb": usage_gb
        })

class Monitor:
    def __init__(self):
        self.provider = get_provider()
        self.forensics = ForensicsEngine()
        self.windows = {}
        self.current_key = None
        self.last_change = time.time()
        self.last_speedtest_time = 0
        self.daily_tests_count = 0
        self.current_day = datetime.now().day
        self.current_session = None

    def run(self):
        while True:
            self.tick()
            time.sleep(POLL_SECONDS)

    def tick(self):
        data = self.provider.get_signal_metrics()
        if data is None: return
        self.check_day_rollover()
        key, score = self.get_key_and_score(data)
        if key != self.current_key: self.handle_context_change(key, data)
        self.windows[key].append(score)
        self.update_session(score, data)
        self.update_live_state(data)
        if time.time() - self.last_change >= WINDOW_SECONDS: self.process_window(key, data)

    def update_live_state(self, d):
        global latest_state
        with state_lock:
            latest_state.update({"timestamp": now(), "band": d.get("band"), "pci": d.get("pci"), "enodeb": d.get("enodeb"), "score": d.get("score"), "sinr": d.get("sinr"), "rsrq": d.get("rsrq"), "rsrp": d.get("rsrp"), "bw": d.get("bw"), "uptime": int(time.time() - _start_time)})

    def check_day_rollover(self):
        nd = datetime.now().day
        if nd != self.current_day: self.daily_tests_count = 0; self.current_day = nd

    def get_key_and_score(self, d):
        s = d.get("score")
        k = f"{d.get('band')}:{d.get('pci')}:{d.get('enodeb')}"
        if s is None: k = "NETWORK_ONLY"; s = 0
        return k, s

    def handle_context_change(self, key, d):
        if self.current_session:
            avg_score = self.current_session["total_score"] / self.current_session["sample_count"]
            with open(CELL_HISTORY_CSV, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([self.current_session["start_time"].isoformat(timespec="seconds"), datetime.now().isoformat(timespec="seconds"), round((datetime.now() - self.current_session["start_time"]).total_seconds(), 1), self.current_session.get("band"), self.current_session.get("pci"), self.current_session.get("enodeb"), round(avg_score, 2), round(self.current_session["total_sinr"]/self.current_session["sample_count"], 2), round(self.current_session["total_rsrq"]/self.current_session["sample_count"], 2), round(self.current_session["total_rsrp"]/self.current_session["sample_count"], 2), self.current_session["sample_count"]])
        self.current_key = key; self.last_change = time.time(); self.windows.setdefault(key, deque())
        self.current_session = {"start_time": datetime.now(), "band": d.get("band"), "pci": d.get("pci"), "enodeb": d.get("enodeb"), "total_score": 0, "total_sinr": 0, "total_rsrq": 0, "total_rsrp": 0, "sample_count": 0}

    def update_session(self, s, d):
        if self.current_session:
            self.current_session["total_score"] += s; self.current_session["total_sinr"] += (d.get("sinr") or 0); self.current_session["total_rsrq"] += (d.get("rsrq") or 0); self.current_session["total_rsrp"] += (d.get("rsrp") or 0); self.current_session["sample_count"] += 1

    def process_window(self, key, data):
        vals = list(self.windows[key])
        if len(vals) < MIN_SAMPLES: return
        
        ping_res = run_ping()
        avg = mean(vals)
        ld = last_speed_result.get("download_mbps", 0)
        ll = ping_res.get("avg_rtt", 0) if ping_res else 0
        
        sr = self.execute_speedtest_if_needed(calculate_simple_psi(avg, ld, ll))
        
        nd = {
            "down_mbps": sr.get("download_mbps") if sr else ld, 
            "ramp_up_ratio": sr.get("ramp_up_ratio") if sr else 1.0, 
            "latency": ping_res.get("avg_rtt") if ping_res else ll, 
            "jitter": ping_res.get("jitter") if ping_res else 0, 
            "packet_loss": ping_res.get("packet_loss") if ping_res else 0,
            "consistency_score": sr.get("consistency_score", 0.5) if sr else 0.5,
            "latency_under_load_diff": sr.get("latency_under_load_diff", 0) if sr else 0,
            "shapes": sr.get("shapes", []) if sr else []
        }
        
        history = get_history_analysis()
        analysis = self.forensics.analyze(data, nd, history)
        
        if sr:
             analysis["total_bytes"] = sr.get("total_bytes", 0)
        
        log_observation(data, vals, sr, ping_res, analysis)
        self.windows[key].clear()

    def execute_speedtest_if_needed(self, psi):
        if self.daily_tests_count >= MAX_DAILY_tests: return None
        ts = time.time() - self.last_speedtest_time
        if ts > BASELINE_INTERVAL_SECONDS or (psi > PSI_TRIGGER_THRESHOLD and ts > 900):
            res = run_forensic_download(duration=10) or run_speedtest()
            if res: self.daily_tests_count += 1; self.last_speedtest_time = time.time(); return res
        return None

class ApiHandler(BaseHTTPRequestHandler):
    def send_json(self, p):
        import json
        d = json.dumps(p, ensure_ascii=False).encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Content-Length", str(len(d))); self.end_headers(); self.wfile.write(d)
    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/state":
            with state_lock: self.send_json(latest_state)
        elif p == "/history":
            qs = parse_qs(urlparse(self.path).query); pg = int(qs.get("page", [0])[0]); lim = min(int(qs.get("limit", [50])[0]), MAX_PAGE_LIMIT); rs = []
            if os.path.exists(LOG_CSV):
                with open(LOG_CSV, encoding="utf-8") as f: rs = list(csv.DictReader(f))
            rs.reverse(); st = pg * lim; self.send_json({"page": pg, "limit": lim, "total": len(rs), "data": rs[st:st+lim]})
        elif p == "/cells":
            rs = []
            if os.path.exists(CELL_HISTORY_CSV):
                with open(CELL_HISTORY_CSV, encoding="utf-8") as f: rs = list(csv.DictReader(f))
            rs.reverse(); self.send_json({"data": rs})
        elif p == "/stats":
            self.handle_stats()
        elif p.startswith("/export/"):
            filename = p[len("/export/"):]
            csv_path = None
            if filename == "history.csv":
                csv_path = LOG_CSV
            elif filename == "state.csv":
                csv_path = STATE_CSV
            elif filename == "cell_history.csv":
                csv_path = CELL_HISTORY_CSV
            if csv_path and os.path.exists(csv_path):
                with open(csv_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", f"attachment; filename={filename}")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.handle_static(p)

    def handle_stats(self):
        if not os.path.exists(LOG_CSV):
            self.send_json({"weekly": {}, "monthly": {}})
            return
        
        wb = dict.fromkeys(range(24), 100.0)
        mb = dict.fromkeys(range(24), 100.0)
        now_dt = datetime.now()
        
        try:
            with open(LOG_CSV, encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self._process_stat_row(row, now_dt, wb, mb)
                        
            w_out = {h: (v if v < 99.9 else None) for h, v in wb.items()}
            m_out = {h: (v if v < 99.9 else None) for h, v in mb.items()}
            self.send_json({"weekly": w_out, "monthly": m_out})
        except Exception as e:
            logger.error(f"Stats error: {e}")
            self.send_json({"weekly": {}, "monthly": {}})

    def _process_stat_row(self, row, now_dt, wb, mb):
        try:
            ts = row.get("timestamp")
            sc = row.get("avg_score") or row.get("score")
            if not ts or not sc: return
            
            dt = datetime.fromisoformat(ts)
            score = float(sc)
            days = (now_dt - dt).days
            h = dt.hour
            
            if days <= 7 and score < wb[h]: wb[h] = score
            if days <= 30 and score < mb[h]: mb[h] = score
        except (ValueError, TypeError):
            pass
    def handle_static(self, p):
        rd = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
        fp = os.path.join(rd, "index.html" if p == "/" else p.lstrip("/"))
        if os.path.exists(fp) and os.path.isfile(fp):
            ext_map = {".html": "text/html", ".js": "application/javascript", ".css": "text/css"}
            ct = ext_map.get(os.path.splitext(fp)[1], "text/plain")
            with open(fp, "rb") as f:
                c = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(c)))
            self.end_headers()
            self.wfile.write(c)
        else:
            self.send_response(404)
            self.end_headers()

def run_initial_speedtest():
    global last_speed_result, latest_state
    logger.info("Starting initial diagnostic speedtest...")
    res = run_forensic_download(duration=10) or run_speedtest()
    if res:
        last_speed_result = res
        with state_lock:
            latest_state.update({
                "down_mbps": res.get("download_mbps", 0),
                "up_mbps": res.get("upload_mbps", 0),
                "ramp_up_ratio": res.get("ramp_up_ratio", 1.0)
            })
        logger.info(f"Initial test complete: {res.get('download_mbps')} Mbps")

if __name__ == "__main__":
    threading.Thread(target=run_initial_speedtest, daemon=True).start()
    threading.Thread(target=lambda: Monitor().run(), daemon=True).start()
    HTTPServer(("", HTTP_PORT), ApiHandler).serve_forever()

import os
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger("huawei_net_forensics")

def parse_num(v):
    if v is None:
        return None
    s = str(v).lower().strip()
    for u in ("dbm", "db", "mhz", "khz"):
        if s.endswith(u):
            s = s[: -len(u)]
    try:
        return float(s)
    except Exception:
        return None

def bw_to_mhz(v):
    if not v:
        return None
    s = str(v).lower().strip()
    if s.endswith("mhz"):
        s = s[:-3]
    try:
        return float(s)
    except Exception:
        return None

def normalize_metric(val, min_v, max_v):
    if val is None: return 0
    return max(0, min(100, ((val - min_v) / (max_v - min_v)) * 100))

def calculate_rf_score(sinr, rsrq, rsrp, _bw):
    if None in (sinr, rsrq, rsrp):
        return None
    
    s_score = normalize_metric(sinr, -5, 25)
    q_score = normalize_metric(rsrq, -20, -10)
    p_score = normalize_metric(rsrp, -120, -80)
    
    return (s_score * 0.45) + (q_score * 0.35) + (p_score * 0.20)

class ModemProvider(ABC):
    @abstractmethod
    def get_signal_metrics(self):
        pass

class NullModemProvider(ModemProvider):
    def get_signal_metrics(self):
        return {
            "band": "N/A",
            "pci": "0",
            "enodeb": "0",
            "sinr": None,
            "rsrq": None,
            "rsrp": None,
            "bw": None,
            "score": None,
            "mode": "no_modem"
        }

class HuaweiModemProvider(ModemProvider):
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password
        self.url = f"http://{username}:{password}@{ip}/"
        self._connected = True
        
        try:
            import huawei_lte_api.Client
            import huawei_lte_api.Connection
            self._client_cls = huawei_lte_api.Client.Client
            self._conn_cls = huawei_lte_api.Connection.Connection
        except ImportError:
            logger.error("huawei_lte_api not installed. Acting as Null Provider.")
            self._connected = False

    def get_signal_metrics(self):
        if not self._connected:
            return NullModemProvider().get_signal_metrics()

        try:
            with self._conn_cls(self.url) as c:
                cli = self._client_cls(c)
                sig = cli.device.signal()

            band = sig.get("band")
            pci = sig.get("pci")
            enodeb = sig.get("enodeb_id")

            sinr = parse_num(sig.get("sinr"))
            rsrq = parse_num(sig.get("rsrq"))
            rsrp = parse_num(sig.get("rsrp"))
            bw = bw_to_mhz(sig.get("dlbandwidth"))
            
            return {
                "band": band,
                "pci": pci,
                "enodeb": enodeb,
                "sinr": sinr,
                "rsrq": rsrq,
                "rsrp": rsrp,
                "bw": bw,
                "score": calculate_rf_score(sinr, rsrq, rsrp, bw),
                "mode": "huawei"
            }
        except Exception as e:
            logger.error(f"Huawei fetch failed: {e}. Falling back to internal null state.")
            return NullModemProvider().get_signal_metrics()

def get_provider():
    ip = os.getenv("MODEM_IP")
    user = os.getenv("MODEM_USERNAME")
    pwd = os.getenv("MODEM_PASSWORD")
    
    if ip and user and pwd:
        return HuaweiModemProvider(ip, user, pwd)
    
    return NullModemProvider()

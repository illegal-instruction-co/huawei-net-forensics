import subprocess
import json
import time
import shutil
import logging
import re
import os
import urllib.request
import threading
import statistics
from datetime import datetime

try:
    import speedtest
except ImportError:
    speedtest = None

logger = logging.getLogger("huawei_net_forensics")

def run_ping_thread(host, duration, results_list):
    """Runs ping in a loop for a specified duration and appends parsed RTTs to results_list."""
    start_t = time.time()
    while time.time() - start_t < duration:
        try:
            cmd = ["ping", "-c", "1", "-W", "1", host] if os.name != 'nt' else ["ping", "-n", "1", "-w", "1000", host]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            
            if os.name == 'nt':
                match = re.search(r"time=(\d+)ms", res.stdout)
            else:
                match = re.search(r"time=([\d\.]+) ms", res.stdout)
                
            if match:
                results_list.append(float(match.group(1)))
            else:
                results_list.append(None)
        except Exception:
            results_list.append(None)
        time.sleep(0.5)

def run_ping(host="8.8.8.8", count=10):
    try:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        
        cmd = ["ping", "-c", str(count), host] if os.name != 'nt' else ["ping", "-n", str(count), host]
            
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20, env=env)
        output = result.stdout
        
        w_loss = re.search(r"Lost = (\d+) \((\d+)% loss\)", output)
        w_time = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", output)
        
        l_loss = re.search(r"(\d+)% packet loss", output)
        l_time1 = re.search(r"rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms", output)
        
        stats = {
            "target": host,
            "min_rtt": 0, "max_rtt": 0, "avg_rtt": 0, "packet_loss": 0, "jitter": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        if w_loss: 
            stats["packet_loss"] = float(w_loss.group(2))
        elif l_loss: 
            stats["packet_loss"] = float(l_loss.group(1))

        if w_time:
            mn = float(w_time.group(1))
            mx = float(w_time.group(2))
            avg = float(w_time.group(3))
            stats["min_rtt"] = mn
            stats["max_rtt"] = mx
            stats["avg_rtt"] = avg
            stats["jitter"] = (mx - mn) / 2.0 
        elif l_time1:
            stats["min_rtt"] = float(l_time1.group(1))
            stats["avg_rtt"] = float(l_time1.group(2))
            stats["max_rtt"] = float(l_time1.group(3))
            stats["jitter"] = float(l_time1.group(4))
            
        return stats
        
    except Exception as e:
        logger.error(f"Ping failed: {e}")
        return None

def analyze_shape(samples):
    """
    Analyzes the throughput samples to determine the curve shape.
    Samples is a list of (time_offset, mbps_at_interval).
    Returns: 'logarithmic', 'linear', 'plateau', 'fluctuating'
    """
    if len(samples) < 4:
        return "uncertain"
        
    mbps_values = [s[1] for s in samples]
    
    steady_state = mbps_values[len(mbps_values)//4:]
    if not steady_state: return "uncertain"
    
    avg = statistics.mean(steady_state)
    if avg < 0.1: return "uncertain"
    
    var = statistics.stdev(steady_state) if len(steady_state) > 1 else 0
    cv = var / avg
    
    if cv < 0.15:
        return "plateau" 
        
    try:
        slope = statistics.linear_regression(times, mbps_values).slope
        correlation = statistics.correlation(times, mbps_values)
        if correlation > 0.8 and slope > 0:
            return "linear_climb"
    except (AttributeError, ValueError):
        pass 

    return "logarithmic" 

def run_single_download(url, duration):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    start_time = time.time()
    total_bytes = 0
    samples = []
    
    try:
        with urllib.request.urlopen(req, timeout=5) as u:
            chunk_size = 81920
            last_sample_time = 0
            bytes_in_interval = 0
            
            while True:
                now = time.time()
                elapsed = now - start_time
                if elapsed > duration:
                    break
                
                chunk = u.read(chunk_size)
                if not chunk:
                    break
                
                size = len(chunk)
                total_bytes += size
                bytes_in_interval += size
                
                # Sample every 0.5s
                if now - last_sample_time >= 0.5:
                    inst_mbps = (bytes_in_interval * 8) / (0.5 * 1_000_000)
                    samples.append((elapsed, inst_mbps))
                    bytes_in_interval = 0
                    last_sample_time = now
                    
    except Exception as e:
        logger.warning(f"DL failed for {url}: {e}")
        return None
        
    total_time = time.time() - start_time
    if total_time < 0.1: total_time = 0.1
    avg_mbps = (total_bytes * 8) / (total_time * 1_000_000)
    
    return {
        "mbps": avg_mbps,
        "samples": samples,
        "shape": analyze_shape(samples),
        "total_bytes": total_bytes
    }

def run_forensic_download(duration=10):
    try:
        targets = [
            "http://speedtest.tele2.net/10MB.zip",
            "http://ipv4.download.thinkbroadband.com/10MB.zip",
            "http://speedtest.belwue.net/10M"
        ]
        
        per_target_duration = max(3, duration // len(targets))
        
        results = []
        total_dl_bytes = 0
        
        logger.info(f"Starting forensic suite on {len(targets)} targets...")
        
        ping_before = run_ping(count=5)
        base_latency = ping_before['avg_rtt'] if ping_before else 0
        
        aggregated_metrics = {
            "download_mbps": 0,
            "upload_mbps": 0,
            "ramp_up_ratio": 1.0,
            "consistency_score": 1.0,
            "shapes": [],
            "latency_under_load_diff": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        mbps_vals = []
        
        for url in targets:
            ping_rtts = []
            pt = threading.Thread(target=run_ping_thread, args=("8.8.8.8", per_target_duration, ping_rtts))
            pt.start()
            
            dl_res = run_single_download(url, per_target_duration)
            
            pt.join()
            
            if dl_res:
                dl_res['ping_during'] = [r for r in ping_rtts if r is not None]
                results.append(dl_res)
                mbps_vals.append(dl_res['mbps'])
                total_dl_bytes += dl_res['total_bytes']
        
        if not results:
            logger.error("All forensic downloads failed")
            return None
            
        avg_mbps = statistics.mean(mbps_vals)
        aggregated_metrics["download_mbps"] = round(avg_mbps, 2)
        aggregated_metrics["shapes"] = [r['shape'] for r in results]
        
        if len(mbps_vals) > 1:
            cv = statistics.stdev(mbps_vals) / avg_mbps if avg_mbps > 0 else 0
            aggregated_metrics["consistency_score"] = max(0.0, 1.0 - (cv * 2))
        
        all_during_pings = []
        for r in results:
            all_during_pings.extend(r['ping_during'])
            
        if all_during_pings:
            avg_during = statistics.mean(all_during_pings)
            aggregated_metrics["latency_under_load_diff"] = avg_during - base_latency
        else:
            aggregated_metrics["latency_under_load_diff"] = 0

        first_success = results[0]
        if first_success['shape'] == 'plateau':
            aggregated_metrics["ramp_up_ratio"] = 1.0
        elif first_success['shape'] == 'linear_climb':
            aggregated_metrics["ramp_up_ratio"] = 0.5
        else:
            aggregated_metrics["ramp_up_ratio"] = 1.5
            
        aggregated_metrics["total_bytes"] = total_dl_bytes
            
        logger.info(f"Forensic Result: Speed={avg_mbps:.1f}, Cons={aggregated_metrics['consistency_score']:.2f}, LatDiff={aggregated_metrics['latency_under_load_diff']:.1f}, Shapes={aggregated_metrics['shapes']}")
        
        return aggregated_metrics

    except Exception as e:
        logger.error(f"Forensic suite failed: {e}")
        return None

def run_speedtest():
    if speedtest:
        try:
            logger.info("Starting speedtest via python library...")
            st = speedtest.Speedtest()
            st.get_best_server()
            st.download()
            st.upload()
            data = st.results.dict()
            
            return {
                "download_mbps": round(data["download"] / 1_000_000, 2),
                "upload_mbps": round(data["upload"] / 1_000_000, 2),
                "ramp_up_ratio": 1.0,
                "ping_latency": data["ping"],
                "packet_loss": 0, 
                "server_id": data["server"]["id"],
                "server_host": data["server"]["host"],
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
             logger.error(f"Speedtest library failed: {e}")

    try:
        exe = shutil.which("speedtest") or shutil.which("speedtest-cli")
        if not exe:
             return None

        logger.info(f"Starting speedtest with {exe}...")
        cmd = [exe, "--json", "--secure", "--no-pre-allocate"]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0:
            logger.error(f"Speedtest failed: {result.stderr}")
            return None
            
        data = json.loads(result.stdout)
        
        download_mbps = data["download"] / 1_000_000
        upload_mbps = data["upload"] / 1_000_000
        
        return {
            "download_mbps": round(download_mbps, 2),
            "upload_mbps": round(upload_mbps, 2),
            "ramp_up_ratio": 1.0,
            "ping_latency": data["ping"],
            "packet_loss": data.get("packetLoss", 0),
            "server_id": data.get("server", {}).get("id"),
            "server_host": data.get("server", {}).get("host"),
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Speedtest execution error: {e}")
        return None

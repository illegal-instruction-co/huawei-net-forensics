# Huawei Net Forensics

<img width="875" height="450" alt="image" src="https://github.com/user-attachments/assets/90dd9603-60f4-4d4b-b997-e72c531356f1" />

------------

A lightweight monitoring tool for Huawei LTE modems. It correlates physical signal metrics (SINR, RSRQ, RSRP) with network throughput and latency to analyze connection consistency over time.

Designed to help distinguish between poor signal reception, network congestion, and potential shaping policies.

## Usage

1.  **Configure**: Rename `.env.example` to `.env` and add your modem credentials.
2.  **Install**: `pip install -r requirements.txt`
3.  **Run**: `python main.py`
4.  **View**: Open `http://localhost:4884`

**Data Storage:** All metrics are logged locally to CSV files in the `data/` directory for historical analysis.

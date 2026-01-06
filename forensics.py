class ForensicsEngine:
    RADIO_THRESHOLD_TERRIBLE = 30
    RADIO_THRESHOLD_BAD = 50
    RADIO_THRESHOLD_MED = 70
    RADIO_THRESHOLD_GOOD = 85
    
    JITTER_THRESHOLD_HIGH = 30
    JITTER_THRESHOLD_EXTREME = 100
    LATENCY_THRESHOLD_HIGH = 150
    PACKET_LOSS_THRESHOLD = 2
    
    SPEED_THRESHOLD_FAST = 50
    SPEED_THRESHOLD_SLOW = 10
    LATENCY_THRESHOLD_STABLE = 100
    JITTER_THRESHOLD_STABLE = 20
    RAMP_UP_THRESHOLD = 1.2
    RF_SCORE_CONFIDENCE = 60

    def analyze(self, signal_data, network_data, history=None):
        metrics = self._extract_metrics(signal_data, network_data)
        
        radio = self._calculate_radio(metrics['rf_score'])
        congestion = self._calculate_congestion(metrics)
        policy = self._calculate_policy(metrics, history)
        
        policy = self._apply_counter_evidence(policy, metrics)

        total = radio + congestion + policy
        if total > 0.95:
            radio, congestion, policy = self._normalize(radio, congestion, policy, total)
            
        verdict = self._get_verdict(radio, congestion, policy)
        
        if verdict.startswith("Policy") and not self._is_confident(history):
            verdict = "Observed, low confidence"

        return {
            "radio_likelihood": round(radio, 2),
            "congestion_likelihood": round(congestion, 2),
            "policy_likelihood": round(policy, 2),
            "verdict": verdict,
            "consistency_score": metrics.get('consistency', 0)
        }

    def _extract_metrics(self, signal_data, network_data):
        return {
            "rf_score": signal_data.get("score") if signal_data else None,
            "down_mbps": network_data.get("down_mbps", 0),
            "latency": network_data.get("latency", 0),
            "jitter": network_data.get("jitter", 0),
            "packet_loss": network_data.get("packet_loss", 0),
            "ramp_up": network_data.get("ramp_up_ratio", 1.0),
            "consistency": network_data.get("consistency_score", 0.5),
            "latency_diff": network_data.get("latency_under_load_diff", 0),
            "shapes": network_data.get("shapes", [])
        }

    def _calculate_radio(self, rf_score):
        if rf_score is None:
            return 0.1
        if rf_score < self.RADIO_THRESHOLD_TERRIBLE:
            return 0.95
        if rf_score < self.RADIO_THRESHOLD_BAD:
            return 0.8
        if rf_score < self.RADIO_THRESHOLD_MED:
            return 0.4
        if rf_score > self.RADIO_THRESHOLD_GOOD:
            return 0.05
        return 0.0

    def _calculate_congestion(self, m):
        score = 0.0
        if m['latency_diff'] > 50: 
            score += 0.4
        elif m['latency_diff'] > 20:
            score += 0.2
            
        if m['jitter'] > self.JITTER_THRESHOLD_HIGH:
            score += 0.3
        if m['packet_loss'] > self.PACKET_LOSS_THRESHOLD:
            score += 0.2
            
        if 'linear_climb' in m['shapes']:
             score += 0.2

        if m['down_mbps'] > self.SPEED_THRESHOLD_FAST:
            score *= 0.1
        return min(1.0, score)

    def _calculate_policy(self, m, history):
        is_slow = m['down_mbps'] < self.SPEED_THRESHOLD_SLOW
        
        score = 0.0
        
        if m['consistency'] > 0.8:
            score += 0.5
        elif m['consistency'] > 0.6:
            score += 0.3

        plateau_count = m['shapes'].count('plateau')
        if plateau_count >= 2:
            score += 0.4
        elif plateau_count == 1:
            score += 0.2

        if history and history.get('is_stable_hour', False):
             score += 0.3

        if m['ramp_up'] > self.RAMP_UP_THRESHOLD:
            score += 0.1
            
        if not is_slow:
             score *= 0.5

        return min(1.0, score)

    def _apply_counter_evidence(self, policy_score, m):
        if m['jitter'] > 100: 
            policy_score *= 0.5
        if m['latency_diff'] > 200:
            policy_score *= 0.6
        if m['rf_score'] is not None and m['rf_score'] < 40: 
            policy_score *= 0.4
        return policy_score

    def _is_confident(self, history):
        if not history: return False
        return history.get('policy_count', 0) >= 3

    def _normalize(self, r, c, p, total):
        factor = 0.95 / total
        return r * factor, c * factor, p * factor

    def _get_verdict(self, r, c, p):
        mx = max(r, c, p)
        if mx < 0.4:
            return "Inconclusive / Gathering Data"
        if r == mx:
            return "Radio Impairment Likely"
        if c == mx:
            return "Congestion Indicators Present"
        if p == mx:
            return "Policy-Like Pattern Detected"
        return "Mixed Signals"

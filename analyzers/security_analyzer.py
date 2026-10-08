from typing import List, Dict, Any

class SecurityAnalyzer:
    @classmethod
    def analyze_events(cls, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        analyzed_events = []

        for event in events:
            ev = event.copy()
            event_name = ev.get("event_name")
            user_type = ev.get("user_type")
            req_params = ev.get("request_parameters")

            if user_type == "Root" or "root" in ev.get("user_arn", ""):
                ev["threat_level"] = "CRITICAL"
                ev["detected_behavior"] = "Root Account Activity Detected"
            elif event_name == "AuthorizeSecurityGroupIngress":
                if req_params and "ipPermissions" in req_params:
                    items = req_params["ipPermissions"].get("items", [])
                    for item in items:
                        ip_ranges = item.get("ipRanges", {}).get("items", [])
                        for ip_range in ip_ranges:
                            if ip_range.get("cidrIp") == "0.0.0.0/0":
                                ev["threat_level"] = "HIGH"
                                ev["detected_behavior"] = "Security Group Opened to World (0.0.0.0/0)"

            analyzed_events.append(ev)

        return analyzed_events

import json
import os
from typing import List, Dict, Any

class CloudTrailParser:
    """
    Parses and normalizes AWS CloudTrail JSON log files into structured event records.
    """

    @classmethod
    def load_logs(cls, filepath: str) -> List[Dict[str, Any]]:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"CloudTrail log file not found at: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        records = raw_data.get("Records", [])
        normalized_logs = []

        for idx, record in enumerate(records, start=1):
            user_identity = record.get("userIdentity", {})
            normalized = {
                "event_id": f"TRAIL-{1000 + idx}",
                "event_time": record.get("eventTime"),
                "event_name": record.get("eventName"),
                "aws_region": record.get("awsRegion"),
                "source_ip": record.get("sourceIPAddress"),
                "user_type": user_identity.get("type", "Unknown"),
                "user_arn": user_identity.get("arn", "N/A"),
                "user_name": user_identity.get("userName", user_identity.get("principalId", "System")),
                "user_agent": record.get("userAgent"),
                "request_parameters": record.get("request_parameters"),
                "threat_level": "NORMAL",
                "detected_behavior": "Standard API Activity"
            }
            normalized_logs.append(normalized)

        return normalized_logs

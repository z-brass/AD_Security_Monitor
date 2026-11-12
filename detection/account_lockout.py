def detect_account_lockout(events):
    alerts = []

    for event in events:
        if event["event_id"] == 4740:
            username = event.get("username")
            actor = event.get("actor")
            timestamp = event.get("timestamp")

            alert = {
                "rule": "AUTH-003",
                "severitiy": "Medium",
                "targeted_user": username,
                "actor": actor,
                "timestamp": timestamp,
                "description": f"Active Directory user account lockout detected."
            }

            alerts.append(alert)

    return alerts


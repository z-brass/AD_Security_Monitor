def detect_account_creation(events):
    alerts = []

# searching for for Event ID 4720 (account creation)
    for event in events:
        if event.get("event_id") != 4720:
            continue

        # identify new account creations + the actor who made them
        username = event.get("username")
        actor = event.get("actor")

        # skipping events missing either of these values
        if not username or not actor:
            continue

        # generate an alert for account creation
        alerts.append({
            "rule": "AUTH-002",
            "severity": "Medium",
            "targeted_user": username,
            "actor": actor,
            "timestamp": event.get("timestamp"),
            "description": (
                "Active Directory user account creation detected."
            )
        })
    return alerts
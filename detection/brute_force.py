## goal: generate an alert when the same source IP produces five or more Kerberos pre-auth failures within a 5-minute window

from datetime import datetime, timedelta

FAILED_ATTEMPT_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=5)

## 4771: Kerberos pre-auth failure
def detect_brute_force(events):
    failed_logins_by_ip = {}

    for event in events:
        if event["event_id"] != 4771:
            continue

        ip = event["source_ip"]

        # converting timestamp string to Python datetime object  
        timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )

        if ip not in failed_logins_by_ip:
            failed_logins_by_ip[ip] = []

        failed_logins_by_ip[ip].append(timestamp)

    return failed_logins_by_ip

## goal: generate an alert when the same source IP produces five or more Kerberos pre-auth failures within a 5-minute window

from datetime import datetime, timedelta

FAILED_ATTEMPT_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=5)

## 4771: Kerberos pre-auth failure
def detect_brute_force(events):
    failed_logins_by_ip = {}

    # collecting Kerberos pre-auth failures by source IP  
    for event in events:
        if event.get("event_id") != 4771:
            continue
        # counting only invalid kerberos pre-auth events
        if event.get("status", "").lower() != "0x18":
            continue

        ip = event.get("source_ip")
        timestamp_text = event.get("timestamp")

        # skipping events missing info needed for detection
        if not ip or not timestamp_text:
            continue

        # converting timestamp string to Python datetime object, with an exception  
        try:
            timestamp = datetime.fromisoformat(
                timestamp_text.replace("Z", "+00:00")
            )
        except ValueError:
            # skips event if timestamp is incorrectly formatted
            continue

        if ip not in failed_logins_by_ip:
            failed_logins_by_ip[ip] = []

        failed_logins_by_ip[ip].append(timestamp)

        ''' ### What we know so far ###

        Our knowns: 1) 5+ attempts, 2) within 5 minutes, and 3) the event ID for Kerberos pre-auth failure is 4771, and 4) all from the same IP  
        As it stands, this is a heuristic detection and not a definitive proof of attack. 
        A legitimate user could have misconfigured their device or forgotten their password, causing the multiple failed attempts.
        We need need to address this false positive by adding a time window check to the detection logic. 
        The current implementation only counts the number of failed attempts per IP, but does not consider the time frame in which these attempts occurred.
        '''

    alerts = []

    # Checking each IP for repeated failures WITHIN 5 MINUTES
    for ip, timestamps in failed_logins_by_ip.items():
        timestamps.sort()
        window_start = 0

        for window_end in range(len(timestamps)):
            current_time = timestamps[window_end]

            # removing attempts older than the 5 minute window
            while (current_time - timestamps[window_start] > TIME_WINDOW):
                window_start += 1

            attempt_count = window_end - window_start + 1

            if attempt_count >= FAILED_ATTEMPT_THRESHOLD:
                alerts.append({
                    "rule": "AUTH-001",
                    "severity": "Medium",
                    "source_ip": ip,
                    "failed_attempts": attempt_count,
                    "window_start": timestamps[window_start].isoformat(),
                    "window_end": current_time.isoformat(),
                    "description": (
                        "Repeated Kerberos pre-authentication "
                        "failures detected within five minutes."
                    )
                })

                # one initial alert per IP, per analysis we run
                break

    return alerts



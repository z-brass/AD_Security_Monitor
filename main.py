from pathlib import Path

from parsers.windows_events import parse_file 
from detection.brute_force import detect_brute_force
from detection.account_creation import detect_account_creation

#print("Project directory:", BASE_DIR)
#print("Sample events file path:", FILE_PATH)

BASE_DIR = Path(__file__).resolve().parent
FILE_PATH = BASE_DIR / "sample_data" / "sample_events.xml"


def display_alert(alert):
    print("\n--- SECURITY ALERT ---")
    print(f"Rule: {alert['rule']}")
    print(f"Severity: {alert['severity']}")

    if alert["rule"] == "AUTH-001":
        print(f"Source IP: {alert['source_ip']}")
        print(f"Targeted Users: {', '.join(alert['targeted_users'])}")
        print(f"Status Codes: {', '.join(alert['status_codes'])}")
        print(f"Failed Attempts: {alert['failed_attempts']}")
        print(f"Window Start: {alert['window_start']}")
        print(f"Window End: {alert['window_end']}")

    elif alert["rule"] == "AUTH-002":
        print(f"Created Account: {alert['targeted_user']}")
        print(f"Created By: {alert['actor']}")
        print(f"Timestamp: {alert['timestamp']}")

    print(f"Description: {alert['description']}")


def main():
    events = parse_file(FILE_PATH)

    # Run both detection rules.
    brute_force_alerts = detect_brute_force(events)
    account_creation_alerts = detect_account_creation(events)

    # Combine the results.
    alerts = brute_force_alerts + account_creation_alerts

    print(f"Events analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")

    for alert in alerts:
        display_alert(alert)


if __name__ == "__main__":
    main()






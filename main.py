from pathlib import Path

from parsers.windows_events import parse_file 
from detection.brute_force import detect_brute_force

#print("Project directory:", BASE_DIR)
#print("Sample events file path:", FILE_PATH)

BASE_DIR = Path(__file__).resolve().parent
FILE_PATH = BASE_DIR / "sample_data" / "sample_events.xml"

def main():
    events = parse_file(FILE_PATH)
    alerts = detect_brute_force(events)

    print(f"Events analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")

    for alert in alerts:
        print("\n--- SECURITY ALERT ---")
        print(f"Rule: {alert['rule']}")
        print(f"Severity: {alert['severity']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failed attempts: {alert['failed_attempts']}")
        print(f"Window start: {alert['window_start']}")
        print(f"Window end: {alert['window_end']}")
        print(f"Description: {alert['description']}")

if __name__ == "__main__":
    main()





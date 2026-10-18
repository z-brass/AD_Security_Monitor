from pathlib import Path

from parsers.windows_events import parse_file 
from detection.brute_force import detect_brute_force

BASE_DIR = Path(__file__).resolve().parent
FILE_PATH = BASE_DIR / "sample_data" / "sample_events.xml"

events = parse_file(FILE_PATH)

failed_logins = detect_brute_force(events)

for ip, timestamps in failed_logins.items():
    print(f"IP: {ip}")
    print(f"Failed attempts: {len(timestamps)}")
    print(f"Timestamps: {timestamps}")

    
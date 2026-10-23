import unittest
from datetime import datetime, timedelta, timezone
from detection.brute_force import detect_brute_force


SOURCE_IP = "192.168.100.20"

def make_event(minutes_after_start, event_id=4771):
    timestamp = (
        datetime(2026, 10, 14, 14, 30, tzinfo=timezone.utc)
        + timedelta(minutes = minutes_after_start)
    )

    return {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "username": "jsmith",
        "source_ip": SOURCE_IP,
        "status": "0x18",
        "service_name": "krbtgt/corp.example.test"
    }

class TestBruteForceDetection(unittest.TestCase):

    def test_five_failures_within_four_minutes_triggers_alert(self):
        events = [make_event(i) for i in range(5)]

        alerts = detect_brute_force(events)


        ## generate 1 alert, if there are 5 attempts, and show source ip
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 5)
        self.assertEqual(alerts[0]["source_ip"], SOURCE_IP)

    def test_four_failures_do_not_trigger_alert(self):
        events = [make_event(i, event_id=4768) for i in range(4)]

        alerts = detect_brute_force(events)

        ## should not generate an alert, so 0 alerts
        self.assertEqual(len(alerts), 0)


    def test_five_failures_spread_over_six_minutes_do_not_alert(self):
        events = [
            make_event(0),
            make_event(2),
            make_event(4),
            make_event(5),
            make_event(6)
        ]

        alerts = detect_brute_force(events)

        ## 5 failures within  6 minutes, should not make an alert, so 0 
        self.assertEqual(len(alerts), 0)

    def test_event_4768_does_not_count_as_a_failure(self):

        ## substitute values for our make_event function (instead of 4771, we test 4768 for first argument)
        events = [make_event(i, event_id=4768) for i in range(5)]

        alerts = detect_brute_force(events)

        # event id is not 4771 (kerberos pre-auth failure), so don't alert 
        self.assertEqual(len(alerts), 0)

    def test_failiures_from_different_ips_are_counted_separately(self):
        events = [
            make_event(0),
            make_event(1),
            make_event(2),
            {
                **make_event(3),
                "source_ip": "192.168.100.30"
            },
            {
                **make_event(4),
                "source_ip": "192.168.100.30"
            }
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    def test_event_missing_source_ip_is_skipping(self):
        events = [make_event(i) for i in range(5)]

        # removing source ip from the 5th event
        events[4]["source_ip"] = None

        alerts = detect_brute_force(events)

        # no alerts if 1 of 5 IPs are missing; we skip to the next check
        self.assertEqual(len(alerts), 0)

    def test_event_missing_timestamp_is_skipped(self):
        events = [make_event(i) for i in range(5)]

        # removing the timestamp from the 5th event this time
        events[4]["timestamp"] = None

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)


    def test_invalid_timestamp_does_not_crash_detector(self):
        events = [make_event(i) for i in range(5)]

        # Replace one valid timestamp with an invalid value.
        events[4]["timestamp"] = "not-a-valid-timestamp"

        # Invalid events should be skipped, not crash the detector.
        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    def test_different_status_code_does_not_count_toward_threshold(self):
        events = [make_event(i) for i in range(4)]

        # add a 5th event, but give it a different status code
        event = make_event(4)
        event["status"] = "0x0"
        events.append(event)

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    
    def test_uppercase_status_code_still_triggers_alert(self):
        events = [make_event(i) for i in range(5)]

        # change the status code to uppercase
        for event in events:
            event["status"] = "0X18"

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 5)

    def test_two_ips_eaech_trigger_separate_alerts(self):
        events = []

        for i in range(5):
            events.append(make_event(1))

        for i in range (5):
            event = make_event(i)
            event["source_ip"] = "192.168.100.30"
            events.append(event)

        alerts = detect_brute_force(events)

        # we are expecting two alerts for each ip reaching the threshold
        self.assertEqual(len(alerts), 2)

        alert_ips = {alert["source_ip"] for alert in alerts}

        self.assertEqual(
            alert_ips,
            {"192.168.100.20", "192.168.100.30"}
        )


if __name__ == "__main__":
    unittest.main()

## test running the code via PS
# py -m unittest discover -s tests -v 
# python -m unittest discover -s tests -v

## Check list:
## The five-failure threshold
## Failures spread outside the five-minute window
## Filters out unrelated event IDs
## Separates attempts by source IP
## Skips events with missing IP addresses or timestamps
## Handles malformed timestamps without crashing
## Filters by status code, including case-insensitive matching
## Two or more IPs reaching threshold successfully generate alerts
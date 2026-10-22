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

if __name__ == "__main__":
    unittest.main()
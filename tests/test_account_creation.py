import unittest
from detection.account_creation import detect_account_creation

def make_event(event_id=4720):
    return {
        "event_id": event_id,
        "timestamp": "2026-11-06T14:30:00+00:00",
        "username": "backup_admin",
        "actor": "jsmith"
    }

class TestAccountCreationDetection(unittest.TestCase):

    def test_event_4720_generates_alert(self):
        events = [make_event()]

        alerts = detect_account_creation(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "AUTH-002")
        self.assertEqual(alerts[0]["targeted_user"], "backup_admin")
        self.assertEqual(alerts[0]["actor"], "jsmith")

    def test_other_event_ids_are_ignored(self):
        events = [make_event(event_id=4624)]

        alerts = detect_account_creation(events)

        self.assertEqual(len(alerts), 0)

    def test_missing_username_does_skip(self):
        event = make_event()
        event["username"] = None

        alerts = detect_account_creation([event])

        self.assertEqual(len(alerts), 0)

    def test_missing_actor_does_skip(self):
        event = make_event()
        event["actor"] = None

        alerts = detect_account_creation([event])

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()


## Testing ##

# python -m unittest discover -s tests -v

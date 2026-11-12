
import unittest

from detection.account_lockout import detect_account_lockout


class TestAccountLockout(unittest.TestCase):

    def test_account_lockout_detected(self):
        events = [
            {
                "event_id": 4740,
                "username": "jsmith",
                "actor": "DC01$",
                "timestamp": "2026-11-10T14:40:00Z"
            }
        ]

        alerts = detect_account_lockout(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "AUTH-003")
        self.assertEqual(alerts[0]["targeted_user"], "jsmith")

    def test_unrelated_event_ignored(self):
        events = [
            {
                "event_id": 4720,
                "username": "jsmith",
                "actor": "admin",
                "timestamp": "2026-11-10T14:40:00Z"
            }
        ]

        alerts = detect_account_lockout(events)

        self.assertEqual(len(alerts), 0)

    def test_multiple_lockouts_detected(self):
        events = [
            {
                "event_id": 4740,
                "username": "jsmith",
                "actor": "DC01$",
                "timestamp": "2026-11-10T14:40:00Z"
            },
            {
                "event_id": 4740,
                "username": "administrator",
                "actor": "DC01$",
                "timestamp": "2026-11-10T14:45:00Z"
            }
        ]

        alerts = detect_account_lockout(events)

        self.assertEqual(len(alerts), 2)


if __name__ == "__main__":
    unittest.main()

# py -m unittest tests.test_account_lockout -v
# python -m unittest tests.test_account_lockout -v
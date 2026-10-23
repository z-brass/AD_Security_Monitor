# AUTH-001 — Repeated Kerberos Pre-Authentication Failures

## Rule Overview

- **Rule ID:** AUTH-001
- **Severity:** Medium
- **Category:** Authentication
- **Data Source:** Windows Security Event Log
- **Event ID:** 4771 — Kerberos pre-authentication failed
- **Detection Threshold:** 5 qualifying failures
- **Time Window:** 5 minutes
- **Grouping:** Source IP address

## Objective

Identify repeated Kerberos pre-authentication failures from a single source IP address that may indicate password guessing or other suspicious authentication activity.

## Detection Logic

The rule currently:

1. Selects Windows Security Event ID 4771.
2. Counts events with status code `0x18`, case-insensitively.
3. Skips events missing a source IP address or timestamp.
4. Skips timestamps that cannot be parsed.
5. Groups events by source IP address.
6. Generates a Medium-severity alert when at least five qualifying failures occur within an inclusive five-minute window.
7. Generates at most one alert per source IP per analysis run.

## Alert Fields

- **Rule:** AUTH-001
- **Severity:** Medium
- **Source IP:** Address associated with the failures
- **Failed Attempts:** Number of qualifying events in the triggering window
- **Window Start / End:** Beginning and end of the triggering window
- **Description:** Summary of the repeated authentication failures

## Analyst Investigation Procedure

1. **Validate the alert.** Confirm the source IP, timestamps, event IDs, and status codes in the original Windows Security logs.
2. **Identify the source.** Determine whether the IP belongs to an approved workstation, server, VPN endpoint, or an unknown device.
3. **Review the account.** Identify the targeted user and determine whether the activity affects one account or multiple accounts.
4. **Examine surrounding activity.** Look for successful logons, account lockouts (Event ID 4740), additional authentication failures, and unusual activity before or after the alert.
5. **Correlate network evidence.** If packet captures are available, investigate relevant DNS, Kerberos, and other network traffic. Remember that encrypted traffic may limit visibility.
6. **Assess the risk.** Consider the number of targeted accounts, repetition, source reputation, successful authentication, and whether the behavior is expected.
7. **Escalate or respond.** Follow organizational procedures. Notify the appropriate team and apply containment or account-protection measures only when authorized.
8. **Document the outcome.** Record the evidence, conclusion, actions taken, and whether the alert was benign, suspicious, or confirmed malicious.

## False Positive Considerations

Potential benign causes include:

- A user repeatedly entering an incorrect password.
- A misconfigured service or scheduled task.
- A legitimate system repeatedly attempting authentication with stale credentials.

The threshold is a starting point for this lab, not a universal production standard. Tune it using the environment's normal authentication patterns.

## Known Limitations

- Only Event ID 4771 with status `0x18` is counted by the current implementation.
- Events without a source IP or valid timestamp are skipped.
- Invalid timestamp strings are skipped, but other unexpected data types have not yet been comprehensively validated.
- The rule analyzes the events supplied to a single run and does not maintain state across runs.
- Only one alert is emitted per source IP per analysis run.
- The rule does not currently correlate activity across multiple IP addresses targeting the same account.
- An alert indicates suspicious behavior, not proof of a successful compromise.

## Validation

Automated tests cover the threshold, time window, event ID filtering, source-IP separation, missing fields, invalid timestamps, and status-code matching.

## MITRE ATT&CK Context

**Potential mapping:** T1110 — Brute Force.

This is a potential behavioral mapping, not proof that the activity is malicious. Confirm the investigative context before assigning a definitive technique to a real incident.
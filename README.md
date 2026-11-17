# SOC Alert Investigations

Phishing alert investigations and case reports from the TryHackMe SOC Simulator. Each alert has its own folder with the full written report and the screenshots that back it up.

> **Note:** these investigations were done in a training environment with simulated data. All email addresses, domains and IP addresses are fictional or defanged (for example `hxxp://` and `[.]`).

## Tools used

- **Splunk:** searching email and firewall logs (all-time searches)
- **TryDetectThis:** checking the reputation of URLs, IP addresses and sender addresses
- **Asset inventory:** matching IP addresses and email addresses to employees and workstations

## Investigations

| Alert | Type | Severity | Verdict | Escalated | Summary |
|-------|------|----------|---------|-----------|---------|
| [8814](alert-8814/README.md) | Phishing | Medium | False positive | No | Onboarding email from the company's third-party HR partner. Sender and link were clean, no firewall connection to the link, and an internal HR email corroborated the sender. |
| [8815](alert-8815/README.md) | Phishing | Medium | True positive | Yes | Fake Amazon delivery email from the look-alike domain amazon[.]biz with a shortened bit[.]ly link. The firewall blocked the connection attempt. |
| [8816](alert-8816/README.md) | Firewall | High | True positive | Yes | The firewall block of the same bit[.]ly link from the same host as alert 8815. Related to alert 8815. |
| [8817](alert-8817/README.md) | Phishing | Medium | True positive | Yes | Fake Microsoft sign-in warning from the look-alike domain m1crosoftsupport[.]co. The firewall allowed the connection to the malicious login page. |

## How each investigation is organised

Every alert folder contains:

- `README.md`: the alert details, the investigation steps with screenshots, and the full case report (time of activity, affected entities, reason for the classification, escalation reason, remediation actions and attack indicators)
- `screenshots/`: the evidence referenced in the report

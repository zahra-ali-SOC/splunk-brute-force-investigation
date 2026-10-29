# Incident Report: Brute Force Followed by Account Compromise

> **Note:** This report is based on a **simulated** Windows login dataset (about 2,000 events), made for practice. All IPs are from documentation ranges. It is not real company data.

## 1. Summary

An attacker at IP `203.0.113.45` made **217 failed logins** against the `administrator` account on the domain controller `SRV-DC01`. About 5 seconds after the last failure, the attacker **logged in successfully**. Within 11 minutes, the same account was used to log in to two more machines (`SRV-FILE01` and `WS-03`).

**Verdict:** True positive. **Severity:** High (privileged account compromised, lateral movement seen).

## 2. Data and Tools

| Item | Detail |
|---|---|
| Tool | Splunk Enterprise |
| Index | `login_lab` |
| Events | 2,094 total (1,773 successful logins, 321 failed logins) |
| Event codes | 4624 = successful logon, 4625 = failed logon |
| Time range | 24-25 Oct 2026 |

## 3. Timeline (25 Oct 2026)

| Time | What happened |
|---|---|
| 02:41:07 | Failed logins start from `203.0.113.45` on `administrator` (about one every 3 seconds) |
| 02:51:55 | Last failed login (217th failure) |
| 02:52:00 | **Successful login** to `SRV-DC01` as `administrator` |
| 02:58:00 | Same account logs in to `SRV-FILE01` |
| 03:03:00 | Same account logs in to `WS-03` |

## 4. Analysis

- **Brute force:** One IP, one account, 217 failures in about 11 minutes. This is far above normal. Normal users had 2-9 failures.
- **Compromise:** A success right after many failures from the same IP means the password was guessed.
- **Lateral movement:** The same account logged in to other machines from the same attacker IP in a short time. LogonType 10 means remote (RDP) logins.

## 5. Other Activity Reviewed (Not the Main Incident)

| Activity | Finding | Verdict |
|---|---|---|
| `198.51.100.77` on 24 Oct, around 09:00 | 36 failures across 12 different users, about 3 tries each, **no success** | Password spraying attempt. Not successful. Needs its own detection |
| `10.0.0.12` (hira.khan) | 8 failures, then a success, from an internal IP | False positive. A user forgot her password |
| Other `10.0.0.x` IPs | 2-9 failures each | Normal typing mistakes |

## 6. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Brute Force | T1110 | 217 failed logins on one account |
| Password Spraying | T1110.003 | 36 failures across 12 users from `198.51.100.77` |
| Valid Accounts | T1078 | Successful login with the guessed password |
| Remote Services | T1021 | Logins to `SRV-FILE01` and `WS-03` (LogonType 10) |

## 7. Detection

```
index=login_lab (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures, count(eval(EventCode=4624)) as successes by src_ip, user
| where failures>=20 AND successes>=1
```

Saved as the alert **Brute Force Followed by Success** (scheduled hourly, triggers when results > 0).

**Why threshold 20:** The false positive (8 failures) stays below it, and the real attack (217) is far above it.

## 8. Recommended Actions

1. **Contain:** Disable the `administrator` account and reset its password. End active sessions.
2. **Block:** Block `203.0.113.45` at the firewall.
3. **Investigate:** Check `SRV-DC01`, `SRV-FILE01` and `WS-03` for new accounts, new services, and files accessed.
4. **Escalate:** Pass the case to Tier 2 with this report.
5. **Prevent:** Turn on account lockout, MFA for admin accounts, and block RDP from the internet.

## 9. Limits and Improvements

- The alert searches all time. In real use, limit it to the last 15-60 minutes.
- The rule does not catch password spraying. A second rule should count **failures across many users from one IP**.
- Data is simulated, so the next step is to test the same searches on a real public dataset.

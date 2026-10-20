# SSH Brute Force Detection — Finding and Fixing a Gap in Wazuh
## What this project covers
A home lab running Wazuh (SIEM) and a Kali Linux agent, used to test whether the default detection rules actually catch a basic SSH brute force attack, not just assume they do.
## The test
Hydra was used to brute force SSH login on the Kali machine itself, trying six passwords against a test account, one of which was correct.
<img width="1700" height="187" alt="1" src="https://github.com/user-attachments/assets/6a6f7d4e-c32d-49f9-9fdb-20d2a9f3ed73" />


## Problem #1: successful logins weren't being logged
The failed login attempts all showed up fine in Wazuh. But the one login that actually succeeded never appeared in the logs at all. Only the failures were visible, which means the actual breach would have gone unnoticed.

<img width="1915" height="771" alt="2" src="https://github.com/user-attachments/assets/39f4f952-194b-4257-9d6e-8c4bde02a749" />

**Cause:** Kali's SSH config (`/etc/ssh/sshd_config`) had `LogLevel` commented out and left at `INFO`, which doesn't log enough detail to capture a successful login properly.

**Fix:** Changed `LogLevel` to `VERBOSE`, restarted SSH, and re-ran the attack. The successful login showed up this time as its own event (rule 5715).

<img width="1917" height="757" alt="3" src="https://github.com/user-attachments/assets/aa34eca5-b3c1-41b5-a466-41fff23ae11d" />

## Problem #2: failures and the success weren't connected
Even with the logging fixed, Wazuh still treated the failed attempts and the successful login as separate, unrelated events. There was nothing tying them together, so anyone looking at the logs would just see some failures and a login, not "this account just got brute-forced."

**Fix:** Added two custom rules to Wazuh's `local_rules.xml`:

\`\`\`xml
<rule id="100010" level="10" frequency="3" timeframe="120">
  <if_matched_sid>5760</if_matched_sid>
  <description>Multiple SSH authentication failures from same source.</description>
  <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,</group>
</rule>

<rule id="100011" level="12">
  <if_matched_sid>100010</if_matched_sid>
  <if_sid>5715</if_sid>
  <description>SSH authentication succeeded after multiple failed attempts - possible brute force success.</description>
  <group>authentication_success,attack,</group>
</rule>
\`\`\`

- Rule 100010 watches for 3+ SSH failures from the same source within 2 minutes and raises an alert.
- Rule 100011 checks if a successful login happens right after that, and if so, raises a higher-severity alert flagging it as a likely successful brute force.

Getting rule 100011 to actually fire took a few tries, the first attempt had XML typos, and after fixing those it still wouldn't trigger until `frequency` and `timeframe` were added to rule 100010, since without those it was only matching once instead of tracking repeats properly.

## Proof it works
Ran the attack again. This time both rules fired in order: rule 100010 after the failures, then rule 100011 right after, flagging the successful login.

<img width="1915" height="767" alt="4" src="https://github.com/user-attachments/assets/84e1011e-6749-406a-a248-4b8a296d4e6f" />

## Why it matters
Wazuh already correlates repeated `sudo` failures into one alert by default, but there's no equivalent for SSH out of the box. That's a real gap, without a rule like this, a successful brute force attempt could easily slip past an analyst who's only looking at individual log lines.

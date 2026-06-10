# Azure Sentinel Honeypot Lab

I built this lab to get hands-on experience with cloud security monitoring. The idea is simple. Spin up a Windows Server VM in Azure, expose it to the internet, and watch what happens. Spoiler: it gets attacked almost immediately.

All the attack data flows into Microsoft Sentinel where I built an attack map, wrote KQL queries to analyze the traffic, and set up detection rules to alert on suspicious activity.

---

## What I Used

- **Azure VM** — Windows Server 2025, exposed as a honeypot
- **Log Analytics Workspace** — central log storage
- **Azure Monitor Agent** — collects security events from the VM
- **Microsoft Sentinel** — SIEM for analysis and alerting
- **KQL** — querying and enriching the logs
- **Sentinel Workbooks** — attack map visualization
- **Sentinel Watchlists** — GeoIP database for IP-to-location mapping

---

## How It Works

The VM sits in Azure with all ports open. Every failed login attempt generates a Windows Security Event (ID 4625), which the Azure Monitor Agent forwards to Log Analytics. From there, Sentinel picks it up, enriches it with geolocation data, and visualizes it on a world map.

**Core KQL query for the attack map:**
```kql
let GeoIPDB = _GetWatchlist("geoip");
Event
| where EventID == 4625
| extend IpAddress = extract(@'Name="IpAddress">([^<]+)<', 1, EventData)
| where IpAddress != "-" and IpAddress != ""
| extend Account = extract(@'Name="TargetUserName">([^<]+)<', 1, EventData)
| evaluate ipv4_lookup(GeoIPDB, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, countryname, cityname
```

---

## Results

The VM was found by automated scanners within a few hours. After letting it run, here's what showed up on the map:

| Location | Attempts |
|---|---|
| Hanoi, Vietnam | 904 |
| Bupyeong-gu, South Korea | 233 |
| Other | 138 |
| London, UK | 44 |
| Sydney, Australia | 14 |

Most bots tried usernames like `Administrator` and `admin` — exactly what you'd expect from credential stuffing attacks.

---

## Detection Rules

I created two analytics rules in Sentinel:

- **Brute Force Attempt Detection** — fires when an IP generates multiple failed logins in a short window (MITRE ATT&CK: T1110)
- **Successful Login After Brute Force** — correlates a series of failures with a subsequent successful login from the same IP, which could indicate a compromised account

---

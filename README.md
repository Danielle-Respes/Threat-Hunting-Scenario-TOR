# Threat Hunt Report: Unauthorized TOR Usage 

## **on a School District Network**</p>


<img width="675" height="607" alt="Screenshot 2026-05-26 at 7 09 11 PM" src="https://github.com/user-attachments/assets/99a6a1f4-f3a8-4811-a8f4-e702a1d20b03" />

## Context

I work in IT for a K-12 school district. When a student device gets caught using TOR, we remove it from the network — that part I already do. What I wanted to build was the *detection and documentation* side: the queries, the evidence trail, the timeline. This lab gave me exactly that.

This scenario uses **Microsoft Defender for Endpoint (MDE)**, which we run in my district, to hunt for, confirm, and document TOR usage on a student device end-to-end using KQL.


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Danielle-Respes/Threat-Hunting-Scenario-TOR/blob/main/Create%20threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Tools Used

* Windows 11 Virtual Machine (simulating a school-issued student device)
* Microsoft Defender for Endpoint (MDE) — endpoint telemetry and raw event collection
* Microsoft Sentinel — SIEM used to ingest MDE logs, run hunting queries, and manage the incident
* Kusto Query Language (KQL) — used across both MDE and Sentinel to query file, process, and network events
* TOR Browser — the subject of the hunt
* Microsoft Azure — where the lab environment lives

## The Scenario

A student on device `district-student-laptop` is attempting to bypass the school's content filter using TOR. Network logs show encrypted outbound traffic hitting known TOR entry nodes from the student subnet during class hours.

MDE is collecting endpoint activity logs from the device. That data flows into Microsoft Sentinel, where it becomes searchable across the `DeviceFileEvents`, `DeviceProcessEvents`, and `DeviceNetworkEvents` tables. The hunt, the timeline, and the incident are all managed from the Sentinel workspace.

**The goal:** Identify the device, confirm TOR usage across file, process, and network telemetry, build a complete evidence timeline, and respond per district policy.

**Why this matters in a K-12 environment:**

* CIPA Compliance — The Children's Internet Protection Act requires schools to enforce content filtering. TOR bypasses it entirely.
* Student Safety — Unfiltered network access exposes students to content that schools are legally required to block.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file downloads and creations.
- **Check `DeviceProcessEvents`** for signs of the browser being installed or launched.
- **Check `DeviceNetworkEvents`** for outgoing connections over known TOR communication ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I searched for any file modifications containing the string "tor". The logs show that a student account (`student.user`) downloaded a portable TOR browser installer on the high school lab computer (`HS-LAB-PC-04`). This action resulted in several TOR-related files being copied to the desktop, alongside a file named `unblocked-games-list.txt` created on `2024-11-08T22:27:19.7259964Z`. These events started at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "HS-LAB-PC-04"
| where InitiatingProcessAccountName == "student.user"
| where FileName contains "tor"
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

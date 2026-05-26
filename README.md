# Threat Hunt Report: Unauthorized TOR Usage 
## **School District Environment**</p>


<img width="675" height="607" alt="Screenshot 2026-05-26 at 7 09 11 PM" src="https://github.com/user-attachments/assets/99a6a1f4-f3a8-4811-a8f4-e702a1d20b03" />




# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Danielle-Respes/Threat-Hunting-Scenario-TOR/blob/main/Create%20threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario
In my day-to-day work at the high school, I constantly see students trying to get around our content filters to access blocked sites. This project started as a fun way to build out the detection and analysis skills I need to actually catch this activity and keep our network secure. 

I noticed a student account (`student.user`) was using a portable TOR browser on a high school computer lab endpoint to bypass our filters and hit restricted domains. The goal of this hunt is to detect unauthorized TOR installation and execution across our fleet, map out the incident, and ensure we're following student data safety policies. If I confirm TOR is being used, the plan is to escalate the findings to the IT Director and building admin for follow-up.

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

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, the student account (student.user) on the lab workstation (HS-LAB-PC-04) executed the installer, triggering a silent deployment installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 2. Searched the `DeviceProcessEvents` Table
Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". The logs show that at `2024-11-08T22:16:47.4484567Z`, the student account (`student.user`) on the lab workstation (`HS-LAB-PC-04`) executed the installer, triggering a silent installation.

**Query used to locate event:**
```kql
DeviceProcessEvents
| where DeviceName == "HS-LAB-PC-04"
| where AccountName == "student.user"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

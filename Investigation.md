# BOTS v3 SOC Investigation

## Day 1 - Initial Investigation

### 1. Host Discovery

I started by exploring the BOTS v3 dataset to identify the available hosts.

```spl
index=botsv3
| stats count by host
```

After reviewing the available hosts and their data sources, I focused the investigation on the Windows host:

`ABUNGST-L`

---

### 2. Windows Security Event Analysis

I analyzed the Windows Security logs available for `ABUNGST-L`.

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security
```

I focused on three Windows Event IDs:

- **4670** - Permissions on an object were changed
- **4688** - A new process was created
- **4689** - A process exited

To count these events, I used:

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security
(EventCode=4670 OR EventCode=4688 OR EventCode=4689)
| stats count by EventCode
```

Results:

| Event ID | Count |
|---|---:|
| 4670 | 345 |
| 4688 | 586 |
| 4689 | 596 |

Because Event ID **4688** records process creation, I decided to investigate the processes executed on the host.

---

### 3. Process Analysis

I filtered the dataset to Event ID 4688 and grouped the results by process name.

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security EventCode=4688
| stats count by New_Process_Name
```

This allowed me to reduce **586 process creation events** into a much smaller list of distinct processes.

I initially investigated `cmd.exe` activity.

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security EventCode=4688 New_Process_Name="*cmd.exe"
```

There were **127 CMD executions**.

To inspect the commands executed through CMD, I used the `Process_Command_Line` field.

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security EventCode=4688 New_Process_Name="*cmd.exe"
| stats count by Process_Command_Line
```

The CMD activity mainly contained commands related to system information, registry queries, network information, and software inventory.

No immediately malicious CMD execution was identified during this stage.

---

### 4. PowerShell Investigation

I returned to the Event ID 4688 process list and identified PowerShell executions for further investigation.

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security EventCode=4688 New_Process_Name="*powershell.exe"
```

There were **3 PowerShell process creation events**.

While reviewing the `Process_Command_Line` field, I identified PowerShell commands using:

`-enc`

This indicates the use of PowerShell's `EncodedCommand` functionality.

One of the observed process relationships was:

```text
browser_broker.exe
        |
        v
powershell.exe
        |
        v
Encoded PowerShell command
```

Because an encoded command hides the actual PowerShell instructions from immediate view, I investigated the encoded content further.

---

### 5. Decoding the PowerShell Command

I extracted the Base64-encoded value from the PowerShell command line and analyzed it using **CyberChef**.

The data was decoded using:

1. `From Base64`
2. `UTF-16LE` text decoding

The resulting PowerShell script contained several suspicious behaviors, including:

- Attempts to disable PowerShell Script Block Logging
- AMSI bypass behavior
- Creation of a `System.Net.WebClient`
- Disabling TLS certificate validation
- Network communication with an external server
- Downloading additional data
- Decryption of downloaded data
- Execution of the resulting content using `IEX` (`Invoke-Expression`)

The script contained the external IP address:

`45.77.53.176`

This IP became the next Indicator of Compromise (IOC) investigated in Splunk.

---

### 6. Network Investigation

I searched the BOTS v3 dataset for events where the identified external IP appeared as the source IP.

```spl
index=botsv3 src_ip="45.77.53.176"
```

This returned **6 network events**.

I grouped them by sourcetype:

```spl
index=botsv3 src_ip="45.77.53.176"
| stats count by sourcetype
```

Results:

| Sourcetype | Count |
|---|---:|
| stream:ip | 4 |
| stream:tcp | 2 |

One of the network flows contained:

```text
src_ip:    45.77.53.176
src_port:  8088

dest_ip:   192.168.9.30
dest_port: 40552

protocol: TCP
```

The event also showed traffic in both directions:

```text
bytes_in:  270
bytes_out: 198
bytes:     468
```

This established network communication between the external IP and the internal address `192.168.9.30`.

---

## Investigation Progress

The investigation path so far:

```text
Windows Security Logs
        |
        v
Event ID 4688
        |
        v
Process Creation Analysis
        |
        v
PowerShell Execution
        |
        v
EncodedCommand
        |
        v
Base64 / UTF-16LE Decoding
        |
        v
Suspicious PowerShell Script
        |
        v
External IP: 45.77.53.176
        |
        v
Network Telemetry
        |
        v
Internal IP: 192.168.9.30
```

## Next Step

Determine which host is associated with the internal IP address:

`192.168.9.30`

After identifying the host, continue correlating endpoint and network telemetry to understand the activity associated with the suspicious PowerShell execution.

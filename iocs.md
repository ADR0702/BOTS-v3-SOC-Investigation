# Indicators of Compromise

Indicators identified during the BOTS v3 investigation.

## Network Indicators

| Type | Value | Context |
|---|---|---|
| External IP | `45.77.53.176` | Identified inside the decoded PowerShell script and later found in network telemetry |
| Internal IP | `192.168.9.30` | Internal system observed communicating with the external IP |

## Suspicious Process Activity

| Process | Observation |
|---|---|
| `powershell.exe` | Executed with an encoded command |
| `browser_broker.exe` | Observed as the creator process of a suspicious PowerShell execution |

## PowerShell Indicators

Observed PowerShell behavior included:

- `-enc` / EncodedCommand
- PowerShell Script Block Logging bypass attempts
- AMSI bypass behavior
- `System.Net.WebClient`
- Disabled TLS certificate validation
- Download of additional data
- `IEX` / `Invoke-Expression` execution

## Investigation Status

The indicators above are findings from the BOTS v3 dataset investigation.

The next step is to determine which internal host is associated with:

`192.168.9.30`

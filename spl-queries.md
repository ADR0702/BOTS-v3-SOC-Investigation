# SPL Queries

SPL searches used during the BOTS v3 SOC investigation.

## Host Discovery

```spl
index=botsv3
| stats count by host
```

## Sourcetypes by Host

```spl
index=botsv3
| stats count by host sourcetype
```

## Windows Security Events

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security
(EventCode=4670 OR EventCode=4688 OR EventCode=4689)
| stats count by EventCode
```

## Process Creation

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security EventCode=4688
| stats count by New_Process_Name
```

## CMD Executions

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security EventCode=4688 New_Process_Name="*cmd.exe"
```

## CMD Command Lines

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security EventCode=4688 New_Process_Name="*cmd.exe"
| stats count by Process_Command_Line
```

## PowerShell Executions

```spl
index=botsv3 host=ABUNGST-L sourcetype=WinEventLog:Security EventCode=4688 New_Process_Name="*powershell.exe"
```

## External IP Investigation

```spl
index=botsv3 src_ip="45.77.53.176"
```

## Network Events by Sourcetype

```spl
index=botsv3 src_ip="45.77.53.176"
| stats count by sourcetype
```

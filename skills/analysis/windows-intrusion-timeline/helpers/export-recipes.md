# Artifact collection / export recipes (optional)

These are *examples* for producing **bounded, reviewable artifacts** suitable for building an intrusion timeline.

## Windows Event Logs (optional)

If you have access to Windows Event Logs, exporting a *targeted subset* (time-bounded, relevant EventIDs) can be enough.

### wevtutil (to rendered text)

- Export a time-bounded set of events (example uses XPath; adjust as needed).
- Output is XML by default; you can still paste relevant parts.

Example (Security log, last 24h):

```text
wevtutil qe Security /q:"*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:RenderedText /c:200
```

### PowerShell Get-WinEvent (objects → JSON)

Example (Security 4624/4625 within window; JSON output):

```powershell
$start = Get-Date "2025-12-26T00:00:00Z"
$end   = Get-Date "2025-12-26T23:59:59Z"

Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624,4625; StartTime=$start; EndTime=$end } |
  Select-Object TimeCreated, Id, LogName, MachineName, ProviderName, LevelDisplayName, Message |
  ConvertTo-Json -Depth 4
```

Tip: if you can, also export structured properties (not only `Message`).

## Sysmon (optional)

If Sysmon is present:

- Sysmon operational log: `Microsoft-Windows-Sysmon/Operational`
- High-signal EventIDs: 1, 3, 11, 13

## EDR / SIEM exports

CSV/JSON exports are perfect as long as they include:

- time
- host
- event_id (or alert/rule id)
- (ideally) user, source ip, process image, command line, parent/child linkage

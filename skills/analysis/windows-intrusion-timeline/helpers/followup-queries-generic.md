# Follow-up query checklist (generic)

Use these as a prompt to generate follow-up filters in your stack.

## Authentication

- 4624 success logons by user, host, source IP
- 4625 failures (password spray vs user error)
- 4648 explicit credential use
- 4672 special privileges assigned
- 4768/4769/4776 Kerberos/NTLM (if DC logs available)

## Account / privilege changes

- 4720/4722/4726 user create/enable/delete
- 4728/4732/4756 group membership additions

## Execution / persistence (if available)

- 4688 process creation (requires auditing)
- 7045 service install (System)
- Scheduled task creation (TaskScheduler Operational)
- PowerShell 4104 script blocks (PowerShell Operational)

## Sysmon (if available)

- 1 process creation (with parent + command line)
- 3 network connections from suspicious processes
- 11 file create for drops
- 13 registry set for persistence

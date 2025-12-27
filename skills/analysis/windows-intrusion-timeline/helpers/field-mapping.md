# Minimal field mapping

When you paste event exports, aim to include these *logical* fields.

| Logical field | Typical Windows field(s) | Notes |
|---|---|---|
| time | `TimeCreated`, `@SystemTime` | Include timezone; prefer UTC |
| host | `Computer`, `MachineName` | For forwarded events, include original host |
| log/channel | `Channel`, `LogName` | e.g., Security, System |
| event_id | `EventID`, `Id` | Integer |
| provider | `ProviderName` | Useful for Sysmon vs Security |
| user/actor | `TargetUserName`, `SubjectUserName` | Depends on EventID |
| src_ip | `IpAddress` | Present in many logon events |
| process | `NewProcessName`, `Image` | Sysmon uses `Image` |
| command_line | `CommandLine`, `ProcessCommandLine` | Often missing unless auditing enabled |

If you only have rendered messages, include 3–10 representative examples per EventID and call out what’s missing.

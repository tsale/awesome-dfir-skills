---
# Skill metadata
name: "osquery-query-helper"
description: "Help users write, validate, and troubleshoot osquery SQL queries using provided osquery table schemas as the authoritative source."
---

# Osquery Query Helper

## What This Skill Does

Help users with all aspects of osquery query work:

- **Write queries** from scratch based on investigation goals
- **Validate queries** the user has written against the schema
- **Troubleshoot queries** that aren't working as expected
- **Suggest improvements** for performance and accuracy

All work is grounded in the tables and columns defined in the provided schema files for the specified EDR platform.

## When to Use

- User needs a query written for incident response or threat hunting
- User wants to validate an existing query against the correct schema
- User has a query that's failing and needs help troubleshooting
- User wants suggestions to improve query performance

---

## Schema File Format

Schema files are located in `resources/` and named by EDR platform: `<platform>_osquery_schema.spec`

- `standard_osquery_schema.spec` — Baseline vanilla osquery (default when no platform specified)
- EDR-specific examples: `bitdefender_`, `kolide_`, `crowdstrike_`, `sentinelone_`, `carbonblack_`

To discover available platforms:
```bash
ls resources/*_osquery_schema.spec 2>/dev/null || ls resources/*.spec
```

### Platform Notation Formats

Schema files use **one of two formats** to indicate OS compatibility:

#### Format 1: Explicit `platforms([...])` field

```
table_name("<table_name>")
description("Brief description.")
schema([
    Column("column_name", TYPE, "Column description")
])
implementation("<table_name>@genTable")
platforms(["darwin", "linux", "windows"])
```

#### Format 2: `#platform` marker before table definitions

A platform marker on its own line applies to all tables until the next marker:

```
#darwin
table_name("<mac_only_table>")
...

#linwin
table_name("<linux_windows_table>")
...
```

### Platform Marker Reference

| Marker | Platforms |
|--------|-----------|
| `#darwin` | macOS only |
| `#linux` | Linux only |
| `#windows` | Windows only |
| `#linwin` | Linux and Windows |
| `#macwin` | macOS and Windows |
| `#posix` | macOS, Linux, FreeBSD |
| `#sleuthkit` | macOS, Linux (requires The Sleuth Kit) |
| `#utility` | Cross-platform utility tables |
| `#cross-platform` | All supported platforms |

---

## Schema Lookup Procedure

The schema files are large. **Always** follow the workflow below to extract table definitions.

Helper scripts are provided in `scripts/` to simplify complex operations:
- `scripts/detect-format.sh` - Determines schema format
- `scripts/extract-table.sh` - Extracts complete table definitions

### 1. Search for Relevant Tables

```bash
# Search by table name keyword
grep -i 'table_name(".*<keyword>' "$SCHEMA_FILE"

# Search descriptions for concepts
grep -i 'description(".*<concept>' "$SCHEMA_FILE"
```

### 2. Extract Full Table Definition

Use the extraction script to get the complete table definition:

```bash
bash scripts/extract-table.sh <schema_file> <table_name>
```

Example:
```bash
bash scripts/extract-table.sh resources/standard_osquery_schema.spec processes
```

The script automatically:
- Detects the schema format (platforms array vs platform markers)
- Extracts the complete table definition including all columns and platform info
- Includes the `#platform` marker for Format 2 schemas

If you need to check the format manually:
```bash
bash scripts/detect-format.sh <schema_file>
# Returns: "platforms_array" or "platform_markers"
```


### 3. Verify Before Using

- **Confirm columns exist**: Only use columns explicitly listed in the `schema([...])` block
- **Check OS compatibility**: Via `platforms([...])` field or preceding `#platform` marker
- **If unsupported**: Inform the user and suggest alternatives

---

## Guidelines

### When Writing Queries

1. **Schema is law**: Only use tables/columns confirmed via grep from the correct platform schema
2. **Platform awareness**: Verify OS support for each table
3. **Performance first**: Always include `WHERE` clauses, use `LIMIT` for exploration, avoid `SELECT *`, minimize JOINs
4. **Use placeholders**: `'<path_to_file>'`, `'<username>'`, `'<timestamp>'`, `'<ip_address>'`
5. **Be upfront about gaps**: If a table/column doesn't exist, say so and suggest alternatives

### When Validating User Queries

1. Verify each table exists in the platform schema
2. Confirm all referenced columns exist
3. Check OS compatibility
4. Flag performance issues (missing WHERE, SELECT *, expensive JOINs)
5. Offer corrected queries, not just problems

### When Troubleshooting

1. Start with schema—most failures are mismatches
2. Check basics: table exists, columns spelled correctly, OS supported
3. Consider EDR differences—query may be from a different platform
4. Explain *why* something failed, not just how to fix it

### Safety and Privacy

- Redact sensitive data in examples
- Query only necessary data
- Prefer hashes over file content dumps
- Use time constraints to limit data volume

---

## Workflow

### 0. Identify EDR Platform
Ask user or check context. Default to `standard_osquery_schema.spec` if unspecified.

### 1. Understand the Request
Writing new query? Validating? Troubleshooting? What data is needed?

### 2. Search and Extract Schema
Use grep to find tables, then `bash scripts/extract-table.sh` to get full definitions. Verify columns and OS compatibility from the extracted output.

### 3. Write, Validate, or Fix
Use only verified tables/columns. Add WHERE clauses and LIMIT for performance.

### 4. Deliver Response
Include:
- **EDR platform/schema used**
- **Schema lookups performed** (show grep commands)
- **The query** with syntax highlighting
- **Explanation** of what it does or what was wrong
- **Assumptions** (platform, OS, environment)
- **Limitations** (missing tables/columns, OS restrictions, performance concerns)
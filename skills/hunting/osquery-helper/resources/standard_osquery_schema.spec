#cross-platform
table_name("arp_cache")
description("Address resolution cache, both static and dynamic (from ARP, NDP).")
schema([
    Column("address", TEXT, "IPv4 address target"),
    Column("mac", TEXT, "MAC address of broadcasted address"),
    Column("interface", TEXT, "Interface of the network for the MAC"),
    Column("permanent", TEXT, "1 for true, 0 for false"),
])
implementation("linux/arp_cache,darwin/routes@genArpCache")
fuzz_paths([
    "/proc/net/arp",
])


#cross-platform
table_name("azure_instance_metadata")
description("Azure instance metadata.")
schema([
    Column("location", TEXT, "Azure Region the VM is running in"),
    Column("name", TEXT, "Name of the VM"),
    Column("offer", TEXT, "Offer information for the VM image (Azure image gallery VMs only)"),
    Column("publisher", TEXT, "Publisher of the VM image"),
    Column("sku", TEXT, "SKU for the VM image"),
    Column("version", TEXT, "Version of the VM image"),
    Column("os_type", TEXT, "Linux or Windows"),
    Column("platform_update_domain", TEXT, "Update domain the VM is running in"),
    Column("platform_fault_domain", TEXT, "Fault domain the VM is running in"),
    Column("vm_id", TEXT, "Unique identifier for the VM", index=True),
    Column("vm_size", TEXT, "VM size"),
    Column("subscription_id", TEXT, "Azure subscription for the VM"),
    Column("resource_group_name", TEXT, "Resource group for the VM"),
    Column("placement_group_id", TEXT, "Placement group for the VM scale set"),
    Column("vm_scale_set_name", TEXT, "VM scale set name"),
    Column("zone", TEXT, "Availability zone of the VM"),
])
attributes(cacheable=True)
implementation("cloud/azure_metadata@genAzureMetadata")
examples([
    "select * from ec2_instance_metadata"
])


#cross-platform
table_name("azure_instance_tags")
description("Azure instance tags.")
schema([
    Column("vm_id", TEXT, "Unique identifier for the VM"),
    Column("key", TEXT, "The tag key"),
    Column("value", TEXT, "The tag value"),
])
attributes(cacheable=True)
implementation("cloud/azure_metadata@genAzureTags")
examples([
    "select * from ec2_instance_tags"
])


#cross-platform
table_name("carbon_black_info", aliases=["cb_info"])
description("Returns info about a Carbon Black sensor install.")
schema([
    Column("sensor_id", INTEGER, "Sensor ID of the Carbon Black sensor"),
    Column("config_name", TEXT, "Sensor group"),
    Column("collect_store_files", INTEGER, "If the sensor is configured to send back binaries to the Carbon Black server"),
    Column("collect_module_loads", INTEGER, "If the sensor is configured to capture module loads"),
    Column("collect_module_info", INTEGER, "If the sensor is configured to collect metadata of binaries"),
    Column("collect_file_mods", INTEGER, "If the sensor is configured to collect file modification events"),
    Column("collect_reg_mods", INTEGER, "If the sensor is configured to collect registry modification events"),
    Column("collect_net_conns", INTEGER, "If the sensor is configured to collect network connections"),
    Column("collect_processes", INTEGER, "If the sensor is configured to process events"),
    Column("collect_cross_processes", INTEGER, "If the sensor is configured to cross process events"),
    Column("collect_emet_events", INTEGER, "If the sensor is configured to EMET events"),
    Column("collect_data_file_writes", INTEGER, "If the sensor is configured to collect non binary file writes"),
    Column("collect_process_user_context", INTEGER, "If the sensor is configured to collect the user running a process"),
    Column("collect_sensor_operations", INTEGER, "Unknown"),
    Column("log_file_disk_quota_mb", INTEGER, "Event file disk quota in MB"),
    Column("log_file_disk_quota_percentage", INTEGER, "Event file disk quota in a percentage"),
    Column("protection_disabled", INTEGER, "If the sensor is configured to report tamper events"),
    Column("sensor_ip_addr", TEXT, "IP address of the sensor"),
    Column("sensor_backend_server", TEXT, "Carbon Black server"),
    Column("event_queue", INTEGER, "Size in bytes of Carbon Black event files on disk"),
    Column("binary_queue", INTEGER, "Size in bytes of binaries waiting to be sent to Carbon Black server"),
])
implementation("carbon_black@genCarbonBlackInfo")
fuzz_paths([
    "/var/lib/cb",
])


#cross-platform
table_name("carves")
description("List the set of completed and in-progress carves. If carve=1 then the query is treated as a new carve request.")
schema([
    Column("time", BIGINT, "Time at which the carve was kicked off"),
    Column("sha256", TEXT, "A SHA256 sum of the carved archive"),
    Column("size", BIGINT, "Size in bytes of the carved archive"),
    Column("path", TEXT, "The path of the requested carve", additional=True),
    Column("status", TEXT, "Status of the carve, can be STARTING, PENDING, SUCCESS, or FAILED"),
    Column("carve_guid", TEXT, "Identifying value of the carve session", index=True),
    Column("request_id", TEXT, "Identifying value of the carve request (e.g., scheduled query name, distributed request, etc)"),
    Column("carve", INTEGER, "Set this value to '1' to start a file carve", additional=True)
])
implementation("forensic/carves@genCarves")
examples([
  "select * from carves",
  "select * from carves where status like '%FAIL%'",
  "select * from carves where path like '/Users/%/Downloads/%' and carve=1",
])


#cross-platform
table_name("certificates")
description("Certificate Authorities installed in Keychains/ca-bundles. NOTE: osquery limits frequent access to keychain files on macOS. This limit is controlled by keychain_access_interval flag.")
schema([
    Column("common_name", TEXT, "Certificate CommonName"),
    Column("subject", TEXT, "Certificate distinguished name (deprecated, use subject2)"),
    Column("issuer", TEXT, "Certificate issuer distinguished name (deprecated, use issuer2)"),
    Column("ca", INTEGER, "1 if CA: true (certificate is an authority) else 0"),
    Column("self_signed", INTEGER, "1 if self-signed, else 0"),
    Column("not_valid_before", DATETIME, "Lower bound of valid date"),
    Column("not_valid_after", DATETIME, "Certificate expiration data"),
    Column("signing_algorithm", TEXT, "Signing algorithm used"),
    Column("key_algorithm", TEXT, "Key algorithm used"),
    Column("key_strength", TEXT, "Key size used for RSA/DSA, or curve name"),
    Column("key_usage", TEXT, "Certificate key usage and extended key usage"),
    Column("subject_key_id", TEXT, "SKID an optionally included SHA1"),
    Column("authority_key_id", TEXT, "AKID an optionally included SHA1"),
    Column("sha1", TEXT, "SHA1 hash of the raw certificate contents"),
    Column("path", TEXT, "Path to Keychain or PEM bundle", additional=True, optimized=True),
    Column("serial", TEXT, "Certificate serial number"),

])

extended_schema(WINDOWS, [
    Column("sid", TEXT, "SID"),
    Column("store_location", TEXT, "Certificate system store location"),
    Column("store", TEXT, "Certificate system store"),
    Column("username", TEXT, "Username"),
    Column("store_id", TEXT, "Exists for service/user stores. Contains raw store id provided by WinAPI."),
])

extended_schema(POSIX, [
    Column("issuer2", TEXT, "Certificate issuer distinguished name", hidden=True),
    Column("subject2", TEXT, "Certificate distinguished name", hidden=True),
])

attributes(cacheable=True)
implementation("certificates@genCerts")


#cross-platform
table_name("chrome_extension_content_scripts")
description("Chrome browser extension content scripts.")
schema([
    Column("browser_type", TEXT, "The browser type (Valid values: chrome, chromium, opera, yandex, brave)"),
    Column("uid", BIGINT, "The local user that owns the extension", index=True, optimized=True),
    Column("identifier", TEXT, "Extension identifier"),
    Column("version", TEXT, "Extension-supplied version"),
    Column("script", TEXT, "The content script used by the extension"),
    Column("match", TEXT, "The pattern that the script is matched against"),
    Column("profile_path", TEXT, "The profile path"),
    Column("path", TEXT, "Path to extension folder"),
    Column("referenced", BIGINT, "1 if this extension is referenced by the Preferences file of the profile"),
    ForeignKey(column="uid", table="users"),
])
attributes(user_data=True)
implementation("applications/browser_chrome@genChromeExtensionContentScripts")
examples([
    "SELECT chrome_extension_content_scripts.* FROM users JOIN chrome_extension_content_scripts USING (uid) GROUP BY identifier, match",
])
fuzz_paths([
    "/Library/Application Support/Google/Chrome/",
    "/Users",
])


#cross-platform
table_name("chrome_extensions")
description("Chrome-based browser extensions.")
schema([
    Column("browser_type", TEXT, "The browser type (Valid values: chrome, chromium, opera, yandex, brave, edge, edge_beta)"),
    Column("uid", BIGINT, "The local user that owns the extension", index=True, optimized=True),
    Column("name", TEXT, "Extension display name"),
    Column("profile", TEXT, "The name of the Chrome profile that contains this extension"),
    Column("profile_path", TEXT, "The profile path"),
    Column("referenced_identifier", TEXT, "Extension identifier, as specified by the preferences file. Empty if the extension is not in the profile."),
    Column("identifier", TEXT, "Extension identifier, computed from its manifest. Empty in case of error."),
    Column("version", TEXT, "Extension-supplied version"),
    Column("description", TEXT, "Extension-optional description"),
    Column("default_locale", TEXT, "Default locale supported by extension", aliases=["locale"]),
    Column("current_locale", TEXT, "Current locale supported by extension"),
    Column("update_url", TEXT, "Extension-supplied update URI"),
    Column("author", TEXT, "Optional extension author"),
    Column("persistent", INTEGER, "1 If extension is persistent across all tabs else 0"),
    Column("path", TEXT, "Path to extension folder"),
    Column("permissions", TEXT, "The permissions required by the extension"),
    Column("permissions_json", TEXT, "The JSON-encoded permissions required by the extension", hidden=True),
    Column("optional_permissions", TEXT, "The permissions optionally required by the extensions"),
    Column("optional_permissions_json", TEXT, "The JSON-encoded permissions optionally required by the extensions", hidden=True),
    Column("manifest_hash", TEXT, "The SHA256 hash of the manifest.json file"),
    Column("referenced", BIGINT, "1 if this extension is referenced by the Preferences file of the profile"),
    Column("from_webstore", TEXT, "True if this extension was installed from the web store"),
    Column("state", TEXT, "1 if this extension is enabled"),
    Column("install_time", TEXT, "Extension install time, in its original Webkit format"),
    Column("install_timestamp", BIGINT, "Extension install time, converted to unix time"),
    Column("manifest_json", TEXT, "The manifest file of the extension", hidden=True),
    Column("key", TEXT, "The extension key, from the manifest file", hidden=True),
    ForeignKey(column="uid", table="users"),
])
attributes(user_data=True)
implementation("applications/browser_chrome@genChromeExtensions")
examples([
    "select * from users join chrome_extensions using (uid)",
])
fuzz_paths([
    "/Library/Application Support/Google/Chrome/",
    "/Users",
])


#cross-platform

table_name("cpu_info")
description("Retrieve cpu hardware info of the machine.")
schema([
  Column("device_id", TEXT, "The DeviceID of the CPU."),
  Column("model", TEXT, "The model of the CPU."),
  Column("manufacturer", TEXT, "The manufacturer of the CPU."),
  Column("processor_type", TEXT, "The processor type, such as Central, Math, or Video."),
  Column("cpu_status", INTEGER, "The current operating status of the CPU."),
  Column("number_of_cores", TEXT, "The number of cores of the CPU."),
  Column("logical_processors", INTEGER, "The number of logical processors of the CPU."),
  Column("address_width", TEXT, "The width of the CPU address bus."),
  Column("current_clock_speed", INTEGER, "The current frequency of the CPU."),
  Column("max_clock_speed", INTEGER, "The maximum possible frequency of the CPU."),
  Column("socket_designation", TEXT, "The assigned socket on the board for the given CPU."),
])
extended_schema(WINDOWS, [
    Column("availability", TEXT, "The availability and status of the CPU."),
    Column("load_percentage", INTEGER, "The current percentage of utilization of the CPU."),
])
extended_schema(DARWIN, [
    Column("number_of_efficiency_cores", INTEGER, "The number of efficiency cores of the CPU. Only available on Apple Silicon"),
    Column("number_of_performance_cores", INTEGER, "The number of performance cores of the CPU. Only available on Apple Silicon")
])
implementation("cpu_info@genCpuInfo")


#cross-platform
table_name("cpuid")
description("Useful CPU features from the cpuid ASM call.")
schema([
    Column("feature", TEXT, "Present feature flags"),
    Column("value", TEXT, "Bit value or string"),
    Column("output_register", TEXT, "Register used to for feature value"),
    Column("output_bit", INTEGER, "Bit in register value for feature value"),
    Column("input_eax", TEXT, "Value of EAX used"),
])
implementation("cpuid@genCPUID")


#cross-platform
table_name("curl")
description("Perform an http request and return stats about it.")
schema([
    Column("url", TEXT, "The url for the request", required=True, index=True, optimized=True),
    Column("method", TEXT, "The HTTP method for the request"),
    Column("user_agent", TEXT, "The user-agent string to use for the request",
       additional=True),
    Column("response_code", INTEGER, "The HTTP status code for the response"),
    Column("round_trip_time", BIGINT, "Time taken to complete the request"),
    Column("bytes", BIGINT, "Number of bytes in the response"),
    Column("result", TEXT, "The HTTP response body"),
])
implementation("networking/curl@genCurl")
examples([
  "select url, round_trip_time, response_code from curl where url = 'https://github.com/osquery/osquery'",
])


#cross-platform
table_name("curl_certificate")
description("Inspect TLS certificates by connecting to input hostnames.")
schema([
    Column("hostname", TEXT, "Hostname to CURL (domain[:port], e.g. osquery.io)", required=True, optimized=True),
    Column("common_name", TEXT, "Common name of company issued to"),
    Column("organization", TEXT, "Organization issued to"),
    Column("organization_unit", TEXT, "Organization unit issued to"),
    Column("serial_number", TEXT, "Certificate serial number"),
    Column("issuer_common_name", TEXT, "Issuer common name"),
    Column("issuer_organization", TEXT, "Issuer organization"),
    Column("issuer_organization_unit", TEXT, "Issuer organization unit"),
    Column("valid_from", TEXT, "Period of validity start date"),
    Column("valid_to", TEXT, "Period of validity end date"),
    Column("sha256_fingerprint", TEXT, "SHA-256 fingerprint"),
    Column("sha1_fingerprint", TEXT, "SHA1 fingerprint"),
    Column("version", INTEGER, "Version Number"),
    Column("signature_algorithm", TEXT, "Signature Algorithm"),
    Column("signature", TEXT, "Signature"),
    Column("subject_key_identifier", TEXT, "Subject Key Identifier"),
    Column("authority_key_identifier", TEXT, "Authority Key Identifier"),
    Column("key_usage", TEXT, "Usage of key in certificate"),
    Column("extended_key_usage", TEXT, "Extended usage of key in certificate"),
    Column("policies", TEXT, "Certificate Policies"),
    Column("subject_alternative_names", TEXT, "Subject Alternative Name"),
    Column("issuer_alternative_names", TEXT, "Issuer Alternative Name"),
    Column("info_access", TEXT, "Authority Information Access"),
    Column("subject_info_access", TEXT, "Subject Information Access"),
    Column("policy_mappings", TEXT, "Policy Mappings"),
    Column("has_expired", INTEGER, "1 if the certificate has expired, 0 otherwise"),
    Column("basic_constraint", TEXT, "Basic Constraints"),
    Column("name_constraints", TEXT, "Name Constraints"),
    Column("policy_constraints", TEXT, "Policy Constraints"),
    Column("dump_certificate", INTEGER, "Set this value to '1' to dump certificate", additional=True, hidden=True),
    Column("timeout", INTEGER, "Set this value to the timeout in seconds to complete the TLS handshake (default 4s, use 0 for no timeout)", additional=True, hidden=True),
    Column("pem", TEXT, "Certificate PEM format")
])
implementation("curl_certificate@genTLSCertificate")
examples([
  "select * from curl_certificate where hostname = 'osquery.io'"
  "select * from curl_certificate where hostname = 'osquery.io' and dump_certificate = 1"
])


#darwin
table_name("account_policy_data")
description("Additional macOS user account data from the AccountPolicy section of OpenDirectory.")
schema([
    Column("uid", BIGINT, "User ID"),
    Column("creation_time", DOUBLE, "When the account was first created"),
    Column("failed_login_count", BIGINT, "The number of failed login attempts using an incorrect password. Count resets after a correct password is entered."),
    Column("failed_login_timestamp", DOUBLE, "The time of the last failed login attempt. Resets after a correct password is entered"),
    Column("password_last_set_time", DOUBLE, "The time the password was last changed"),
    ForeignKey(column="uid", table="users"),
])
implementation("account_policy_data@genAccountPolicyData")
examples([
  "select * from users join account_policy_data using (uid)",
])


#darwin
table_name("ad_config")
description("macOS Active Directory configuration.")
schema([
    Column("name", TEXT, "The macOS-specific configuration name"),
    Column("domain", TEXT, "Active Directory trust domain"),
    Column("option", TEXT, "Canonical name of option"),
    Column("value", TEXT, "Variable typed option value"),
])
implementation("ad_config@genADConfig")
fuzz_paths([
    "/Library/Preferences/OpenDirectory/Configurations/Active Directory/",
])


#darwin
table_name("alf")
description("macOS application layer firewall (ALF) service details.")
schema([
    Column("allow_signed_enabled", INTEGER, "1 If allow signed mode is enabled else 0 (not supported on macOS 15+)"),
    Column("firewall_unload", INTEGER, "1 If firewall unloading enabled else 0 (not supported on macOS 15+)"),
    Column("global_state", INTEGER, "1 If the firewall is enabled with exceptions, 2 if the firewall is configured to block all incoming connections, else 0"),
    Column("logging_enabled", INTEGER, "1 If logging mode is enabled else 0"),
    Column("logging_option", INTEGER, "Firewall logging option (not supported on macOS 15+)"),
    Column("stealth_enabled", INTEGER, "1 If stealth mode is enabled else 0"),
    Column("version", TEXT, "Application Layer Firewall version", collate="version"),
])
implementation("firewall@genALF")
fuzz_paths([
    "/Library/Preferences/com.apple.alf.plist",
])


#darwin
table_name("alf_exceptions")
description("macOS application layer firewall (ALF) service exceptions.")
schema([
    Column("path", TEXT, "Path to the executable that is excepted. On macOS 15+ this can also be a bundle identifier"),
    Column("state", INTEGER, "Firewall exception state. 0 if the application is configured to allow incoming connections, 2 if the application is configured to block incoming connections and 3 if the application is configuted to allow incoming connections but with additional restrictions."),
])
implementation("firewall@genALFExceptions")


#darwin
table_name("alf_explicit_auths")
description("ALF services explicitly allowed to perform networking. Not supported on macOS 15+ (returns no results).")
schema([
    Column("process", TEXT, "Process name that is explicitly allowed"),
])
implementation("firewall@genALFExplicitAuths")


#darwin
table_name("app_schemes")
description("macOS application schemes and handlers (e.g., http, file, mailto).")
schema([
    Column("scheme", TEXT, "Name of the scheme/protocol"),
    Column("handler", TEXT, "Application label for the handler"),
    Column("enabled", INTEGER, "1 if this handler is the OS default, else 0"),
    Column("external", INTEGER,
        "1 if this handler does NOT exist on macOS by default, else 0"),
    Column("protected", INTEGER,
        "1 if this handler is protected (reserved) by macOS, else 0"),
])
implementation("apps@genAppSchemes")


#darwin
table_name("apps")
description("macOS applications installed in known search paths (e.g., /Applications).")
schema([
    Column("name", TEXT, "Name of the Name.app folder"),
    Column("path", TEXT, "Absolute and full Name.app path", index=True, optimized=True),
    Column("bundle_executable", TEXT,
        "Info properties CFBundleExecutable label"),
    Column("bundle_identifier", TEXT,
        "Info properties CFBundleIdentifier label", collate="nocase"),
    Column("bundle_name", TEXT, "Info properties CFBundleName label"),
    Column("bundle_short_version", TEXT,
        "Info properties CFBundleShortVersionString label", collate="version"),
    Column("bundle_version", TEXT, "Info properties CFBundleVersion label", collate="version"),
    Column("bundle_package_type", TEXT,
        "Info properties CFBundlePackageType label"),
    Column("environment", TEXT, "Application-set environment variables"),
    Column("element", TEXT, "Does the app identify as a background agent"),
    Column("compiler", TEXT, "Info properties DTCompiler label"),
    Column("development_region", TEXT,
        "Info properties CFBundleDevelopmentRegion label"),
    Column("display_name", TEXT, "Info properties CFBundleDisplayName label"),
    Column("info_string", TEXT, "Info properties CFBundleGetInfoString label"),
    Column("minimum_system_version", TEXT,
        "Minimum version of macOS required for the app to run", collate="version"),
    Column("category", TEXT,
        "The UTI that categorizes the app for the App Store"),
    Column("applescript_enabled", TEXT,
        "Info properties NSAppleScriptEnabled label"),
    Column("copyright", TEXT, "Info properties NSHumanReadableCopyright label"),
    Column("last_opened_time", DOUBLE, "The time that the app was last used"),
])
attributes(cacheable=True)
implementation("apps@genApps")


#darwin
table_name("asl")
description("Queries the Apple System Log data structure for system events.")

# Columns pulled from asl.h
# Descriptions mostly as retrieved from asl.h, some with clarifications
schema([
    Column("time", INTEGER, "Unix timestamp.  Set automatically", additional=True),
    Column("time_nano_sec", INTEGER, "Nanosecond time.", additional=True),
    Column("host", TEXT, "Sender's address (set by the server).", additional=True),
    Column("sender", TEXT, "Sender's identification string.  Default is process name.", additional=True),
    Column("facility", TEXT, "Sender's facility.  Default is 'user'.", additional=True),
    Column("pid", INTEGER, "Sending process ID encoded as a string.  Set automatically.", additional=True),
    # UID and GID of 4294967294 have been encountered
    Column("gid", BIGINT, "GID that sent the log message (set by the server).", additional=True),
    Column("uid", BIGINT, "UID that sent the log message (set by the server).", additional=True),
    Column("level", INTEGER, "Log level number.  See levels in asl.h.", additional=True),
    Column("message", TEXT, "Message text.", additional=True),
    Column("ref_pid", INTEGER, "Reference PID for messages proxied by launchd", additional=True),
    Column("ref_proc", TEXT, "Reference process for messages proxied by launchd", additional=True),
    # Gather anything extra into the "extra" column
    Column("extra", TEXT, "Extra columns, in JSON format. Queries against this column are performed entirely in SQLite, so do not benefit from efficient querying via asl.h."),
])

implementation("asl@genAsl")


#darwin
table_name("authorization_mechanisms")
description("macOS Authorization mechanisms database.")
schema([
    Column("label", TEXT, "Label of the authorization right", index=True, optimized=True),
    Column("plugin", TEXT, "Authorization plugin name"),
    Column("mechanism", TEXT, "Name of the mechanism that will be called"),
    Column("privileged", TEXT, "If privileged it will run as root, else as an anonymous user"),
    Column("entry", TEXT, "The whole string entry"),
])
implementation("system/darwin/authorization_mechanisms@genAuthorizationMechanisms")
examples([
  "select * from authorization_mechanisms;",
  "select * from authorization_mechanisms where label = 'system.login.console';",
  "select * from authorization_mechanisms where label = 'authenticate';"
])


#darwin
table_name("authorizations")
description("macOS Authorization rights database.")
schema([
    Column("label", TEXT, "Item name, usually in reverse domain format", index=True, optimized=True),
    Column("modified", TEXT, "Label top-level key"),
    Column("allow_root", TEXT, "Label top-level key"),
    Column("timeout", TEXT, "Label top-level key"),
    Column("version", TEXT, "Label top-level key"),
    Column("tries", TEXT, "Label top-level key"),
    Column("authenticate_user", TEXT, "Label top-level key"),
    Column("shared", TEXT, "Label top-level key"),
    Column("comment", TEXT, "Label top-level key"),
    Column("created", TEXT, "Label top-level key"),
    Column("class", TEXT, "Label top-level key"),
    Column("session_owner", TEXT, "Label top-level key"),
])
implementation("system/darwin/authorizations@genAuthorizations")
examples([
    "select * from authorizations;",
    "select * from authorizations where label = 'system.login.console';",
    "select * from authorizations where label = 'authenticate';",
    "select * from authorizations where label = 'system.preferences.softwareupdate';"
])
fuzz_paths([
    "/System/Library/Security/authorization.plist",
])


#darwin
table_name("browser_plugins")
description("All C/NPAPI browser plugin details for all users. C/NPAPI has been deprecated on all major browsers. To query for plugins on modern browsers, try: `chrome_extensions` `firefox_addons` `safari_extensions`.")
schema([
    Column("uid", BIGINT, "The local user that owns the plugin",
      index=True),
    Column("name", TEXT, "Plugin display name"),
    Column("identifier", TEXT, "Plugin identifier"),
    Column("version", TEXT, "Plugin short version", collate="version"),
    Column("sdk", TEXT, "Build SDK used to compile plugin"),
    Column("description", TEXT, "Plugin description text"),
    Column("development_region", TEXT, "Plugin language-localization"),
    Column("native", INTEGER, "Plugin requires native execution"),
    Column("path", TEXT, "Path to plugin bundle", index=True),
    Column("disabled", INTEGER, "Is the plugin disabled. 1 = Disabled"),
    ForeignKey(column="uid", table="users")
])
attributes(user_data=True)
implementation("applications/browser_plugins@genBrowserPlugins")
examples([
    "select * from users join browser_plugins using (uid)",
])
fuzz_paths([
    "/Library/Internet Plug-Ins",
    "/Users",
])


#darwin
table_name("certificate_trust_settings")
description("Certificate Authorities trust settings installed in Keychains/ca-bundles.")
schema([
    Column("common_name", TEXT, "Certificate common name"),
    Column("serial", TEXT, "Certificate serial number"),
    Column("trust_domain", TEXT, "Certificate trust settings domain", index=True, optimized=True),
    Column("trust_policy_name", TEXT, "Certificate trust policy name"),
    Column("trust_policy_data", TEXT, "Certificate trust policy data"),
    Column("trust_allowed_error", TEXT, "Certificate trust allowed error"),
    Column("trust_key_usage", TEXT, "Certificate trust key usage"),
    Column("trust_result", TEXT, "Certificate trust result"),
])
implementation("certificate_trust_settings@genCertificateTrustSettings")
examples([
    "select * from certificate_trust_settings where trust_domain = 'admin'",
])


#darwin
table_name("connected_displays")
description("Provides information about the connected displays of the machine.")
schema([
    Column("name", TEXT, "The name of the display."),
    Column("product_id", TEXT, "The product ID of the display."),
    Column("serial_number", TEXT, "The serial number of the display. (may not be unique)"),
    Column("vendor_id", TEXT, "The vendor ID of the display."),
    Column("manufactured_week", INTEGER, "The manufacture week of the display. This field is 0 if not supported"),
    Column("manufactured_year", INTEGER, "The manufacture year of the display. This field is 0 if not supported"),
    Column("display_id", TEXT, "The display ID."),
    Column("pixels", TEXT, "The number of pixels of the display."),
    Column("resolution", TEXT, "The resolution of the display."),
    Column("ambient_brightness_enabled", TEXT, "The ambient brightness setting associated with the display. This will be 1 if enabled and is 0 if disabled or not supported."),
    Column("connection_type", TEXT, "The connection type associated with the display."),
    Column("display_type", TEXT, "The type of display."),
    Column("main", INTEGER, "If the display is the main display."),
    Column("mirror", INTEGER, "If the display is mirrored or not. This field is 1 if mirrored and 0 if not mirrored."),
    Column("online", INTEGER, "The online status of the display. This field is 1 if the display is online and 0 if it is offline."),
    Column("rotation", TEXT, "The rotation of the display (0, 90, 180, or 270 degrees). This field is -1 if display rotation is not supported."),
])
implementation("connected_displays@genConnectedDisplays")


#darwin
table_name("crashes")
description("Application, System, and Mobile App crash logs.")
schema([
    Column("type", TEXT, "Type of crash log"),
    Column("pid", BIGINT, "Process (or thread) ID of the crashed process"),
    Column("path", TEXT, "Path to the crashed process"),
    Column("crash_path", TEXT, "Location of log file", index=True),
    Column("identifier", TEXT, "Identifier of the crashed process"),
    Column("version", TEXT, "Version info of the crashed process", collate="version"),
    Column("parent", BIGINT, "Parent PID of the crashed process"),
    Column("responsible", TEXT, "Process responsible for the crashed process"),
    Column("uid", INTEGER, "User ID of the crashed process", index=True),
    Column("datetime", TEXT, "Date/Time at which the crash occurred"),
    Column("crashed_thread", BIGINT, "Thread ID which crashed"),
    Column("stack_trace", TEXT, "Most recent frame from the stack trace"),
    Column("exception_type", TEXT, "Exception type of the crash"),
    Column("exception_codes", TEXT, "Exception codes from the crash"),
    Column("exception_notes", TEXT, "Exception notes from the crash"),
    Column("registers", TEXT, "The value of the system registers")
])
attributes(user_data=True)
implementation("crashes@genCrashLogs")
examples([
    "select * from users join crashes using (uid)",
])
fuzz_paths([
    "/Library/Logs/DiagnosticReports",
    "/Users",
])


#darwin
table_name("cups_destinations")
description("Returns all configured printers.")
schema([
    Column("name", TEXT, "Name of the printer"),
    Column("option_name", TEXT, "Option name"),
    Column("option_value", TEXT, "Option value")
])
implementation("cups_destinations@genCupsDestinations")


#darwin
table_name("cups_jobs")
description("Returns all completed print jobs from cups.")
schema([
    Column("title", TEXT, "Title of the printed job"),
    Column("destination", TEXT, "The printer the job was sent to"),
    Column("user", TEXT, "The user who printed the job"),
    Column("format", TEXT, "The format of the print job"),
    Column("size", INTEGER, "The size of the print job"),
    Column("completed_time", INTEGER, "When the job completed printing"),
    Column("processing_time", INTEGER, "How long the job took to process"),
    Column("creation_time", INTEGER, "When the print request was initiated"),
])
implementation("cups_jobs@genCupsJobs")


#darwin
table_name("device_firmware")
description("A best-effort list of discovered firmware versions.")
schema([
    Column("type", TEXT, "Type of device"),
    Column("device", TEXT, "The device name", index=True),
    Column("version", TEXT, "Firmware version", collate="version"),
])
implementation("device_firmware@genDeviceFirmware")


#darwin
table_name("disk_events")
description("Track DMG disk image events (appearance/disappearance) when opened.")
schema([
    Column("action", TEXT, "Appear or disappear"),
    Column("path", TEXT, "Path of the DMG file accessed"),
    Column("name", TEXT, "Disk event name"),
    Column("device", TEXT, "Disk event BSD name",
        aliases=["bsd_name"]),
    Column("uuid", TEXT, "UUID of the volume inside DMG if available"),
    Column("size", BIGINT, "Size of partition in bytes"),
    Column("ejectable", INTEGER, "1 if ejectable, 0 if not"),
    Column("mountable", INTEGER, "1 if mountable, 0 if not"),
    Column("writable", INTEGER, "1 if writable, 0 if not"),
    Column("content", TEXT, "Disk event content"),
    Column("media_name", TEXT, "Disk event media name string"),
    Column("vendor", TEXT, "Disk event vendor string"),
    Column("filesystem", TEXT, "Filesystem if available"),
    Column("checksum", TEXT, "UDIF Master checksum if available (CRC32)"),
    Column("time", BIGINT, "Time of appearance/disappearance in UNIX time", additional=True),
    Column("eid", TEXT, "Event ID", hidden=True),
])
attributes(event_subscriber=True)
implementation("events/darwin/disk_events@disk_events::genTable")


#darwin
table_name("es_process_events")
description("Process execution events from EndpointSecurity.")
schema([
    Column("version", INTEGER, "Version of EndpointSecurity event"),
    Column("seq_num", BIGINT, "Per event sequence number"),
    Column("global_seq_num", BIGINT, "Global sequence number"),
    Column("pid", BIGINT, "Process (or thread) ID"),
    Column("pidversion", BIGINT, "Process ID version"),
    Column("path", TEXT, "Path of executed file"),
    Column("parent", BIGINT, "Parent process ID"),
    Column("original_parent", BIGINT, "Original parent process ID in case of reparenting"),
    Column("session_id", BIGINT, "The identifier of the session that contains the process group."),
    Column("responsible_pid", BIGINT, "The pid of the process responsible for this process."),
    Column("responsible_pidversion", BIGINT, "The pidversion of the process responsible for this process."),
    Column("parent_pidversion", BIGINT, "The pidversion of the parent process."),
    Column("cmdline", TEXT, "Command line arguments (argv)"),
    Column("cmdline_count", BIGINT, "Number of command line arguments"),
    Column("env", TEXT, "Environment variables delimited by spaces"),
    Column("env_count", BIGINT, "Number of environment variables"),
    Column("cwd", TEXT, "The process current working directory"),
    Column("uid", BIGINT, "User ID of the process"),
    Column("euid", BIGINT, "Effective User ID of the process"),
    Column("gid", BIGINT, "Group ID of the process"),
    Column("egid", BIGINT, "Effective Group ID of the process"),
    Column("username", TEXT, "Username"),
    Column("signing_id", TEXT, "Signature identifier of the process"),
    Column("team_id", TEXT, "Team identifier of the process"),
    Column("cdhash", TEXT, "Codesigning hash of the process"),
    Column("platform_binary", INTEGER, "Indicates if the binary is Apple signed binary (1) or not (0)"),
    Column("exit_code", INTEGER, "Exit code of a process in case of an exit event"),
    Column("child_pid", BIGINT, "Process ID of a child process in case of a fork event"),
    Column("time", BIGINT, "Time of execution in UNIX time", additional=True),
    Column("event_type", TEXT, "Type of EndpointSecurity event"),
    Column("eid", TEXT, "Event ID", hidden=True),
    Column("codesigning_flags", TEXT, "Codesigning flags matching one of these options, in a comma separated list: NOT_VALID, ADHOC, NOT_RUNTIME, INSTALLER. See kern/cs_blobs.h in XNU for descriptions."),
])
attributes(event_subscriber=True)
implementation("events/darwin/es_process_events@es_process_events::genTable")


#darwin
table_name("es_process_file_events")
description("File integrity monitoring events from EndpointSecurity including process context.")
schema([
    Column("version", INTEGER, "Version of EndpointSecurity event"),
    Column("seq_num", BIGINT, "Per event sequence number"),
    Column("global_seq_num", BIGINT, "Global sequence number"),
    Column("pid", BIGINT, "Process (or thread) ID"),
     Column("parent", BIGINT, "Parent process ID"),
    Column("path", TEXT, "Path of executed file"),
    Column("filename", TEXT, "The source or target filename for the event"),
    Column("dest_filename", TEXT, "Destination filename for the event"),
    Column("event_type", TEXT, "Type of EndpointSecurity event"),
    Column("time", BIGINT, "Time of execution in UNIX time", additional=True),
    Column("eid", TEXT, "Event ID", hidden=True),
])
attributes(event_subscriber=True)
implementation("events/darwin/es_process_file_events@es_process_file_events::genTable")


#darwin
table_name("event_taps")
description("Returns information about installed event taps.")
schema([
    Column("enabled", INTEGER, "Is the Event Tap enabled"),
    Column("event_tap_id", INTEGER, "Unique ID for the Tap"),
    Column("event_tapped", TEXT, "The mask that identifies the set of events to be observed."),
    Column("process_being_tapped", INTEGER, "The process ID of the target application"),
    Column("tapping_process", INTEGER, "The process ID of the application that created the event tap."),
])
implementation("event_taps@genEventTaps")


#darwin
table_name("fan_speed_sensors")
description("Fan speeds.")
schema([
    Column("fan", TEXT, "Fan number"),
    Column("name", TEXT, "Fan name"),
    Column("actual", INTEGER, "Actual speed"),
    Column("min", INTEGER, "Minimum speed"),
    Column("max", INTEGER, "Maximum speed"),
    Column("target", INTEGER, "Target speed"),
])
implementation("smc_keys@genFanSpeedSensors")


#darwin
table_name("gatekeeper")
description("macOS Gatekeeper Details.")
schema([
    Column("assessments_enabled", INTEGER, "1 If a Gatekeeper is enabled else 0"),
    Column("dev_id_enabled", INTEGER, "1 If a Gatekeeper allows execution from identified developers else 0"),
    Column("version", TEXT, "Version of Gatekeeper's gke.bundle", collate="version"),
    Column("opaque_version", TEXT, "Version of Gatekeeper's gkopaque.bundle", collate="version"),
])
implementation("gatekeeper@genGateKeeper")
fuzz_paths([
    "/var/db/SystemPolicy"
])


#darwin
table_name("gatekeeper_approved_apps")
description("Gatekeeper apps a user has allowed to run.")
schema([
    Column("path", TEXT, "Path of executable allowed to run"),
    Column("requirement", TEXT, "Code signing requirement language"),
    Column("ctime", DOUBLE, "Last change time"),
    Column("mtime", DOUBLE, "Last modification time"),
])
implementation("gatekeeper@genGateKeeperApprovedApps")
fuzz_paths([
    "/var/db/SystemPolicy"
])


#darwin
table_name("homebrew_packages")
description("The installed homebrew package database.")
schema([
    Column("name", TEXT, "Package name"),
    Column("path", TEXT, "Package install path"),
    Column("version", TEXT, "Current 'linked' version", collate="version"),
    Column("type", TEXT, "Package type ('formula' or 'cask')"),
    Column("auto_updates", INTEGER, "1 if the cask auto-updates otherwise 0"),
    Column("app_name", TEXT, "Name of the installed App (for Casks)"),
    Column("prefix", TEXT, "Homebrew install prefix", hidden=True, additional=True, optimized=True),
])
attributes(cacheable=True)
implementation("system/homebrew_packages@genHomebrewPackages")


#darwin
table_name("ibridge_info")
description("Information about the Apple iBridge hardware controller.")
schema([
    Column("boot_uuid", TEXT, "Boot UUID of the iBridge controller"),
    Column("coprocessor_version", TEXT, "The manufacturer and chip version"),
    Column("firmware_version", TEXT, "The build version of the firmware"),
    Column("unique_chip_id", TEXT, "Unique id of the iBridge controller"),
])
attributes(cacheable=True)
implementation("system/ibridge@genIBridgeInfo")


#darwin
table_name("iokit_devicetree")
description("The IOKit registry matching the DeviceTree plane.")
schema([
    Column("name", TEXT, "Device node name"),
    Column("class", TEXT, "Best matching device class (most-specific category)"),
    Column("id", BIGINT, "IOKit internal registry ID"),
    Column("parent", BIGINT, "Parent device registry ID"),
    Column("device_path", TEXT, "Device tree path"),
    Column("service", INTEGER, "1 if the device conforms to IOService else 0"),
    Column("busy_state", INTEGER, "1 if the device is in a busy state else 0"),
    Column("retain_count", INTEGER, "The device reference count"),
    Column("depth", INTEGER, "Device nested depth"),
])
attributes(cacheable=True)
implementation("system/iokit_registry@genIOKitDeviceTree")


#darwin
table_name("iokit_registry")
description("The full IOKit registry without selecting a plane.")
schema([
    Column("name", TEXT, "Default name of the node"),
    Column("class", TEXT, "Best matching device class (most-specific category)"),
    Column("id", BIGINT, "IOKit internal registry ID"),
    Column("parent", BIGINT, "Parent registry ID"),
    Column("busy_state", INTEGER, "1 if the node is in a busy state else 0"),
    Column("retain_count", INTEGER, "The node reference count"),
    Column("depth", INTEGER, "Node nested depth"),
])
attributes(cacheable=True)
implementation("system/iokit_registry@genIOKitRegistry")


#darwin
table_name("kernel_extensions")
description("macOS's kernel extensions, both loaded and within the load search path.")
schema([
    Column("idx", INTEGER, "Extension load tag or index"),
    Column("refs", INTEGER, "Reference count"),
    Column("size", BIGINT, "Bytes of wired memory used by extension"),
    Column("name", TEXT, "Extension label"),
    Column("version", TEXT, "Extension version", collate="version"),
    Column("linked_against", TEXT,
      "Indexes of extensions this extension is linked against"),
    Column("path", TEXT, "Optional path to extension bundle"),
])
implementation("kextstat@genKernelExtensions")


#darwin
table_name("kernel_panics")
description("System kernel panic logs.")
schema([
    Column("path", TEXT, "Location of log file"),
    Column("time", TEXT, "Formatted time of the event"),
    Column("registers", TEXT, "A space delimited line of register:value pairs"),
    Column("frame_backtrace", TEXT, "Backtrace of the crashed module"),
    Column("module_backtrace", TEXT, "Modules appearing in the crashed module's backtrace"),
    Column("dependencies", TEXT, "Module dependencies existing in crashed module's backtrace"),
    Column("name", TEXT, "Process name corresponding to crashed thread"),
    Column("os_version", TEXT, "Version of the operating system"),
    Column("kernel_version", TEXT, "Version of the system kernel"),
    Column("system_model", TEXT, "Physical system model, for example 'MacBookPro12,1 (Mac-E43C1C25D4880AD6)'"),
    Column("uptime", BIGINT, "System uptime at kernel panic in nanoseconds"),
    Column("last_loaded", TEXT, "Last loaded module before panic"),
    Column("last_unloaded", TEXT, "Last unloaded module before panic"),
])
implementation("kernel_panics@genKernelPanics")


#darwin
table_name("keychain_acls")
description("Applications that have ACL entries in the keychain. NOTE: osquery limits frequent access to keychain files. This limit is controlled by keychain_access_interval flag.")
schema([
    Column("keychain_path", TEXT, "The path of the keychain"),
    Column("authorizations", TEXT, "A space delimited set of authorization attributes"),
    Column("path", TEXT, "The path of the authorized application"),
    Column("description", TEXT, "The description included with the ACL entry"),
    Column("label", TEXT, "An optional label tag that may be included with the keychain entry"),
])
attributes(cacheable=True)
implementation("keychain_acl@genKeychainACLApps")
examples([
  "select label, description, authorizations, path, count(path) as c from keychain_acls where label != '' and path != '' group by label having c > 1;",
])


#darwin
table_name("keychain_items")
description("Generic details about keychain items. NOTE: osquery limits frequent access to keychain files. This limit is controlled by keychain_access_interval flag.")
schema([
    Column("label", TEXT, "Generic item name"),
    Column("description", TEXT, "Optional item description"),
    Column("comment", TEXT, "Optional keychain comment"),
    Column("account", TEXT, "Optional item account"),
    Column("created", TEXT, "Date item was created"),
    Column("modified", TEXT, "Date of last modification"),
    Column("type", TEXT, "Keychain item type (class)"),
    Column("pk_hash", TEXT, "Hash of associated public key (SHA1 of subjectPublicKey, see RFC 8520 4.2.1.2)"),
    Column("path", TEXT, "Path to keychain containing item", additional=True, optimized=True),
])
implementation("keychain_items@genKeychainItems")


#darwin
table_name("launchd")
description("LaunchAgents and LaunchDaemons from default search paths.")
schema([
    Column("path", TEXT, "Path to daemon or agent plist", index=True),
    Column("name", TEXT, "File name of plist (used by launchd)"),
    Column("label", TEXT, "Daemon or agent service name"),
    Column("program", TEXT, "Path to target program"),
    Column("run_at_load", TEXT, "Should the program run on launch load"),
    Column("keep_alive", TEXT, "Should the process be restarted if killed"),
    Column("on_demand", TEXT, "Deprecated key, replaced by keep_alive"),
    Column("disabled", TEXT, "Skip loading this daemon or agent on boot"),
    Column("username", TEXT, "Run this daemon or agent as this username"),
    Column("groupname", TEXT, "Run this daemon or agent as this group"),
    Column("stdout_path", TEXT, "Pipe stdout to a target path"),
    Column("stderr_path", TEXT, "Pipe stderr to a target path"),
    Column("start_interval", TEXT, "Frequency to run in seconds"),
    Column("program_arguments", TEXT,
        "Command line arguments passed to program"),
    Column("watch_paths", TEXT,
        "Key that launches daemon or agent if path is modified"),
    Column("queue_directories", TEXT,
        "Similar to watch_paths but only with non-empty directories"),
    Column("inetd_compatibility", TEXT,
        "Run this daemon or agent as it was launched from inetd"),
    Column("start_on_mount", TEXT,
        "Run daemon or agent every time a filesystem is mounted"),
    Column("root_directory", TEXT,
        "Key used to specify a directory to chroot to before launch"),
    Column("working_directory", TEXT,
        "Key used to specify a directory to chdir to before launch"),
    Column("process_type", TEXT,
        "Key describes the intended purpose of the job"),
])
attributes(cacheable=True)
implementation("launchd@genLaunchd")
fuzz_paths([
    "/System/Library/LaunchDaemons",
])


#darwin
table_name("launchd_overrides")
description("Override keys, per user, for LaunchDaemons and Agents.")
schema([
    Column("label", TEXT, "Daemon or agent service name"),
    Column("key", TEXT, "Name of the override key"),
    Column("value", TEXT, "Overridden value"),
    Column("uid", BIGINT, "User ID applied to the override, 0 applies to all"),
    Column("path", TEXT, "Path to daemon or agent plist"),
])
attributes(cacheable=True)
implementation("launchd@genLaunchdOverrides")


#darwin
table_name("location_services")
description("Reports the status of the Location Services feature of the OS.")
schema([
    Column("enabled", INTEGER, "1 if Location Services are enabled, else 0"),
])
implementation("location_services@genLocationServices")


#darwin
table_name("managed_policies")
description("The managed configuration policies from AD, MDM, MCX, etc.")
schema([
    Column("domain", TEXT, "System or manager-chosen domain key", collate="nocase"),
    Column("uuid", TEXT, "Optional UUID assigned to policy set"),
    Column("name", TEXT, "Policy key name"),
    Column("value", TEXT, "Policy value"),
    Column("username", TEXT, "Policy applies only this user"),
    Column("manual", INTEGER, "1 if policy was loaded manually, otherwise 0"),
])
implementation("managed_policy@genManagedPolicies")
fuzz_paths([
    "/Library/Managed Preferences",
])


#darwin
table_name("mdfind")
description("Run searches against the spotlight database.")
schema([
    Column("path", TEXT, "Path of the file returned from spotlight"),
    Column("query", TEXT, "The query that was run to find the file", required=True, optimized=True),
])
implementation("mdfind@genMdfindResults")
fuzz_paths([])
examples([
	"select count(*) from mdfind where query = 'kMDItemTextContent == \"osquery\"';"
	"select * from mdfind where query = 'kMDItemDisplayName == \"rook.stl\"';",
	"select * from mdfind where query in ('kMDItemDisplayName == \"rook.stl\"', 'kMDItemDisplayName == \"video.mp4\"')"
])


#darwin
table_name("mdls")
description("Query file metadata in the Spotlight database.")
schema([
    Column("path", TEXT, "Path of the file", required=True, optimized=True),
    Column("key", TEXT, "Name of the metadata key"),
    Column("value", TEXT, "Value stored in the metadata key"),
    Column("valuetype", TEXT, "CoreFoundation type of data stored in value", hidden=True),
])
implementation("mdls@genMdlsResults")
fuzz_paths([])
examples([
	"select * from mdls where path = '/Users/testuser/Desktop/testfile';"
])


#darwin
table_name("nfs_shares")
description("NFS shares exported by the host.")
schema([
    Column("share", TEXT, "Filesystem path to the share"),
    Column("options", TEXT, "Options string set on the export share"),
    Column("readonly", INTEGER, "1 if the share is exported readonly else 0"),
])
implementation("nfs_shares@genNFSShares")
fuzz_paths([
    "/etc/exports",
])


#darwin
table_name("nvram")
description("Apple NVRAM variable listing.")
schema([
    Column("name", TEXT, "Variable name", additional=True, index=True, optimized=True),
    Column("type", TEXT, "Data type (CFData, CFString, etc)"),
    Column("value", TEXT, "Raw variable data"),
])
implementation("nvram@genNVRAM")


#darwin
table_name("package_bom")
description("macOS package bill of materials (BOM) file list.")
schema([
    Column("filepath", TEXT, "Package file or directory"),
    Column("uid", INTEGER, "Expected user of file or directory"),
    Column("gid", INTEGER, "Expected group of file or directory"),
    Column("mode", INTEGER, "Expected permissions"),
    Column("size", BIGINT, "Expected file size"),
    Column("modified_time", INTEGER, "Timestamp the file was installed"),
    Column("path", TEXT, "Path of package bom", required=True, optimized=True),
])
implementation("packages@genPackageBOM")
examples([
  "select * from package_bom where path = '/var/db/receipts/com.apple.pkg.MobileDevice.bom'"
])


#darwin
table_name("package_install_history")
description("macOS package install history.")
schema([
    Column("package_id", TEXT, "Label packageIdentifiers"),
    Column("time", INTEGER, "Label date as UNIX timestamp"),
    Column("name", TEXT, "Package display name"),
    Column("version", TEXT, "Package display version", collate="version"),
    Column("source", TEXT, "Install source: usually the installer process name"),
    Column("content_type", TEXT, "Package content_type (optional)"),
])
implementation("packages@genPackageInstallHistory")


#darwin
table_name("package_receipts", aliases=["packages"])
description("macOS package receipt details.")
schema([
    Column("package_id", TEXT, "Package domain identifier"),
    Column("package_filename", TEXT, "Filename of original .pkg file",
        index=True, hidden=True),
    Column("version", TEXT, "Installed package version", collate="version"),
    Column("location", TEXT, "Optional relative install path on volume"),
    Column("install_time", DOUBLE, "Timestamp of install time"),
    Column("installer_name", TEXT, "Name of installer process"),
    Column("path", TEXT, "Path of receipt plist", additional=True),
])
implementation("packages@genPackageReceipts")
examples([
    "SELECT * FROM package_receipts;"
])
fuzz_paths([
    "/private/var/db/receipts/",
    "/Library/Receipts/",
])


#darwin
table_name("password_policy")
description("OpenDirectory account policies for macOS including password content, authentication, and password change policies.")
schema([
    Column("uid", BIGINT, "User ID for the policy, -1 for policies that are global", index=True, optimized=True),
    Column("policy_identifier", TEXT, "Policy Identifier"),
    Column("policy_content", TEXT, "Policy content"),
    Column("policy_description", TEXT, "Policy description"),
    Column("policy_category", TEXT, "Policy category: passwordPolicyAuthentication, passwordPolicyPasswordChange, or passwordPolicyPasswordContent"),
    Column("policy_parameters", TEXT, "Policy parameters serialized as JSON"),
])
implementation("password_policy@genPasswordPolicy")
examples([
  "select * from password_policy",
  "select * from password_policy where policy_category = 'policyCategoryPasswordContent'",
])


#darwin
table_name("plist")
description("Read and parse a plist file.")
schema([
    Column("key", TEXT, "Preference top-level key"),
    Column("subkey", TEXT, "Intermediate key path, includes lists/dicts"),
    Column("value", TEXT, "String value of most CF types"),
    Column("path", TEXT, "(required) read preferences from a plist", required=True, optimized=True),
])
implementation("system/darwin/preferences@genOSXPlist")
examples([
  "select * from plist where path = '/Library/Preferences/loginwindow.plist'"
])


#darwin
table_name("power_sensors")
description("Machine power (currents, voltages, wattages, etc) sensors.")
schema([
    Column("key", TEXT, "The SMC key on macOS", index=True, optimized=True),
    Column("category", TEXT, "The sensor category: currents, voltage, wattage"),
    Column("name", TEXT, "Name of power source"),
    Column("value", TEXT, "Power in Watts"),
    ForeignKey(column="key", table="smc_keys"),
])
examples([
  "select * from power_sensors where category = 'voltage'"
])
implementation("smc_keys@genPowerSensors")


#darwin
table_name("preferences")
description("macOS defaults and managed preferences.")
schema([
    Column("domain", TEXT, "Application ID usually in com.name.product format", index=True, optimized=True),
    Column("key", TEXT, "Preference top-level key", index=True),
    Column("subkey", TEXT, "Intemediate key path, includes lists/dicts"),
    Column("value", TEXT, "String value of most CF types"),
    Column("forced", INTEGER, "1 if the value is forced/managed, else 0"),
    Column("username", TEXT, "(optional) read preferences for a specific user",
      additional=True),
    Column("host", TEXT,
      "'current' or 'any' host, where 'current' takes precedence"),
])
attributes(user_data=True)
implementation("system/darwin/preferences@genOSXDefaultPreferences")
examples([
    "select * from preferences where domain = 'loginwindow'",
    "select preferences.* from users join preferences using (username)",
])
fuzz_paths([
    "/Users",
])


#darwin
table_name("quicklook_cache")
description("Files and thumbnails within macOS's Quicklook Cache.")
schema([
    Column("path", TEXT, "Path of file"),
    Column("rowid", INTEGER, "Quicklook file rowid key"),
    Column("fs_id", TEXT, "Quicklook file fs_id key"),
    Column("volume_id", INTEGER, "Parsed volume ID from fs_id"),
    Column("inode", INTEGER, "Parsed file ID (inode) from fs_id"),
    Column("mtime", INTEGER, "Parsed version date field"),
    Column("size", BIGINT, "Parsed version size field"),
    Column("label", TEXT, "Parsed version 'gen' field"),
    Column("last_hit_date", INTEGER,
      "Apple date format for last thumbnail cache hit"),
    Column("hit_count", TEXT, "Number of cache hits on thumbnail"),
    Column("icon_mode", BIGINT, "Thumbnail icon mode"),
    Column("cache_path", TEXT, "Path to cache data"),
])
attributes(cacheable=True)
implementation("quicklook_cache@genQuicklookCache")
fuzz_paths([
    "/private/var/folders/",
])


#darwin
table_name("running_apps")

description("macOS applications currently running on the host system.")

schema([
    Column("pid", INTEGER, "The pid of the application", index=True),
    Column("bundle_identifier", TEXT, "The bundle identifier of the application"),
    Column("is_active", INTEGER, "(DEPRECATED)", hidden=True)
])

implementation("running_apps@genRunningApps")


#darwin
table_name("safari_extensions")
description("Safari browser extension details for all users. This table requires Full Disk Access (FDA) permission.")
schema([
    Column("uid", BIGINT, "The local user that owns the extension", index=True, optimized=True),
    Column("name", TEXT, "Extension display name"),
    Column("identifier", TEXT, "Extension identifier"),
    Column("version", TEXT, "Extension long version", collate="version"),
    Column("sdk", TEXT, "Bundle SDK used to compile extension", collate="version"),
    Column("description", TEXT, "Optional extension description text"),
    Column("path", TEXT, "Path to the Info.plist describing the extension"),
    Column("bundle_version", TEXT, "The version of the build that identifies an iteration of the bundle"),
    Column("copyright", TEXT, "A human-readable copyright notice for the bundle"),
    ForeignKey(column="uid", table="users")
])
attributes(user_data=True)
implementation("applications/browser_plugins@genSafariExtensions")
examples([
  "select * from safari_extensions where uid=501",
  "select count(*) from users JOIN safari_extensions using (uid)",
])
fuzz_paths([
    "/Users",
])


#darwin
table_name("sandboxes")
description("macOS application sandboxes container details.")
schema([
    Column("label", TEXT, "UTI-format bundle or label ID"),
    Column("user", TEXT, "Sandbox owner"),
    Column("enabled", INTEGER, "Application sandboxings enabled on container"),
    Column("build_id", TEXT, "Sandbox-specific identifier"),
    Column("bundle_path", TEXT, "Application bundle used by the sandbox"),
    Column("path", TEXT, "Path to sandbox container directory"),
])
attributes(cacheable=True)
implementation("sandboxes@genSandboxContainers")
fuzz_paths([
    "/Users",
])


#darwin
table_name("screenlock")
description("macOS screenlock status. Note: only fetches results for osquery's current logged-in user context. The user must also have recently logged in.")
schema([
    Column("enabled", INTEGER, "1 If a password is required after sleep or the screensaver begins; else 0"),
    Column("grace_period", INTEGER, "The amount of time in seconds the screen must be asleep or the screensaver on before a password is required on-wake. 0 = immediately; -1 = no password is required on-wake"),
])
implementation("screenlock@genScreenlock")


#darwin
table_name("shared_folders")
description("Folders available to others via SMB or AFP.")
schema([
    Column("name", TEXT, "The shared name of the folder as it appears to other users"),
    Column("path", TEXT, "Absolute path of shared folder on the local system")
])
implementation("shared_folders@genSharedFolders")


#darwin
table_name("sharing_preferences", aliases=["alf_services"])
description("macOS Sharing preferences.")
schema([
Column("screen_sharing", INTEGER, "1 If screen sharing is enabled else 0"),
Column("file_sharing", INTEGER, "1 If file sharing is enabled else 0"),
Column("printer_sharing", INTEGER, "1 If printer sharing is enabled else 0"),
Column("remote_login", INTEGER, "1 If remote login is enabled else 0"),
Column("remote_management", INTEGER, "1 If remote management is enabled else 0"),
Column("remote_apple_events", INTEGER, "1 If remote apple events are enabled else 0"),
Column("internet_sharing", INTEGER, "1 If internet sharing is enabled else 0"),
Column("bluetooth_sharing", INTEGER, "1 If bluetooth sharing is enabled for any user else 0"),
Column("disc_sharing", INTEGER, "1 If CD or DVD sharing is enabled else 0"),
Column("content_caching", INTEGER, "1 If content caching is enabled else 0"),
])
implementation("sharing_preferences@genSharingPreferences")


#darwin
table_name("signature")
description("File (executable, bundle, installer, disk) code signing status.")
schema([
    Column("path", TEXT, "Must provide a path or directory", index=True, optimized=True, required=True),
    Column("hash_resources", INTEGER,
       "Set to 1 to also hash resources, or 0 otherwise. Default is 1",
       additional=True),
    Column("hash_executable", INTEGER,
       "Set to 1 to also hash the executable, or 0 otherwise. Default is 1",
       additional=True),
    Column("arch", TEXT, "If applicable, the arch of the signed code"),
    Column("signed", INTEGER, "1 If the file is signed else 0"),
    Column("identifier", TEXT, "The signing identifier sealed into the signature"),
    Column("cdhash", TEXT, "Hash of the application Code Directory"),
    Column("team_identifier", TEXT, "The team signing identifier sealed into the signature"),
    Column("authority", TEXT, "Certificate Common Name"),
    Column("entitlements", TEXT, "JSON representation of the code signing entitlements"),
])
implementation("signature@genSignature")
examples([
  "SELECT * FROM signature WHERE path = '/bin/ls'",
  "SELECT * FROM signature WHERE path = '/Applications/Xcode.app' AND hash_resources=0",
  "SELECT * FROM (SELECT path, MIN(signed) AS all_signed, MIN(CASE WHEN authority = 'Software Signing' AND signed = 1 THEN 1 ELSE 0 END) AS all_signed_by_apple FROM signature WHERE path LIKE '/bin/%' GROUP BY path);"
])


#darwin
table_name("sip_config")
description("Apple's System Integrity Protection (rootless) status.")
schema([
    Column("config_flag", TEXT, "The System Integrity Protection config flag"),
    Column("enabled", INTEGER, "1 if this configuration is enabled, otherwise 0"),
    Column("enabled_nvram", INTEGER, "1 if this configuration is enabled, otherwise 0"),
])
implementation("sip_config@genSIPConfig")
examples([
  "select * from sip_config",
])


#darwin
table_name("smc_keys")
description("Apple's system management controller keys.")
schema([
    Column("key", TEXT, "4-character key", additional=True, index=True, optimized=True),
    Column("type", TEXT, "SMC-reported type literal type"),
    Column("size", INTEGER, "Reported size of data in bytes"),
    Column("value", TEXT, "A type-encoded representation of the key value"),
    Column("hidden", INTEGER, "1 if this key is normally hidden, otherwise 0"),
])
implementation("smc_keys@genSMCKeys")
examples([
  "select * from smc_keys where key = 'MOJO'",
])


#darwin
table_name("system_extensions")
description("macOS (>= 10.15) system extension table.")
schema([
    Column("path", TEXT, "Original path of system extension"),
    Column("UUID", TEXT, "Extension unique id"),
    Column("state", TEXT, "System extension state"),
    Column("identifier", TEXT, "Identifier name", collate="nocase"),
    Column("version", TEXT, "System extension version", collate="version"),
    Column("category", TEXT, "System extension category"),
    Column("bundle_path", TEXT, "System extension bundle path"),
    Column("team", TEXT, "Signing team ID"),
    Column("mdm_managed", INTEGER, "1 if managed by MDM system extension payload configuration, 0 otherwise")
])
implementation("system_extensions@genSystemExtensions")
examples([
  "select * from system_extensions",
])


#darwin
table_name("system_profiler")
description("Query system_profiler data types and return the full result as JSON. Returns only the data types specified in the constraints. See available data types with `system_profiler -listDataTypes`.")
schema([
    Column("data_type", TEXT, "The system profiler data type (e.g., SPHardwareDataType)", index=True, required=True),
    Column("value", TEXT, "A JSON representation of the full result dictionary for the data type"),
])
implementation("system_profiler@genSystemProfilerResults")
examples([
    "SELECT * FROM system_profiler WHERE data_type = 'SPUSBDataType';",
    "SELECT JSON_EXTRACT(value, '$[0].platform_UUID') AS hardware_uuid FROM system_profiler WHERE data_type = 'SPHardwareDataType';",
    "SELECT each.value->>'_name' AS name, each.value->>'coreaudio_device_manufacturer' AS manufacturer FROM system_profiler sp, JSON_EACH(sp.value->'[0]._items') each WHERE data_type = 'SPAudioDataType';"
]) 


#darwin
table_name("temperature_sensors")
description("Machine's temperature sensors.")
schema([
    Column("key", TEXT, "The SMC key on macOS", index=True, optimized=True),
    Column("name", TEXT, "Name of temperature source"),
    Column("celsius", DOUBLE, "Temperature in Celsius"),
    Column("fahrenheit", DOUBLE, "Temperature in Fahrenheit"),
    ForeignKey(column="key", table="smc_keys"),
])
implementation("smc_keys@genTemperatureSensors")


#darwin
table_name("time_machine_backups")
description("Backups to drives using TimeMachine. This table requires Full Disk Access (FDA) permission.")
schema([
    Column("destination_id", TEXT, "Time Machine destination ID"),
    Column("backup_date", INTEGER, "Backup Date"),
])
implementation("time_machine@genTimeMachineBackups")
examples([
  "select alias, backup_date, td.destination_id, root_volume_uuid, encryption from time_machine_backups tb join time_machine_destinations td on (td.destination_id=tb.destination_id);",
])
fuzz_paths([
    "/Library/Preferences/com.apple.TimeMachine.plist",
])


#darwin
table_name("time_machine_destinations")
description("Locations backed up to using Time Machine. This table requires Full Disk Access (FDA) permission.")
schema([
    Column("alias", TEXT, "Human readable name of drive"),
    Column("destination_id", TEXT, "Time Machine destination ID"),
    Column("consistency_scan_date", INTEGER, "Consistency scan date"),
    Column("root_volume_uuid", TEXT, "Root UUID of backup volume"),
    Column("bytes_available", INTEGER, "Bytes available on volume"),
    Column("bytes_used", INTEGER, "Bytes used on volume"),
    Column("encryption", TEXT, "Last known encrypted state"),
])
implementation("time_machine@genTimeMachineDestinations")
examples([
  "select alias, backup_date, td.destination_id, root_volume_uuid, encryption from time_machine_backups tb join time_machine_destinations td on (td.destination_id=tb.destination_id);",
])
fuzz_paths([
    "/Library/Preferences/com.apple.TimeMachine.plist",
])


#darwin
table_name("unified_log")
description("Queries the OSLog framework for entries in the system log. "
            "The maximum number of rows returned is limited for performance issues. "
            "Use timestamp > or >= constraints to optimize query performance. "
            "This table introduces a new idiom for extracting sequential data in batches using multiple queries, ordered by timestamp. "
            "To trigger it, the user should include the condition \"timestamp > -1\", and the table will handle pagination. "
            "Note that the saved pagination counter is incremented globally across all queries and table invocations within a query. "
            "To avoid multiple table invocations within a query, use only AND and = constraints in WHERE clause."
            )

schema([
  Column("timestamp", BIGINT, "unix timestamp associated with the entry", additional=True),
  Column("timestamp_double", TEXT, "floating point timestamp associated with the entry"),
  Column("storage", INTEGER, "the storage category for the entry", additional=True),
  Column("message", TEXT, "composed message", additional=True),
  Column("activity", BIGINT, "the activity ID associate with the entry", additional=True),
  Column("process", TEXT, "the name of the process that made the entry", additional=True),
  Column("pid", BIGINT, "the pid of the process that made the entry", additional=True),
  Column("sender", TEXT, "the name of the binary image that made the entry", additional=True),
  Column("tid", BIGINT, "the tid of the thread that made the entry", additional=True),
  Column("category", TEXT, "the category of the os_log_t used", additional=True),
  Column("subsystem", TEXT, "the subsystem of the os_log_t used", additional=True),
  Column("level", TEXT, "the severity level of the entry"),
  Column("max_rows", INTEGER, "the max number of rows returned (defaults to 100)", additional=True, hidden=True),
  Column("predicate", TEXT, "predicate to search (see `log help predicates`), note that this is merged into the predicate created from the column constraints", additional=True, hidden=True)
])
examples([
  "select * from unified_log",
  "select * from unified_log where process = 'osqueryd'",
  "select * from unified_log where predicate = 'process = \"osqueryd\" OR process = \"Santa\"'",
  "select * from unified_log where predicate = 'processImagePath = \"/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd\"'",
  "select * from unified_log where max_rows = 1234",
  "select * from unified_log where timestamp > -1",
  "select * from unified_log where timestamp > -1 and max_rows = 500",
  "select * from unified_log where timestamp > -1 and timestamp > (select unix_time - 86400 from time)",
])
implementation("unified_log@genUnifiedLog")


#darwin
table_name("user_interaction_events")
description("Track user interaction events from macOS' event tapping framework.")
schema([
    Column("time", BIGINT, "Time", additional=True)
])
attributes(event_subscriber=True)
implementation("events/darwin/user_interaction_events@user_interaction_events::genTable")


#darwin
table_name("virtual_memory_info")
description("Darwin Virtual Memory statistics.")
schema([
    Column("free", BIGINT, "Total number of free pages."),
    Column("active", BIGINT, "Total number of active pages."),
    Column("inactive", BIGINT, "Total number of inactive pages."),
    Column("speculative", BIGINT, "Total number of speculative pages."),
    Column("throttled", BIGINT, "Total number of throttled pages."),
    Column("wired", BIGINT, "Total number of wired down pages."),
    Column("purgeable", BIGINT, "Total number of purgeable pages."),
    Column("faults", BIGINT, "Total number of calls to vm_faults."),
    Column("copy", BIGINT, "Total number of copy-on-write pages."),
    Column("zero_fill", BIGINT, "Total number of zero filled pages."),
    Column("reactivated", BIGINT, "Total number of reactivated pages."),
    Column("purged", BIGINT, "Total number of purged pages."),
    Column("file_backed", BIGINT, "Total number of file backed pages."),
    Column("anonymous", BIGINT, "Total number of anonymous pages."),
    Column("uncompressed", BIGINT, "Total number of uncompressed pages."),
    Column("compressor", BIGINT, "The number of pages used to store compressed VM pages."),
    Column("decompressed", BIGINT, "The total number of pages that have been decompressed by the VM compressor."),
    Column("compressed", BIGINT, "The total number of pages that have been compressed by the VM compressor."),
    Column("page_ins", BIGINT, "The total number of requests for pages from a pager."),
    Column("page_outs", BIGINT, "Total number of pages paged out."),
    Column("swap_ins", BIGINT, "The total number of compressed pages that have been swapped out to disk."),
    Column("swap_outs", BIGINT, "The total number of compressed pages that have been swapped back in from disk."),
])
implementation("system/darwin/virtual_memory_info@genVirtualMemoryInfo")
examples([
  "select * from virtual_memory_info;",
])


#darwin
table_name("wifi_networks")
description("macOS known/remembered Wi-Fi networks list.")
schema([
    Column("ssid", TEXT, "SSID octets of the network"),
    Column("network_name", TEXT, "Name of the network"),
    Column("security_type", TEXT, "Type of security on this network"),
    Column("last_connected", INTEGER, "Last time this network was connected to as a unix_time (max of last_connected_automatic and last_connected_manual, if available)", hidden=True),
    Column("last_connected_automatic", INTEGER, "Last time this network was automatically connected to by the system as a unix_time"),
    Column("last_connected_manual", INTEGER, "Last time this network was manually connected to by the user as a unix_time"),
    Column("passpoint", INTEGER, "1 if Passpoint is supported, 0 otherwise", hidden=True),
    Column("possibly_hidden", INTEGER, "1 if network is possibly a hidden network, 0 otherwise"),
    Column("roaming", INTEGER, "1 if roaming is supported, 0 otherwise", hidden=True),
    Column("roaming_profile", TEXT, "Describe the roaming profile, usually one of Single, Dual  or Multi"),
    Column("auto_login", INTEGER, "1 if auto login is enabled, 0 otherwise", hidden=True),
    Column("temporarily_disabled", INTEGER, "1 if this network is temporarily disabled, 0 otherwise"),
    Column("disabled", INTEGER, "1 if this network is disabled, 0 otherwise", hidden=True),
    Column("add_reason", TEXT, "Shows why this network was added, via menubar or command line or something else "),
    Column("added_at", INTEGER, "Time this network was added as a unix_time"),
    Column("captive_portal", INTEGER, "1 if this network has a captive portal, 0 otherwise"),
    Column("captive_login_date", INTEGER, "Time this network logged in to a captive portal as unix_time"),
    Column("was_captive_network", INTEGER, "1 if this network was previously a captive network, 0 otherwise"),
    Column("auto_join", INTEGER, "1 if this network set to join automatically, 0 otherwise"),
    Column("personal_hotspot", INTEGER, "1 if this network is a personal hotspot, 0 otherwise"),
])
attributes(cacheable=True)
implementation("networking/wifi@genKnownWifiNetworks")
fuzz_paths([
    "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
    "/Library/Preferences/com.apple.wifi.known-networks.plist"
])


#darwin
table_name("wifi_survey")
description("Scan for nearby WiFi networks.")
schema([
    Column("interface", TEXT, "Name of the interface"),
    Column("ssid", TEXT, "SSID octets of the network"),
    Column("bssid", TEXT, "The current basic service set identifier"),
    Column("network_name", TEXT, "Name of the network"),
    Column("country_code", TEXT, "The country code (ISO/IEC 3166-1:1997) for the network"),
    Column("rssi", INTEGER, "The current received signal strength indication (dbm)"),
    Column("noise", INTEGER, "The current noise measurement (dBm)"),
    Column("channel", INTEGER, "Channel number"),
    Column("channel_width", INTEGER, "Channel width"),
    Column("channel_band", INTEGER, "Channel band"),
])
attributes(cacheable=False)
implementation("networking/wifi_survey@genWifiScan")
fuzz_paths([])


#darwin
table_name("wifi_status")
description("macOS current WiFi status.")
schema([
    Column("interface", TEXT, "Name of the interface"),
    Column("ssid", TEXT, "SSID octets of the network"),
    Column("bssid", TEXT, "The current basic service set identifier"),
    Column("network_name", TEXT, "Name of the network"),
    Column("country_code", TEXT, "The country code (ISO/IEC 3166-1:1997) for the network"),
    Column("security_type", TEXT, "Type of security on this network"),
    Column("rssi", INTEGER, "The current received signal strength indication (dbm)"),
    Column("noise", INTEGER, "The current noise measurement (dBm)"),
    Column("channel", INTEGER, "Channel number"),
    Column("channel_width", INTEGER, "Channel width"),
    Column("channel_band", INTEGER, "Channel band"),
    Column("transmit_rate", TEXT, "The current transmit rate"),
    Column("mode", TEXT, "The current operating mode for the Wi-Fi interface"),
])
attributes(cacheable=True)
implementation("networking/wifi_status@genWifiStatus")
fuzz_paths([])


#darwin
table_name("xprotect_entries")
description("Database of the machine's XProtect signatures.")
schema([
    Column("name", TEXT, "Description of XProtected malware"),
    Column("launch_type", TEXT, "Launch services content type"),
    Column("identity", TEXT, "XProtect identity (SHA1) of content"),
    Column("filename", TEXT, "Use this file name to match"),
    Column("filetype", TEXT, "Use this file type to match"),
    Column("optional", INTEGER, "Match any of the identities/patterns for this XProtect name"),
    Column("uses_pattern", INTEGER, "Uses a match pattern instead of identity"),
])
attributes(cacheable=True)
implementation("xprotect@genXProtectEntries")


#darwin
table_name("xprotect_meta")
description("Database of the machine's XProtect browser-related signatures.")
schema([
    Column("identifier", TEXT, "Browser plugin or extension identifier"),
    Column("type", TEXT, "Either plugin or extension"),
    Column("developer_id", TEXT, "Developer identity (SHA1) of extension"),
    Column("min_version", TEXT, "The minimum allowed plugin version.", collate="version"),
])
attributes(cacheable=True)
implementation("xprotect@genXProtectMeta")


#darwin
table_name("xprotect_reports")
description("Database of XProtect matches (if user generated/sent an XProtect report).")
schema([
    Column("name", TEXT, "Description of XProtected malware"),
    Column("user_action", TEXT, "Action taken by user after prompted"),
    Column("time", TEXT, "Quarantine alert time"),
])
implementation("xprotect@genXProtectReports")
fuzz_paths([
    "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/",
    "/Library/Logs/DiagnosticReports",
])


#cross-platform
table_name("ec2_instance_metadata")
description("EC2 instance metadata.")
schema([
    Column("instance_id", TEXT, "EC2 instance ID"),
    Column("instance_type", TEXT, "EC2 instance type"),
    Column("architecture", TEXT, "Hardware architecture of this EC2 instance"),
    Column("region", TEXT, "AWS region in which this instance launched"),
    Column("availability_zone", TEXT, "Availability zone in which this instance launched"),
    Column("local_hostname", TEXT, "Private IPv4 DNS hostname of the first interface of this instance"),
    Column("local_ipv4", TEXT, "Private IPv4 address of the first interface of this instance"),
    Column("mac", TEXT, "MAC address for the first network interface of this EC2 instance"),
    Column("security_groups", TEXT, "Comma separated list of security group names"),
    Column("iam_arn", TEXT, "If there is an IAM role associated with the instance, contains instance profile ARN"),
    Column("ami_id", TEXT, "AMI ID used to launch this EC2 instance"),
    Column("reservation_id", TEXT, "ID of the reservation"),
    Column("account_id", TEXT, "AWS account ID which owns this EC2 instance"),
    Column("ssh_public_key", TEXT, "SSH public key. Only available if supplied at instance launch time")
])
attributes(cacheable=True)
implementation("cloud/ec2_metadata@genEc2Metadata")
examples([
    "select * from ec2_instance_metadata"
])


#cross-platform
table_name("ec2_instance_tags")
description("EC2 instance tag key value pairs.")
schema([
    Column("instance_id", TEXT, "EC2 instance ID"),
    Column("key", TEXT, "Tag key"),
    Column("value", TEXT, "Tag value")
])
attributes(cacheable=True)
implementation("cloud/ec2_instance_tags@genEc2InstanceTags")
examples([
  "select * from ec2_instance_tags"
])


#cross-platform
table_name("etc_hosts", aliases=["hosts"])
description("Line-parsed /etc/hosts.")
schema([
    Column("address", TEXT, "IP address mapping"),
    Column("hostnames", TEXT, "Raw hosts mapping"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
attributes(cacheable=True)
implementation("etc_hosts@genEtcHosts")


#cross-platform
table_name("etc_protocols")
description("Line-parsed /etc/protocols.")
schema([
    Column("name", TEXT, "Protocol name"),
    Column("number", INTEGER, "Protocol number"),
    Column("alias", TEXT, "Protocol alias"),
    Column("comment", TEXT, "Comment with protocol description"),
])
attributes(cacheable=True)
implementation("etc_protocols@genEtcProtocols")
fuzz_paths([
    "/etc/protocols",
])


#cross-platform
table_name("etc_services")
description("Line-parsed /etc/services.")
schema([
    Column("name", TEXT, "Service name"),
    Column("port", INTEGER, "Service port number"),
    Column("protocol", TEXT, "Transport protocol (TCP/UDP)"),
    Column("aliases", TEXT, "Optional space separated list of other names for a service"),
    Column("comment", TEXT, "Optional comment for a service."),
])
attributes(cacheable=True)
implementation("etc_services@genEtcServices")
fuzz_paths([
    "/etc/services",
])


#cross-platform
# This .table file is called a "spec" and is written in Python
# This syntax (several definitions) is defined in /tools/codegen/gentable/py.
table_name("example")

# Provide a short "one line" description, please use punctuation!
description("This is an example table spec.")

# Define your schema, which accepts a list of Column instances at minimum.
# You may also describe foreign keys and "action" columns.
schema([
    # Declare the name, type, and documentation description for each column.
    # The supported types are INTEGER, BIGINT, TEXT, DATE, and DATETIME.
    Column("name", TEXT, "Description for name column"),
    Column("points", INTEGER, "This is a signed SQLite int column"),
    Column("size", BIGINT, "This is a signed SQLite bigint column"),

    # More complex tables include columns denoted as "required".
    # A required column MUST be present in a query predicate (WHERE clause).
    Column("action", TEXT, "Action performed in generation", required=True),

    # Tables may optimize there selection using "index" columns.
    # The optimization is undefined, but this is a hint to table users that
    # JOINing on this column will improve performance.
    Column("id", INTEGER, "An index of some sort", index=True),

    # Some tables operate using default configurations or OS settings.
    # macOS has default paths for .app executions, but .apps exist otherwise.
    # Tables may generate additional or different data when using some columns.
    # Set the "additional" argument if searching a non-default path.
    Column("path", TEXT, "Path of example", additional=True),
    # When paths are involved they are usually both additional and an index.
])

# Use the "@gen{TableName}" to communicate the C++ symbol name.
# Event subscriber tables and other more-complex implementations may use
# class-static methods for generation; they use "@ClassName::genTable" syntax.
implementation("@genExample")

# Provide some example queries that stress table use.
# If using actions or indexing, it will be best to include those predicates.
examples([
  "select * from example where id = 1",
  "select name from example where action = 'new'",

  # Examples may be used in documentation and in stress/fuzz testing.
  # Including example JOINs on indexes is preferred.
  "select e.* from example e, example_environments ee where e.id = ee.id"
])

# Attributes provide help to documentation/API generation tools.
# If an attribute is false, or no attributes apply, do no include 'attributes'.
attributes(
  # Set event_subscriber if this table is generated using an EventSubscriber.
  event_subscriber=False,
  # Set utility if this table should be built into the osquery-SDK (core).
  # Utility tables are mostly reserved for osquery meta-information.
  utility=False,
)


#cross-platform
table_name("firefox_addons")
description("Firefox browser extensions, webapps, and addons.")
schema([
    Column("uid", BIGINT, "The local user that owns the addon", additional=True, optimized=True),
    Column("name", TEXT, "Addon display name"),
    Column("identifier", TEXT, "Addon identifier", index=True),
    Column("creator", TEXT, "Addon-supported creator string"),
    Column("type", TEXT, "Extension, addon, webapp"),
    Column("version", TEXT, "Addon-supplied version string", collate="version"),
    Column("description", TEXT, "Addon-supplied description string"),
    Column("source_url", TEXT, "URL that installed the addon"),
    Column("visible", INTEGER, "1 If the addon is shown in browser else 0"),
    Column("active", INTEGER, "1 If the addon is active else 0"),
    Column("disabled", INTEGER,
      "1 If the addon is application-disabled else 0"),
    Column("autoupdate", INTEGER,
      "1 If the addon applies background updates else 0"),
    Column("location", TEXT, "Global, profile location"),
    Column("path", TEXT, "Path to plugin bundle"),
    ForeignKey(column="uid", table="users"),
])
attributes(user_data=True)
implementation("applications/browser_firefox@genFirefoxAddons")
examples([
    "SELECT * FROM users CROSS JOIN firefox_addons USING (uid)",
])
fuzz_paths([
    "/Library/Application Support/Firefox/Profiles/",
    "/Users",
])


#cross-platform
table_name("groups")
description("Local system groups.")
schema([
    Column("gid", BIGINT, "Unsigned int64 group ID", index=True),
    Column("gid_signed", BIGINT, "A signed int64 version of gid"),
    Column("groupname", TEXT, "Canonical local group name"),
])
extended_schema(WINDOWS, [
    Column("group_sid", TEXT, "Unique group ID", index=True),
    Column("comment", TEXT, "Remarks or comments associated with the group"),
])

extended_schema(DARWIN, [
    Column("is_hidden", INTEGER, "IsHidden attribute set in OpenDirectory"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
implementation("groups@genGroups")
examples([
  "select * from groups where gid = 0",
  # Group/user_groups is not JOIN optimized
  #"select g.groupname, ug.uid from groups g, user_groups ug where g.gid = ug.gid",
  # The relative group ID, or RID, is used by osquery as the "gid"
  # For Windows, "gid" and "gid_signed" will always be the same.
])


#cross-platform
table_name("hash")
description("Filesystem hash data.")
schema([
    Column("path", TEXT, "Must provide a path or directory", index=True, optimized=True, required=True),
    Column("directory", TEXT, "Must provide a path or directory", required=True, optimized=True),
    Column("md5", TEXT, "MD5 hash of provided filesystem data"),
    Column("sha1", TEXT, "SHA1 hash of provided filesystem data"),
    Column("sha256", TEXT, "SHA256 hash of provided filesystem data"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
    Column("mount_namespace_id", TEXT, "Mount namespace id", hidden=True),
])
implementation("hash@genHash")
examples([
  "select * from hash where path = '/etc/passwd'",
  "select * from hash where directory = '/etc/'",
])


#cross-platform
table_name("interface_addresses")
description("Network interfaces and relevant metadata.")
schema([
    Column("interface", TEXT, "Interface name"),
    Column("address", TEXT, "Specific address for interface"),
    Column("mask", TEXT, "Interface netmask"),
    Column("broadcast", TEXT, "Broadcast address for the interface"),
    Column("point_to_point", TEXT, "PtP address for the interface"),
    Column("type", TEXT, "Type of address. One of dhcp, manual, auto, other, unknown")
])
extended_schema(WINDOWS, [
    Column("friendly_name", TEXT, "The friendly display name of the interface."),
])
attributes(cacheable=True)
implementation("interfaces@genInterfaceAddresses")


#cross-platform
table_name("interface_details")
description("Detailed information and stats of network interfaces.")
schema([
    Column("interface", TEXT, "Interface name"),
    Column("mac", TEXT, "MAC of interface (optional)"),
    Column("type", INTEGER, "Interface type (includes virtual)"),
    Column("mtu", INTEGER, "Network MTU"),
    Column("metric", INTEGER, "Metric based on the speed of the interface"),
    Column("flags", INTEGER, "Flags (netdevice) for the device"),
    Column("ipackets", BIGINT, "Input packets"),
    Column("opackets", BIGINT, "Output packets"),
    Column("ibytes", BIGINT, "Input bytes"),
    Column("obytes", BIGINT, "Output bytes"),
    Column("ierrors", BIGINT, "Input errors"),
    Column("oerrors", BIGINT, "Output errors"),
    Column("idrops", BIGINT, "Input drops"),
    Column("odrops", BIGINT, "Output drops"),
    Column("collisions", BIGINT, "Packet Collisions detected"),
    Column("last_change", BIGINT, "Time of last device modification (optional)"),
])

extended_schema(POSIX, [
  Column("link_speed", BIGINT, "Interface speed in Mb/s"),
])

extended_schema(LINUX, [
  Column("pci_slot", TEXT, "PCI slot number"),
])

extended_schema(WINDOWS, [
    Column("friendly_name", TEXT, "The friendly display name of the interface."),
    Column("description", TEXT, "Short description of the object a one-line string."),
    Column("manufacturer", TEXT, "Name of the network adapter's manufacturer."),
    Column("connection_id", TEXT, "Name of the network connection as it appears in the Network Connections Control Panel program."),
    Column("connection_status", TEXT, "State of the network adapter connection to the network."),
    Column("enabled", INTEGER, "Indicates whether the adapter is enabled or not."),
    Column("physical_adapter", INTEGER, "Indicates whether the adapter is a physical or a logical adapter."),
    Column("speed", INTEGER, "Estimate of the current bandwidth in bits per second."),
    Column("service", TEXT, "The name of the service the network adapter uses."),
    Column("dhcp_enabled", INTEGER, "If TRUE, the dynamic host configuration protocol (DHCP) server automatically assigns an IP address to the computer system when establishing a network connection."),
    Column("dhcp_lease_expires", TEXT, "Expiration date and time for a leased IP address that was assigned to the computer by the dynamic host configuration protocol (DHCP) server."),
    Column("dhcp_lease_obtained", TEXT, "Date and time the lease was obtained for the IP address assigned to the computer by the dynamic host configuration protocol (DHCP) server."),
    Column("dhcp_server", TEXT, "IP address of the dynamic host configuration protocol (DHCP) server."),
    Column("dns_domain", TEXT, "Organization name followed by a period and an extension that indicates the type of organization, such as 'microsoft.com'."),
    Column("dns_domain_suffix_search_order", TEXT, "Array of DNS domain suffixes to be appended to the end of host names during name resolution."),
    Column("dns_host_name", TEXT, "Host name used to identify the local computer for authentication by some utilities."),
    Column("dns_server_search_order", TEXT, "Array of server IP addresses to be used in querying for DNS servers."),
])
attributes(cacheable=True)
implementation("interfaces@genInterfaceDetails")
examples([
    "select interface, mac, type, idrops as input_drops from interface_details;",
    "select interface, mac, type, flags, (1<<8) as promisc_flag from interface_details where (flags & promisc_flag) > 0;",
    "select interface, mac, type, flags, (1<<3) as loopback_flag from interface_details where (flags & loopback_flag) > 0;",
])


#cross-platform
table_name("jetbrains_plugins")
description("JetBrains IDEs plugins.")
schema([
    Column("product_type", TEXT, "The product type (Valid values: CLion, DataGrip, GoLand, IntelliJIdea, IntelliJIdeaCommunityEdition, PhpStorm, PyCharm, PyCharmCommunityEdition, ReSharper, Rider, RubyMine, RustRover, WebStorm)"),
    Column("uid", BIGINT, "The local user that owns the plugin", index=True),
    Column("name", TEXT, "Name of the plugin (Title Case)"),
    Column("version", TEXT, "Version of the plugin"),
    Column("vendor", TEXT, "The vendor name or organization id that authored the plugin"),
    Column("path", TEXT, "The path on the filesystem for the plugin. This may be a folder or a jar filename"),
])
attributes(user_data=True)
implementation("applications/jetbrains_plugins@genJetBrainsPlugins")
examples([
    "select * from users cross join jetbrains_plugins using (uid)"
])
fuzz_paths([
    "/Library/Application Support/JetBrains",
    "%APPDATA%\\JetBrains\\",
    "/.local/share/JetBrains/"
])


#cross-platform
table_name("kernel_info")
description("Basic active kernel information.")
schema([
  Column("version", TEXT, "Kernel version", collate="version"),
  Column("arguments", TEXT, "Kernel arguments"),
  Column("path", TEXT, "Kernel path"),
  Column("device", TEXT, "Kernel device identifier"),
])
attributes(cacheable=True)
implementation("system/kernel_info@genKernelInfo")
fuzz_paths([
    "/proc/cmdline",
    "/proc/version",
])


#linux
table_name("apparmor_events")
description("Track AppArmor events.")
schema([
    Column("type", TEXT, "Event type"),
    Column("message", TEXT, "Raw audit message"),
    Column("time", BIGINT, "Time of execution in UNIX time", additional=True),
    Column("uptime", BIGINT, "Time of execution in system uptime"),
    Column("eid", TEXT, "Event ID", hidden=True),
    Column("apparmor", TEXT, "Apparmor Status like ALLOWED, DENIED etc."),
    Column("operation", TEXT, "Permission requested by the process"),
    Column("parent", UNSIGNED_BIGINT, "Parent process PID"),
    Column("profile", TEXT, "Apparmor profile name"),
    Column("name", TEXT, "Process name"),
    Column("pid", UNSIGNED_BIGINT, "Process ID"),
    Column("comm", TEXT, "Command-line name of the command that was used to invoke the analyzed process"),
    Column("denied_mask", TEXT, "Denied permissions for the process"),
    Column("capname", TEXT, "Capability requested by the process"),
    Column("fsuid", UNSIGNED_BIGINT, "Filesystem user ID"),
    Column("ouid", UNSIGNED_BIGINT, "Object owner's user ID"),
    Column("capability", BIGINT, "Capability number"),
    Column("requested_mask", TEXT, "Requested access mask"),
    Column("info", TEXT, "Additional information"),
    Column("error", TEXT, "Error information"),
    Column("namespace", TEXT, "AppArmor namespace"),
    Column("label", TEXT, "AppArmor label"),
])
attributes(event_subscriber=True)
implementation("apparmor_events@apparmor_events::genTable")


#linux
table_name("apparmor_profiles")
description("Track active AppArmor profiles.")
schema([
    Column("path", TEXT, "Unique, aa-status compatible, policy identifier.", index=True),
    Column("name", TEXT, "Policy name."),
    Column("attach", TEXT, "Which executable(s) a profile will attach to."),
    Column("mode", TEXT, "How the policy is applied."),
    Column("sha1", TEXT, "A unique hash that identifies this policy."),
    Column("sha256", TEXT, "A unique hash that identifies this policy."),
])
implementation("system/apparmor_profiles@genAppArmorProfiles")
examples([
  "SELECT * FROM apparmor_profiles WHERE mode = 'complain'",
])


#linux
table_name("apt_sources")
description("Current list of APT repositories or software channels.")
schema([
    Column("name", TEXT, "Repository name"),
    Column("source", TEXT, "Source file"),
    Column("base_uri", TEXT, "Repository base URI"),
    Column("release", TEXT, "Release name"),
    Column("version", TEXT, "Repository source version", collate="version_dpkg"),
    Column("maintainer", TEXT, "Repository maintainer"),
    Column("components", TEXT, "Repository components"),
    Column("architectures", TEXT, "Repository architectures"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
implementation("system/apt_sources@genAptSrcs")
fuzz_paths([
    "/etc/apt/",
    "/var/lib/apt",
])


#linux
table_name("bpf_process_events")
description("Track time/action process executions.")
schema([
    Column("tid", BIGINT, "Thread ID"),
    Column("pid", BIGINT, "Process ID"),
    Column("parent", BIGINT, "Parent process ID"),
    Column("uid", BIGINT, "User ID"),
    Column("gid", BIGINT, "Group ID"),
    Column("cid", INTEGER, "Cgroup ID"),
    Column("exit_code", TEXT, "Exit code of the system call"),
    Column("probe_error", INTEGER, "Set to 1 if one or more buffers could not be captured"),
    Column("syscall", TEXT, "System call name"),
    Column("path", TEXT, "Binary path"),
    Column("cwd", TEXT, "Current working directory"),
    Column("cmdline", TEXT, "Command line arguments"),
    Column("duration", INTEGER, "How much time was spent inside the syscall (nsecs)"),
    Column("json_cmdline", TEXT, "Command line arguments, in JSON format", hidden=True),
    Column("ntime", TEXT, "The nsecs uptime timestamp as obtained from BPF"),
    Column("time", BIGINT, "Time of execution in UNIX time", hidden=True, additional=True),
    Column("eid", INTEGER, "Event ID", hidden=True),
])
attributes(event_subscriber=True)
implementation("bpf_process_events@bpf_process_events::genTable")


#linux
table_name("bpf_socket_events")
description("Track network socket opens and closes.")
schema([
    Column("tid", BIGINT, "Thread ID"),
    Column("pid", BIGINT, "Process ID"),
    Column("parent", BIGINT, "Parent process ID"),
    Column("uid", BIGINT, "User ID"),
    Column("gid", BIGINT, "Group ID"),
    Column("cid", INTEGER, "Cgroup ID"),
    Column("exit_code", TEXT, "Exit code of the system call"),
    Column("probe_error", INTEGER, "Set to 1 if one or more buffers could not be captured"),
    Column("syscall", TEXT, "System call name"),
    Column("path", TEXT, "Path of executed file"),
    Column("fd", TEXT, "The file description for the process socket"),
    Column("family", INTEGER, "The Internet protocol family ID"),
    Column("type", INTEGER, "The socket type"),
    Column("protocol", INTEGER, "The network protocol ID"), 
    Column("local_address", TEXT, "Local address associated with socket"),
    Column("remote_address", TEXT, "Remote address associated with socket"),
    Column("local_port", INTEGER, "Local network protocol port number"),
    Column("remote_port", INTEGER, "Remote network protocol port number"),
    Column("duration", INTEGER, "How much time was spent inside the syscall (nsecs)"),
    Column("ntime", TEXT, "The nsecs uptime timestamp as obtained from BPF"),
    Column("time", BIGINT, "Time of execution in UNIX time", hidden=True, additional=True),
    Column("eid", INTEGER, "Event ID", hidden=True),
])
attributes(event_subscriber=True)
implementation("bpf_socket_events@bpf_socket_events::genTable")


#linux
table_name("deb_package_files")
description("Installed files from DEB packages that are currently installed on the system.")
schema([
    Column("package", TEXT, "DEB package name", index=True, optimized=True),
    Column("path", TEXT, "File path within the package", index=True),
    Column("admindir", TEXT, "libdpkg admindir. Defaults to /var/lib/dpkg", additional=True, optimized=True),
])
implementation("system/deb_packages@genDebPackageFiles", generator=True)

#linux
table_name("deb_packages")
description("The installed DEB package database.")
schema([
    Column("name", TEXT, "Package name"),
    Column("version", TEXT, "Package version", collate="version_dpkg"),
    Column("source", TEXT, "Package source"),
    Column("size", BIGINT, "Package size in bytes"),
    Column("arch", TEXT, "Package architecture"),
    Column("revision", TEXT, "Package revision"),
    Column("status", TEXT, "Package status"),
    Column("maintainer", TEXT, "Package maintainer"),
    Column("section", TEXT, "Package section"),
    Column("priority", TEXT, "Package priority"),
    Column("admindir", TEXT, "libdpkg admindir. Defaults to /var/lib/dpkg", additional=True, optimized=True),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
    Column("mount_namespace_id", TEXT, "Mount namespace id", hidden=True),
])
attributes(cacheable=True)
implementation("system/deb_packages@genDebPackages")
fuzz_paths([
    "/var/lib/dpkg",
])


#linux
table_name("iptables")
description("Linux IP packet filtering and NAT tool.")
schema([
    Column("filter_name", TEXT, "Packet matching filter table name."),
    Column("chain", TEXT, "Size of module content."),
    Column("policy", TEXT, "Policy that applies for this rule."),
    Column("target", TEXT, "Target that applies for this rule."),
    Column("protocol", INTEGER, "Protocol number identification."),
    Column("src_port", TEXT, "Protocol source port(s)."),
    Column("dst_port", TEXT, "Protocol destination port(s)."),
    Column("src_ip", TEXT, "Source IP address."),
    Column("src_mask", TEXT, "Source IP address mask."),
    Column("iniface", TEXT, "Input interface for the rule."),
    Column("iniface_mask", TEXT, "Input interface mask for the rule."),
    Column("dst_ip", TEXT, "Destination IP address."),
    Column("dst_mask", TEXT, "Destination IP address mask."),
    Column("outiface", TEXT, "Output interface for the rule."),
    Column("outiface_mask", TEXT, "Output interface mask for the rule."),
    Column("match", TEXT, "Matching rule that applies."),
    Column("packets", INTEGER, "Number of matching packets for this rule."),
    Column("bytes", INTEGER, "Number of matching bytes for this rule."),
])
implementation("iptables@genIptables")
fuzz_paths([
    "/proc/net/ip_tables_names",
])


#linux
table_name("kernel_keys")
description("List of security data, authentication keys and encryption keys.")
schema([
    Column("serial_number", TEXT, "The serial key of the key."),
    Column("flags", TEXT, "A set of flags describing the state of the key."),
    Column("usage", BIGINT, "the number of threads and open file references that"
                     " refer to this key."),
    Column("timeout", TEXT, "The amount of time until the key will expire,"
                     " expressed in human-readable form. The string perm here"
                     " means that the key is permanent (no timeout).  The"
                     " string expd means that the key has already expired."),
    Column("permissions", TEXT, "The key permissions, expressed as four hexadecimal"
                     " bytes containing, from left to right, the"
                     " possessor, user, group, and other permissions."),
    Column("uid", BIGINT, "The user ID of the key owner."),
    Column("gid", BIGINT, "The group ID of the key."),
    Column("type", TEXT, "The key type."),
    Column("description", TEXT, "The key description."),
])
implementation("system/kernel_keys@genKernelKeys")
examples([
  "select * from kernel_keys"
])


#linux
table_name("kernel_modules")
description("Linux kernel modules both loaded and within the load search path.")
schema([
    Column("name", TEXT, "Module name"),
    Column("size", BIGINT, "Size of module content"),
    Column("used_by", TEXT, "Module reverse dependencies"),
    Column("status", TEXT, "Kernel module status"),
    Column("address", TEXT, "Kernel module address"),
])
implementation("kernel_modules@genKernelModules")
fuzz_paths([
    "/proc/modules",
])


#linux
table_name("lxd_certificates")
description("LXD certificates information.")
schema([
    Column("name", TEXT, "Name of the certificate"),
    Column("type", TEXT, "Type of the certificate"),
    Column("fingerprint", TEXT, "SHA256 hash of the certificate"),
    Column("certificate", TEXT, "Certificate content")
])
implementation("applications/lxd@genLxdCerts")
examples([
  "select * from lxd_certificates" 
])


#linux
table_name("lxd_cluster")
description("LXD cluster information.")
schema([
    Column("server_name", TEXT, "Name of the LXD server node"),
    Column("enabled", INTEGER, "Whether clustering enabled (1) or not (0) on this node"),
    Column("member_config_entity", TEXT, "Type of configuration parameter for this node"),
    Column("member_config_name", TEXT, "Name of configuration parameter"),
    Column("member_config_key", TEXT, "Config key"),
    Column("member_config_value", TEXT, "Config value"),
    Column("member_config_description", TEXT, "Config description")
])
implementation("applications/lxd@genLxdCluster")
examples([
  "select * from lxd_cluster" 
])


#linux
table_name("lxd_cluster_members")
description("LXD cluster members information.")
schema([
    Column("server_name", TEXT, "Name of the LXD server node"),
    Column("url", TEXT, "URL of the node"),
    Column("database", INTEGER, "Whether the server is a database node (1) or not (0)"),
    Column("status", TEXT, "Status of the node (Online/Offline)"),
    Column("message", TEXT, "Message from the node (Online/Offline)")
])
implementation("applications/lxd@genLxdClusterMembers")
examples([
  "select * from lxd_cluster_members" 
])


#linux
table_name("lxd_images")
description("LXD images information.")
schema([
    Column("id", TEXT, "Image ID", index=True),
    Column("architecture", TEXT, "Target architecture for the image"),
    Column("os", TEXT, "OS on which image is based"),
    Column("release", TEXT, "OS release version on which the image is based"),
    Column("description", TEXT, "Image description"),
    Column("aliases", TEXT, "Comma-separated list of image aliases"),
    Column("filename", TEXT, "Filename of the image file"),
    Column("size", BIGINT, "Size of image in bytes"),
    Column("auto_update", INTEGER, "Whether the image auto-updates (1) or not (0)"),
    Column("cached", INTEGER, "Whether image is cached (1) or not (0)"),
    Column("public", INTEGER, "Whether image is public (1) or not (0)"),
    Column("created_at", TEXT, "ISO time of image creation"),
    Column("expires_at", TEXT, "ISO time of image expiration"),
    Column("uploaded_at", TEXT, "ISO time of image upload"),
    Column("last_used_at", TEXT, "ISO time for the most recent use of this image in terms of container spawn"),
    Column("update_source_server", TEXT, "Server for image update"),
    Column("update_source_protocol", TEXT, "Protocol used for image information update and image import from source server"),
    Column("update_source_certificate", TEXT, "Certificate for update source server"),
    Column("update_source_alias", TEXT, "Alias of image at update source server")
])
implementation("applications/lxd@genLxdImages")
examples([
  "select * from lxd_images", 
  "select * from lxd_images where id = '0931b693c8'",
  "select * from lxd_images where id = '0931b693c877ef357b9e17b3195ae952a2450873923ffd2b34b60836ea730cfa'",
])


#linux
table_name("lxd_instance_config")
description("LXD instance configuration information.")
schema([
    Column("name", TEXT, "Instance name", index=True, required=True),
    Column("key", TEXT, "Configuration parameter name"),
    Column("value", TEXT, "Configuration parameter value")
])
implementation("applications/lxd@genLxdInstanceConfig")
examples([
  "select * from lxd_instance_config where name = 'hello'"
])


#linux
table_name("lxd_instance_devices")
description("LXD instance devices information.")
schema([
    Column("name", TEXT, "Instance name", index=True, required=True),
    Column("device", TEXT, "Name of the device"),
    Column("device_type", TEXT, "Device type"),
    Column("key", TEXT, "Device info param name"),
    Column("value", TEXT, "Device info param value")
])
implementation("applications/lxd@genLxdInstanceDevices")
examples([
  "select * from lxd_instance_devices where name = 'hello'"
])



#linux
table_name("lxd_instances")
description("LXD instances information.")
schema([
    Column("name", TEXT, "Instance name", index=True),
    Column("status", TEXT, "Instance state (running, stopped, etc.)"),
    Column("stateful", INTEGER, "Whether the instance is stateful(1) or not(0)"),
    Column("ephemeral", INTEGER, "Whether the instance is ephemeral(1) or not(0)"),
    Column("created_at", TEXT, "ISO time of creation"),
    Column("base_image", TEXT, "ID of image used to launch this instance"),
    Column("architecture", TEXT, "Instance architecture"),
    Column("os", TEXT, "The OS of this instance"),
    Column("description", TEXT, "Instance description"),
    Column("pid", INTEGER, "Instance's process ID"),
    Column("processes", INTEGER, "Number of processes running inside this instance")
])
implementation("applications/lxd@genLxdInstances")
examples([
  "select * from lxd_instances", 
  "select * from lxd_instances where name = 'hello'"
])


#linux
table_name("lxd_networks")
description("LXD network information.")
schema([
    Column("name", TEXT, "Name of the network"),
    Column("type", TEXT, "Type of network"),
    Column("managed", INTEGER, "1 if network created by LXD, 0 otherwise"),
    Column("ipv4_address", TEXT, "IPv4 address"),
    Column("ipv6_address", TEXT, "IPv6 address"),
    Column("used_by", TEXT, "URLs for containers using this network"),
    Column("bytes_received", BIGINT, "Number of bytes received on this network"),
    Column("bytes_sent", BIGINT, "Number of bytes sent on this network"),
    Column("packets_received", BIGINT, "Number of packets received on this network"),
    Column("packets_sent", BIGINT, "Number of packets sent on this network"),
    Column("hwaddr", TEXT, "Hardware address for this network"),
    Column("state", TEXT, "Network status"),
    Column("mtu", INTEGER, "MTU size")
])
implementation("applications/lxd@genLxdNetworks")
examples([
  "select * from lxd_networks" 
])


#linux
table_name("lxd_storage_pools")
description("LXD storage pool information.")
schema([
    Column("name", TEXT, "Name of the storage pool"),
    Column("driver", TEXT, "Storage driver"),
    Column("source", TEXT, "Storage pool source"),
    Column("size", TEXT, "Size of the storage pool"),
    Column("space_used", BIGINT, "Storage space used in bytes"),
    Column("space_total", BIGINT, "Total available storage space in bytes for this storage pool"),
    Column("inodes_used", BIGINT, "Number of inodes used"),
    Column("inodes_total", BIGINT, "Total number of inodes available in this storage pool")
])
implementation("applications/lxd@genLxdStoragePools")
examples([
  "select * from lxd_storage_pools" 
])


#linux
table_name("md_devices")
description("Software RAID array settings.")
schema([
    Column("device_name", TEXT, "md device name"),
    Column("status", TEXT, "Current state of the array"),
    Column("raid_level", INTEGER, "Current raid level of the array"),
    Column("size", BIGINT, "size of the array in blocks"),
    Column("chunk_size", BIGINT, "chunk size in bytes"),
    Column("raid_disks", INTEGER, "Number of configured RAID disks in array"),
    Column("nr_raid_disks", INTEGER,
        "Number of partitions or disk devices to comprise the array"),
    Column("working_disks", INTEGER, "Number of working disks in array"),
    Column("active_disks", INTEGER, "Number of active disks in array"),
    Column("failed_disks", INTEGER, "Number of failed disks in array"),
    Column("spare_disks", INTEGER, "Number of idle disks in array"),
    Column("superblock_state", TEXT, "State of the superblock"),
    Column("superblock_version", TEXT, "Version of the superblock"),
    Column("superblock_update_time", BIGINT, "Unix timestamp of last update"),
    Column("bitmap_on_mem", TEXT,
        "Pages allocated in in-memory bitmap, if enabled"),
    Column("bitmap_chunk_size", TEXT, "Bitmap chunk size"),
    Column("bitmap_external_file", TEXT, "External referenced bitmap file"),
    Column("recovery_progress", TEXT, "Progress of the recovery activity"),
    Column("recovery_finish", TEXT, "Estimated duration of recovery activity"),
    Column("recovery_speed", TEXT, "Speed of recovery activity"),
    Column("resync_progress", TEXT, "Progress of the resync activity"),
    Column("resync_finish", TEXT, "Estimated duration of resync activity"),
    Column("resync_speed", TEXT, "Speed of resync activity"),
    Column("reshape_progress", TEXT, "Progress of the reshape activity"),
    Column("reshape_finish", TEXT, "Estimated duration of reshape activity"),
    Column("reshape_speed", TEXT, "Speed of reshape activity"),
    Column("check_array_progress", TEXT, "Progress of the check array activity"),
    Column("check_array_finish", TEXT, "Estimated duration of the check array activity"),
    Column("check_array_speed", TEXT, "Speed of the check array activity"),
    Column("unused_devices", TEXT, "Unused devices"),
    Column("other", TEXT,
        "Other information associated with array from /proc/mdstat"),
])
implementation("system/md_stat@genMDDevices")


#linux
table_name("md_drives")
description("Drive devices used for Software RAID.")
schema([
    Column("md_device_name", TEXT, "md device name"),
    Column("drive_name", TEXT, "Drive device name"),
    Column("slot", INTEGER, "Slot position of disk"),
    Column("state", TEXT, "State of the drive"),
])
implementation("system/md_stat@genMDDrives")


#linux
table_name("md_personalities")
description("Software RAID setting supported by the kernel.")
schema([
    Column("name", TEXT, "Name of personality supported by kernel"),
])
implementation("system/md_stat@genMDPersonalities")


#linux
table_name("memory_info")
description("Main memory information in bytes.")
schema([
    Column("memory_total",  BIGINT, "Total amount of physical RAM, in bytes"),
    Column("memory_free", BIGINT, "The amount of physical RAM, in bytes, left unused by the system"),
    Column("memory_available", BIGINT, "The amount of physical RAM, in bytes, available for starting new applications, without swapping"),
    Column("buffers", BIGINT, "The amount of physical RAM, in bytes, used for file buffers"),
    Column("cached", BIGINT, "The amount of physical RAM, in bytes, used as cache memory"),
    Column("swap_cached", BIGINT, "The amount of swap, in bytes, used as cache memory"),
    Column("active", BIGINT, "The total amount of buffer or page cache memory, in bytes, that is in active use"),
    Column("inactive", BIGINT, "The total amount of buffer or page cache memory, in bytes, that are free and available"),
    Column("swap_total", BIGINT, "The total amount of swap available, in bytes"),
    Column("swap_free", BIGINT, "The total amount of swap free, in bytes"),
])

implementation("memory_info@getMemoryInfo")
fuzz_paths([
    "/proc/meminfo",
])


#linux
table_name("memory_map")
description("OS memory region map.")
schema([
    Column("name", TEXT, "Region name"),
    Column("start", TEXT, "Start address of memory region"),
    Column("end", TEXT, "End address of memory region"),
])
implementation("memory_map@genMemoryMap")
fuzz_paths([
    "/proc/iomem",
])


#linux
table_name("msr")
description("Various pieces of data stored in the model specific register per "
            "processor. NOTE: the msr kernel module must be enabled, and "
            "osquery must be run as root.")
schema([
    Column("processor_number", BIGINT,
      "The processor number as reported in /proc/cpuinfo"),
    Column("turbo_disabled", BIGINT, "Whether the turbo feature is disabled."),
    Column("turbo_ratio_limit", BIGINT, "The turbo feature ratio limit."),
    Column("platform_info", BIGINT, "Platform information."),
    Column("perf_ctl", BIGINT, "Performance setting for the processor."),
    Column("perf_status", BIGINT, "Performance status for the processor."),
    Column("feature_control", BIGINT, "Bitfield controlling enabled features."),
    Column("rapl_power_limit", BIGINT,
      "Run Time Average Power Limiting power limit."),
    Column("rapl_energy_status", BIGINT,
      "Run Time Average Power Limiting energy status."),
    Column("rapl_power_units", BIGINT,
      "Run Time Average Power Limiting power units.")
])
implementation("model_specific_register@genModelSpecificRegister")


#linux
table_name("portage_keywords")
description("A summary about portage configurations like keywords, mask and unmask.")
schema([
    Column("package", TEXT, "Package name"),
    Column("version", TEXT, "The version which are affected by the use flags, empty means all"),
    Column("keyword", TEXT, "The keyword applied to the package"),
    Column("mask", INTEGER, "If the package is masked"),
    Column("unmask", INTEGER, "If the package is unmasked"),
])
implementation("system/portage_keywords@genPortageKeywordSummary")
fuzz_paths([
    "/etc/portage/",
])


#linux
table_name("portage_packages")
description("List of currently installed packages.")
schema([
    Column("package", TEXT, "Package name"),
    Column("version", TEXT, "The version which are affected by the use flags, empty means all"),
    Column("slot", TEXT, "The slot used by package"),
    Column("build_time", BIGINT, "Unix time when package was built"),
    Column("repository", TEXT, "From which repository the ebuild was used"),
    Column("eapi", BIGINT, "The eapi for the ebuild"),
    Column("size", BIGINT, "The size of the package"),
	Column("world", INTEGER, "If package is in the world file"),
])
implementation("system/portage_packages@portagePackages")
fuzz_paths([
    "/var/db/pkg/",
    "/var/lib/portage",
])


#linux
table_name("portage_use")
description("List of enabled portage USE values for specific package.")
schema([
    Column("package", TEXT, "Package name"),
    Column("version", TEXT, "The version of the installed package"),
    Column("use", TEXT, "USE flag which has been enabled for package"),
])
implementation("system/portage_use@genPortageUse")
fuzz_paths([
    "/var/db/pkg/",
])


#linux
table_name("process_file_events")
description("A File Integrity Monitor implementation using the audit service.")

schema([
    Column("operation", TEXT, "Operation type"),
    Column("pid", BIGINT, "Process ID"),
    Column("ppid", BIGINT, "Parent process ID"),
    Column("time", BIGINT, "Time of execution in UNIX time", additional=True),
    Column("executable", TEXT, "The executable path"),
    Column("partial", TEXT, "True if this is a partial event (i.e.: this process existed before we started osquery)"),
    Column("cwd", TEXT, "The current working directory of the process"),
    Column("path", TEXT, "The path associated with the event"),
    Column("dest_path", TEXT, "The canonical path associated with the event"),
    Column("uid", TEXT, "The uid of the process performing the action"),
    Column("gid", TEXT, "The gid of the process performing the action"),
    Column("auid", TEXT, "Audit user ID of the process using the file"),
    Column("euid", TEXT, "Effective user ID of the process using the file"),
    Column("egid", TEXT, "Effective group ID of the process using the file"),
    Column("fsuid", TEXT, "Filesystem user ID of the process using the file"),
    Column("fsgid", TEXT, "Filesystem group ID of the process using the file"),
    Column("suid", TEXT, "Saved user ID of the process using the file"),
    Column("sgid", TEXT, "Saved group ID of the process using the file"),
    Column("uptime", BIGINT, "Time of execution in system uptime"),
    Column("eid", TEXT, "Event ID", hidden=True),
])

attributes(event_subscriber=True)
implementation("process_file_events@process_file_events::genTable")


#linux
table_name("process_namespaces")
description("Linux namespaces for processes running on the host system.")
schema([
    Column("pid", INTEGER, "Process (or thread) ID", index=True, optimized=True),
    Column("cgroup_namespace", TEXT, "cgroup namespace inode"),
    Column("ipc_namespace", TEXT, "ipc namespace inode"),
    Column("mnt_namespace", TEXT, "mnt namespace inode"),
    Column("net_namespace", TEXT, "net namespace inode"),
    Column("pid_namespace", TEXT, "pid namespace inode"),
    Column("user_namespace", TEXT, "user namespace inode"),
    Column("uts_namespace", TEXT, "uts namespace inode")
])
implementation("system/processes@genProcessNamespaces")
examples([
  "select * from process_namespaces where pid = 1",
])


#linux
table_name("process_open_pipes")
description("Pipes and partner processes for each process.")
schema([
    Column("pid", BIGINT, "Process ID"),
    Column("fd", BIGINT, "File descriptor"),
    Column("mode", TEXT, "Pipe open mode (r/w)"),
    Column("inode", BIGINT, "Pipe inode number"),
    Column("type", TEXT, "Pipe Type: named vs unnamed/anonymous"),
    Column("partner_pid", BIGINT, "Process ID of partner process sharing a particular pipe"),
    Column("partner_fd", BIGINT, "File descriptor of shared pipe at partner's end"),
    Column("partner_mode", TEXT, "Mode of shared pipe at partner's end"),
])
implementation("system/process_open_pipes@genPipes")
examples([
  "select * from process_open_pipes",
])


#linux
table_name("rpm_package_files")
description("Installed files from RPM packages that are currently installed on the system.")
schema([
    Column("package", TEXT, "RPM package name", index=True, optimized=True),
    Column("path", TEXT, "File path within the package", index=True),
    Column("username", TEXT, "File default username from info DB"),
    Column("groupname", TEXT, "File default groupname from info DB"),
    Column("mode", TEXT, "File permissions mode from info DB"),
    Column("size", BIGINT, "Expected file size in bytes from RPM info DB"),
    Column("sha256", TEXT, "SHA256 file digest from RPM info DB"),
])
implementation("@genRpmPackageFiles", generator=True)


#linux
table_name("rpm_packages")
description("RPM packages that are currently installed on the host system.")
schema([
    Column("name", TEXT, "RPM package name", index=True, optimized=True),
    Column("version", TEXT, "Package version" ,index=True, collate="version_rhel"),
    Column("release", TEXT, "Package release", index=True),
    Column("source", TEXT, "Source RPM package name (optional)"),
    Column("size", BIGINT, "Package size in bytes"),
    Column("sha1", TEXT, "SHA1 hash of the package contents"),
    Column("arch", TEXT, "Architecture(s) supported", index=True),
    Column("epoch", INTEGER, "Package epoch value", index=True),
    Column("install_time", INTEGER, "When the package was installed"),
    Column("vendor", TEXT, "Package vendor"),
    Column("package_group", TEXT, "Package group")
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
    Column("mount_namespace_id", TEXT, "Mount namespace id", hidden=True),
])
attributes(cacheable=True)
implementation("@genRpmPackages")


#linux
table_name("seccomp_events")

description("A virtual table that tracks seccomp events.")

schema([
    Column("time", BIGINT, "Time of execution in UNIX time", additional=True),
    Column("uptime", BIGINT, "Time of execution in system uptime"),
    Column("auid", UNSIGNED_BIGINT, "Audit user ID (loginuid) of the user who started the analyzed process"),
    Column("uid", UNSIGNED_BIGINT, "User ID of the user who started the analyzed process"),
    Column("gid", UNSIGNED_BIGINT, "Group ID of the user who started the analyzed process"),
    Column("ses", UNSIGNED_BIGINT, "Session ID of the session from which the analyzed process was invoked"),
    Column("pid", UNSIGNED_BIGINT, "Process ID"),
    Column("comm", TEXT, "Command-line name of the command that was used to invoke the analyzed process"),
    Column("exe", TEXT, "The path to the executable that was used to invoke the analyzed process"),
    Column("sig", BIGINT, "Signal value sent to process by seccomp"),
    Column("arch", TEXT, "Information about the CPU architecture"),
    Column("syscall", TEXT, "Type of the system call"),
    Column("compat", BIGINT, "Is system call in compatibility mode"),
    Column("ip", TEXT, "Instruction pointer value"),
    Column("code", TEXT, "The seccomp action"),
])

attributes(event_subscriber=True)
implementation("seccomp_events@seccomp_events::genTable")


#linux
table_name("selinux_events")
description("Track SELinux events.")
schema([
    Column("type", TEXT, "Event type"),
    Column("message", TEXT, "Message"),
    Column("time", BIGINT, "Time of execution in UNIX time", additional=True),
    Column("uptime", BIGINT, "Time of execution in system uptime"),
    Column("eid", TEXT, "Event ID", hidden=True),
])
attributes(event_subscriber=True)
implementation("selinux_events@selinux_events::genTable")


#linux
table_name("selinux_settings")
description("Track active SELinux settings.")
schema([
    Column("scope", TEXT, "Where the key is located inside the SELinuxFS mount point."),
    Column("key", TEXT, "Key or class name."),
    Column("value", TEXT, "Active value."),
])
implementation("system/selinux_settings@genSELinuxSettings")
examples([
  "SELECT * FROM selinux_settings WHERE key = 'enforce'",
])


#linux
table_name("shadow")
description("Local system users encrypted passwords and related information. Please note, that you usually need superuser rights to access `/etc/shadow`.")
schema([
    Column("password_status", TEXT, "Password status"),
    Column("hash_alg", TEXT, "Password hashing algorithm"),
    Column("last_change", BIGINT, "Date of last password change (starting from UNIX epoch date)"),
    Column("min", BIGINT, "Minimal number of days between password changes"),
    Column("max", BIGINT, "Maximum number of days between password changes"),
    Column("warning", BIGINT, "Number of days before password expires to warn user about it"),
    Column("inactive", BIGINT, "Number of days after password expires until account is blocked"),
    Column("expire", BIGINT, "Number of days since UNIX epoch date until account is disabled"),
    Column("flag", BIGINT, "Reserved"),
    Column("username", TEXT, "Username", index=True, optimized=True),
])
implementation("system/shadow@genShadow")
examples([
  "select * from shadow where username = 'root'",
])


#linux
table_name("shared_memory")
description("OS shared memory regions.")
schema([
    Column("shmid", INTEGER, "Shared memory segment ID"),
    Column("owner_uid", BIGINT, "User ID of owning process"),
    Column("creator_uid", BIGINT, "User ID of creator process"),
    Column("pid", BIGINT, "Process ID to last use the segment"),
    Column("creator_pid", BIGINT, "Process ID that created the segment"),
    Column("atime", BIGINT, "Attached time"),
    Column("dtime", BIGINT, "Detached time"),
    Column("ctime", BIGINT, "Changed time"),
    Column("permissions", TEXT, "Memory segment permissions"),
    Column("size", BIGINT, "Size in bytes"),
    Column("attached", INTEGER, "Number of attached processes"),
    Column("status", TEXT, "Destination/attach status"),
    Column("locked", INTEGER, "1 if segment is locked else 0"),
])
implementation("shared_memory@genSharedMemory")


#linux
table_name("syslog_events", aliases=["syslog"])
schema([
    Column("time", BIGINT, "Current unix epoch time", additional=True),
    Column("datetime", TEXT, "Time known to syslog"),
    Column("host", TEXT, "Hostname configured for syslog"),
    Column("severity", INTEGER, "Syslog severity"),
    Column("facility", TEXT, "Syslog facility"),
    Column("tag", TEXT, "The syslog tag"),
    Column("message", TEXT, "The syslog message"),
    Column("eid", TEXT, "Event ID", hidden=True),
])
attributes(event_subscriber=True)
implementation("syslog_events@SyslogEventSubscriber::genTable")


#linux
table_name("systemd_units")
description("Track systemd units.")
schema([
    Column("id", TEXT, "Unique unit identifier"),
    Column("description", TEXT, "Unit description"),
    Column("load_state", TEXT, "Reflects whether the unit definition was properly loaded"),
    Column("active_state", TEXT, "The high-level unit activation state, i.e. generalization of SUB"),
    Column("sub_state", TEXT, "The low-level unit activation state, values depend on unit type"),
    Column("unit_file_state", TEXT, "Whether the unit file is enabled, e.g. `enabled`, `masked`, `disabled`, etc"),
    Column("following", TEXT, "The name of another unit that this unit follows in state"),
    Column("object_path", TEXT, "The object path for this unit"),
    Column("job_id", BIGINT, "Next queued job id"),
    Column("job_type", TEXT, "Job type"),
    Column("job_path", TEXT, "The object path for the job"),
    Column("fragment_path", TEXT, "The unit file path this unit was read from, if there is any"),
    Column("user", TEXT, "The configured user, if any"),
    Column("source_path", TEXT, "Path to the (possibly generated) unit configuration file"),
])
attributes(strongly_typed_rows=True)
implementation("system/systemd_units@genSystemdUnits")


#linux
table_name("yum_sources")
description("Current list of Yum repositories or software channels.")
schema([
    Column("name", TEXT, "Repository name"),
    Column("source", TEXT, "Source file"),
    Column("baseurl", TEXT, "Repository base URL"),
    Column("mirrorlist", TEXT, "Mirrorlist URL"),
    Column("metalink", TEXT, "Metalink URL"),
    Column("enabled", TEXT, "Whether the repository is used"),
    Column("gpgcheck", TEXT, "Whether packages are GPG checked"),
    Column("gpgkey", TEXT, "URL to GPG key"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
implementation("system/yum_sources@genYumSrcs")


#linwin
table_name("intel_me_info")
description("Intel ME/CSE Info.")
schema([
    Column("version",  TEXT, "Intel ME version", collate="version"),
])

implementation("intel_me_info@getIntelMEInfo")
fuzz_paths([
    "/proc/meminfo",
])


#cross-platform
table_name("listening_ports")
description("Processes with listening (bound) network sockets/ports.")
schema([
    Column("pid", INTEGER, "Process (or thread) ID"),
    Column("port", INTEGER, "Transport layer port"),
    Column("protocol", INTEGER, "Transport protocol (TCP/UDP)"),
    Column("family", INTEGER, "Network protocol (IPv4, IPv6)"),
    Column("address", TEXT, "Specific address for bind"),
    Column("fd", BIGINT, "Socket file descriptor number"),
    Column("socket", BIGINT, "Socket handle or inode number"),
    Column("path", TEXT, "Path for UNIX domain sockets")
])
extended_schema(LINUX, [
    Column("net_namespace", TEXT, "The inode number of the network namespace"),
])
attributes(cacheable=True)
implementation("listening_ports@genListeningPorts")


#cross-platform
table_name("logged_in_users")
description("Users with an active shell on the system.")
schema([
    Column("type", TEXT, "Login type"),
    Column("user", TEXT, "User login name"),
    Column("tty", TEXT, "Device name"),
    Column("host", TEXT, "Remote hostname"),
    Column("time", BIGINT, "Time entry was made"),
    Column("pid", INTEGER, "Process (or thread) ID"),
])
extended_schema(WINDOWS, [
    Column("sid", TEXT, "The user's unique security identifier"),
    Column("registry_hive", TEXT, "HKEY_USERS registry hive"),
])
attributes(cacheable=True)
implementation("logged_in_users@genLoggedInUsers")


#macwin
table_name("battery")
description("Provides information about the internal battery of a laptop. Note: On Windows, columns with Ah or mAh units assume that the battery is 12V.")
schema([
    Column("manufacturer", TEXT, "The battery manufacturer's name"),
    Column("model", TEXT, "The battery's model number"),
    Column("serial_number", TEXT, "The battery's serial number"),
    Column("cycle_count", INTEGER, "The number of charge/discharge cycles"),
    Column("state", TEXT, "One of the following: \"AC Power\" indicates the battery is connected to an external power source, \"Battery Power\" indicates that the battery is drawing internal power, \"Off Line\" indicates the battery is off-line or no longer connected"),
    Column("charging", INTEGER, "1 if the battery is currently being charged by a power source. 0 otherwise"),
    Column("charged", INTEGER, "1 if the battery is currently completely charged. 0 otherwise"),
    Column("designed_capacity", INTEGER, "The battery's designed capacity in mAh"),
    Column("max_capacity", INTEGER, "The battery's actual capacity when it is fully charged in mAh"),
    Column("current_capacity", INTEGER, "The battery's current capacity (level of charge) in mAh"),
    Column("percent_remaining", INTEGER, "The percentage of battery remaining before it is drained"),
    Column("amperage", INTEGER, "The current amperage in/out of the battery in mA (positive means charging, negative means discharging)"),
    Column("voltage", INTEGER, "The battery's current voltage in mV"),
    Column("minutes_until_empty", INTEGER, "The number of minutes until the battery is fully depleted. This value is -1 if this time is still being calculated"),
    Column("minutes_to_full_charge", INTEGER, "The number of minutes until the battery is fully charged. This value is -1 if this time is still being calculated. On Windows this is calculated from the charge rate and capacity and may not agree with the number reported in \"Power & Battery\""),
])
extended_schema(WINDOWS, [
    Column("chemistry", TEXT, "The battery chemistry type (eg. LiP). Some possible values are documented in https://learn.microsoft.com/en-us/windows/win32/power/battery-information-str."),
])
extended_schema(DARWIN, [
    Column("health", TEXT, "One of the following: \"Good\" describes a well-performing battery, \"Fair\" describes a functional battery with limited capacity, or \"Poor\" describes a battery that's not capable of providing power"),
    Column("condition", TEXT, "One of the following: \"Normal\" indicates the condition of the battery is within normal tolerances, \"Service Needed\" indicates that the battery should be checked out by a licensed Mac repair service, \"Permanent Failure\" indicates the battery needs replacement"),
    Column("manufacture_date", INTEGER, "The date the battery was manufactured UNIX Epoch"),
])
implementation("battery@genBatteryInfo")


#cross-platform
table_name("memory_devices")
description("Physical memory device (type 17) information retrieved from SMBIOS.")
schema([
    Column("handle",  TEXT, "Handle, or instance number, associated with the structure in SMBIOS"),
    Column("array_handle",  TEXT, "The memory array that the device is attached to"),
    Column("form_factor", TEXT, "Implementation form factor for this memory device"),
    Column("total_width", INTEGER, "Total width, in bits, of this memory device, including any check or error-correction bits"),
    Column("data_width", INTEGER, "Data width, in bits, of this memory device"),
    Column("size", INTEGER, "Size of memory device in Megabyte"),
    Column("set", INTEGER, "Identifies if memory device is one of a set of devices.  A value of 0 indicates no set affiliation."),
    Column("device_locator", TEXT, "String number of the string that identifies the physically-labeled socket or board position where the memory device is located"),
    Column("bank_locator", TEXT, "String number of the string that identifies the physically-labeled bank where the memory device is located"),
    Column("memory_type", TEXT, "Type of memory used"),
    Column("memory_type_details", TEXT, "Additional details for memory device"),
    Column("max_speed", INTEGER, "Max speed of memory device in megatransfers per second (MT/s)"),
    Column("configured_clock_speed", INTEGER, "Configured speed of memory device in megatransfers per second (MT/s)"),
    Column("manufacturer", TEXT, "Manufacturer ID string"),
    Column("serial_number", TEXT, "Serial number of memory device"),
    Column("asset_tag", TEXT, "Manufacturer specific asset tag of memory device"),
    Column("part_number", TEXT, "Manufacturer specific serial number of memory device"),
    Column("min_voltage", INTEGER, "Minimum operating voltage of device in millivolts"),
    Column("max_voltage", INTEGER, "Maximum operating voltage of device in millivolts"),
    Column("configured_voltage", INTEGER, "Configured operating voltage of device in millivolts"),
])

implementation("system@genMemoryDevices")
fuzz_paths([
    "/sys/firmware/efi/systab",
])

#cross-platform
table_name("npm_packages")
description("Node packages installed in a system.")
schema([
    Column("name", TEXT, "Package display name"),
    Column("version", TEXT, "Package-supplied version", collate="version"),
    Column("description", TEXT, "Package-supplied description"),
    Column("author", TEXT, "Package-supplied author"),
    Column("license", TEXT, "License under which package is launched"),
    Column("homepage", TEXT, "Package supplied homepage"),
    Column("path", TEXT, "Path at which this module resides"),
    Column("directory", TEXT, "Directory where node_modules are located", index=True, optimized=True)
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
    Column("mount_namespace_id", TEXT, "Mount namespace id", hidden=True),
])
implementation("npm_packages@genNodePackages")
examples([
  "select * from npm_packages",
  "select * from npm_packages where directory = '/home/user/my_project'",
])
fuzz_paths([
    "/usr/lib/node_modules/",
])


#cross-platform
table_name("os_version")
description("A single row containing the operating system name and version.")
schema([
    Column("name", TEXT, "Distribution or product name"),
    Column("version", TEXT, "Pretty, suitable for presentation, OS version", collate="version"),
    Column("major", INTEGER, "Major release version"),
    Column("minor", INTEGER, "Minor release version"),
    Column("patch", INTEGER, "Optional patch release"),
    Column("build", TEXT, "Optional build-specific or variant string"),
    Column("platform", TEXT, "OS Platform or ID"),
    Column("platform_like", TEXT, "Closely related platforms"),
    Column("codename", TEXT, "OS version codename"),
    Column("arch", TEXT, "OS Architecture"),
])

extended_schema(DARWIN, [
    Column("extra", TEXT, "Optional extra release specification"),
])

extended_schema(WINDOWS, [
    Column("install_date", BIGINT, "The install date of the OS."),
    Column("revision", INTEGER, "Update Build Revision, refers to the specific revision number of a Windows update"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
    Column("mount_namespace_id", TEXT, "Mount namespace id", hidden=True),
])
implementation("system/os_version@genOSVersion")
fuzz_paths([
    "/System/Library/CoreServices/SystemVersion.plist",
])


#cross-platform
table_name("platform_info")
description("Information about EFI/UEFI/ROM and platform/boot.")
schema([
    Column("vendor", TEXT, "Platform code vendor"),
    Column("version", TEXT, "Platform code version"),
    Column("date", TEXT, "Self-reported platform code update date"),
    Column("revision", TEXT, "BIOS major and minor revision"),
    Column("extra", TEXT, "Platform-specific additional information"),
    Column("firmware_type", TEXT, "The type of firmware (uefi, bios, iboot, openfirmware, unknown).")
])
extended_schema(LINUX + DARWIN,[
    Column("address", TEXT, "Relative address of firmware mapping"),
    Column("size", TEXT, "Size in bytes of firmware"),
    Column("volume_size", INTEGER, "(Optional) size of firmware volume")
])
implementation("system@genPlatformInfo")


#posix
table_name("acpi_tables")
description("Firmware ACPI functional table common metadata and content.")
schema([
    Column("name", TEXT, "ACPI table name"),
    Column("size", INTEGER, "Size of compiled table data"),
    Column("md5", TEXT, "MD5 hash of table content"),
])
implementation("system/acpi_tables@genACPITables")
fuzz_paths([
    "/sys/firmware/",
])


#posix
table_name("augeas", aliases=["configurations"])
description("Configuration files parsed by augeas.")
schema([
    Column("node", TEXT, "The node path of the configuration item", index=True),
    Column("value", TEXT, "The value of the configuration item"),
    Column("label", TEXT, "The label of the configuration item"),
    Column("path", TEXT, "The path to the configuration file", additional=True)
])
implementation("other/augeas@genAugeas")
examples([
  "select * from augeas where path = '/etc/hosts'",
])


#posix
table_name("authorized_keys")
description("A line-delimited authorized_keys table.")
schema([
    Column("uid", BIGINT, "The local owner of authorized_keys file",
      additional=True),
    Column("algorithm", TEXT, "Key type"),
    Column("key", TEXT, "Key encoded as base64"),
    Column("options", TEXT, "Optional list of login options"),
    Column("comment", TEXT, "Optional comment"),
    Column("key_file", TEXT, "Path to the authorized_keys file"),
    ForeignKey(column="uid", table="users"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
attributes(user_data=True, no_pkey=True)
implementation("authorized_keys@getAuthorizedKeys")
examples([
  "select * from users join authorized_keys using (uid)",
])
fuzz_paths([
  "/home",
  "/Users",
])


#posix
table_name("block_devices")
description("Block (buffered access) device file nodes: disks, ramdisks, and DMG containers.")
schema([
    Column("name", TEXT, "Block device name", index=True),
    Column("parent", TEXT, "Block device parent name"),
    Column("vendor", TEXT, "Block device vendor string"),
    Column("model", TEXT, "Block device model string identifier"),
    Column("serial", TEXT, "Disk serial number"),
    Column("size", BIGINT, "Block device size in blocks"),
    Column("block_size", INTEGER, "Block size in bytes"),
    Column("uuid", TEXT, "Block device Universally Unique Identifier"),
    Column("type", TEXT, "Block device type string"),
    Column("label", TEXT, "Block device label string"),
])
implementation("block_devices@genBlockDevs")


#posix
table_name("cpu_time")
description("Displays information from /proc/stat file about the time the cpu cores spent in different parts of the system.")
schema([
    Column("core", INTEGER, "Name of the cpu (core)"),
    Column("user", BIGINT, "Time spent in user mode"),
    Column("nice", BIGINT, "Time spent in user mode with low priority (nice)"),
    Column("system", BIGINT, "Time spent in system mode"),
    Column("idle", BIGINT, "Time spent in the idle task"),
    Column("iowait", BIGINT, "Time spent waiting for I/O to complete"),
    Column("irq", BIGINT, "Time spent servicing interrupts"),
    Column("softirq", BIGINT, "Time spent servicing softirqs"),
    Column("steal", BIGINT, "Time spent in other operating systems when running in a virtualized environment"),
    Column("guest", BIGINT, "Time spent running a virtual CPU for a guest OS under the control of the Linux kernel"),
    Column("guest_nice", BIGINT, "Time spent running a niced guest "),
])
implementation("cpu_time@genCpuTime")
fuzz_paths([
    "/proc/stat",
])


#posix
table_name("crontab")
description("Line parsed values from system and user cron/tab.")
schema([
    Column("event", TEXT, "The job @event name (rare)"),
    Column("minute", TEXT, "The exact minute for the job"),
    Column("hour", TEXT, "The hour of the day for the job"),
    Column("day_of_month", TEXT, "The day of the month for the job"),
    Column("month", TEXT, "The month of the year for the job"),
    Column("day_of_week", TEXT, "The day of the week for the job"),
    Column("command", TEXT, "Raw command string"),
    Column("path", TEXT, "File parsed"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
attributes(cacheable=True)
implementation("crontab@genCronTab")
fuzz_paths([
    "/var/spool/cron/crontabs/",
    "/etc/crontab",
])


#posix
table_name("disk_encryption")
description("Disk encryption status and information.")
schema([
    Column("name", TEXT, "Disk name", index=True),
    Column("uuid", TEXT, "Disk Universally Unique Identifier"),
    Column("encrypted", INTEGER, "1 If encrypted: true (disk is encrypted), else 0"),
    Column("type", TEXT, "Description of cipher type and mode if available"),
    Column("encryption_status", TEXT, "Disk encryption status with one of following values: encrypted | not encrypted | undefined"),
])
extended_schema(DARWIN, [
    ForeignKey(column="name", table="block_devices"),
    ForeignKey(column="uuid", table="block_devices"),
    Column("uid", TEXT, "Currently authenticated user if available"),
    Column("user_uuid", TEXT, "UUID of authenticated user if available"),
    Column("filevault_status", TEXT, "FileVault status with one of following values: on | off | unknown"),
])
implementation("disk_encryption@genFDEStatus")


#posix
table_name("dns_resolvers")
description("Resolvers used by this host. Note: On Windows this data is available in the interface_details table.")
schema([
    Column("id", INTEGER, "Address type index or order"),
    Column("type", TEXT, "Address type: sortlist, nameserver, search"),
    Column("address", TEXT, "Resolver IP/IPv6 address"),
    Column("netmask", TEXT, "Address (sortlist) netmask length"),
    Column("options", BIGINT, "Resolver options"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
implementation("dns_resolvers@genDNSResolvers")


#posix
table_name("docker_container_envs")
description("Docker container environment variables.")
schema([
    Column("id", TEXT, "Container ID", index=True),
    Column("key", TEXT, "Environment variable name"),
    Column("value", TEXT, "Environment variable value")
])
implementation("applications/docker@genContainerEnvs")
examples([
  "select * from docker_container_envs",
  "select * from docker_container_envs where id = '1234567890abcdef'",
  "select * from docker_container_envs where id = '11b2399e1426d906e62a0c657650e363426d6c56dbe2f35cbaa9b452250e3355'"
])


#posix
table_name("docker_container_fs_changes")
description("Changes to files or directories on container's filesystem.")
schema([
    Column("id", TEXT, "Container ID", index=True, required=True),
    Column("path", TEXT, "FIle or directory path relative to rootfs"),
    Column("change_type", TEXT, "Type of change: C:Modified, A:Added, D:Deleted")
])
implementation("applications/docker@genContainerFsChanges")
examples([
  "select * from docker_container_fs_changes where id = '1234567890abcdef'",
  "select * from docker_container_fs_changes where id = '11b2399e1426d906e62a0c357650e363426d6c56dbe2f35cbaa9b452250e3355'"
])


#posix
table_name("docker_container_labels")
description("Docker container labels.")
schema([
    Column("id", TEXT, "Container ID", index=True),
    Column("key", TEXT, "Label key", index=True),
    Column("value", TEXT, "Optional label value")
])
implementation("applications/docker@genContainerLabels")
examples([
  "select * from docker_container_labels",
  "select * from docker_container_labels where id = '1234567890abcdef'",
  "select * from docker_container_labels where id = '11b2399e1426d906e62a0c357650e363426d6c56dbe2f35cbaa9b452250e3355'"
])


#posix
table_name("docker_container_mounts")
description("Docker container mounts.")
schema([
    Column("id", TEXT, "Container ID", index=True),
    Column("type", TEXT, "Type of mount (bind, volume)"),
    Column("name", TEXT, "Optional mount name", index=True),
    Column("source", TEXT, "Source path on host"),
    Column("destination", TEXT, "Destination path inside container"),
    Column("driver", TEXT, "Driver providing the mount"),
    Column("mode", TEXT, "Mount options (rw, ro)"),
    Column("rw", INTEGER, "1 if read/write. 0 otherwise"),
    Column("propagation", TEXT, "Mount propagation")
])
implementation("applications/docker@genContainerMounts")
examples([
  "select * from docker_container_mounts",
  "select * from docker_container_mounts where id = '1234567890abcdef'",
  "select * from docker_container_mounts where id = '11b2399e1426d906e62a0c357650e363426d6c56dbe2f35cbaa9b452250e3355'"
])


#posix
table_name("docker_container_networks")
description("Docker container networks.")
schema([
    Column("id", TEXT, "Container ID", index=True),
    Column("name", TEXT, "Network name", index=True),
    Column("network_id", TEXT, "Network ID"),
    Column("endpoint_id", TEXT, "Endpoint ID"),
    Column("gateway", TEXT, "Gateway"),
    Column("ip_address", TEXT, "IP address"),
    Column("ip_prefix_len", INTEGER, "IP subnet prefix length"),
    Column("ipv6_gateway", TEXT, "IPv6 gateway"),
    Column("ipv6_address", TEXT, "IPv6 address"),
    Column("ipv6_prefix_len", INTEGER, "IPv6 subnet prefix length"),
    Column("mac_address", TEXT, "MAC address")
])
implementation("applications/docker@genContainerNetworks")
examples([
  "select * from docker_container_networks",
  "select * from docker_container_networks where id = '1234567890abcdef'",
  "select * from docker_container_networks where id = '11b2399e1426d906e62a0c357650e363426d6c56dbe2f35cbaa9b452250e3355'"
])


#posix
table_name("docker_container_ports")
description("Docker container ports.")
schema([
    Column("id", TEXT, "Container ID", additional=True),
    Column("type", TEXT, "Protocol (tcp, udp)"),
    Column("port", INTEGER, "Port inside the container"),
    Column("host_ip", TEXT, "Host IP address on which public port is listening"),
    Column("host_port", INTEGER, "Host port")
])
implementation("applications/docker@genContainerPorts")
examples([
  "select * from docker_container_ports",
  "select * from docker_container_ports where id = '1234567890abcdef'",
  "select * from docker_container_ports where id = '11b2399e1426d906e62a0c357650e363426d6c56dbe2f35cbaa9b452250e3355'"
])


#posix
table_name("docker_container_processes")
description("Docker container processes.")
schema([
    Column("id", TEXT, "Container ID", index=True, required=True),
    Column("pid", BIGINT, "Process ID", index=True),
    Column("name", TEXT, "The process path or shorthand argv[0]"),
    Column("cmdline", TEXT, "Complete argv"),
    Column("state", TEXT, "Process state"),
    Column("uid", BIGINT, "User ID"),
    Column("gid", BIGINT, "Group ID"),
    Column("euid", BIGINT, "Effective user ID"),
    Column("egid", BIGINT, "Effective group ID"),
    Column("suid", BIGINT, "Saved user ID"),
    Column("sgid", BIGINT, "Saved group ID"),
    Column("wired_size", BIGINT, "Bytes of unpageable memory used by process"),
    Column("resident_size", BIGINT, "Bytes of private memory used by process"),
    Column("total_size", BIGINT, "Total virtual memory size"),
    Column("start_time", BIGINT,
        "Process start in seconds since boot (non-sleeping)"),
    Column("parent", BIGINT, "Process parent's PID"),
    Column("pgroup", BIGINT, "Process group"),
    Column("threads", INTEGER, "Number of threads used by process"),
    Column("nice", INTEGER, "Process nice level (-20 to 20, default 0)"),
    Column("user", TEXT, "User name"),
    Column("time", TEXT, "Cumulative CPU time. [DD-]HH:MM:SS format"),
    Column("cpu", DOUBLE, "CPU utilization as percentage"),
    Column("mem", DOUBLE, "Memory utilization as percentage")
])
implementation("applications/docker@genContainerProcesses")
examples([
  "select * from docker_container_processes where id = '1234567890abcdef'",
  "select * from docker_container_processes where id = '11b2399e1426d906e62a0c357650e363426d6c56dbe2f35cbaa9b452250e3355'"
])


#posix
table_name("docker_container_stats")
description("Docker container statistics. Queries on this table take at least one second.")
schema([
    Column("id", TEXT, "Container ID", index=True, required=True),
    Column("name", TEXT, "Container name", index=True),
    Column("pids", INTEGER, "Number of processes"),
    Column("read", BIGINT, "UNIX time when stats were read"),
    Column("preread", BIGINT, "UNIX time when stats were last read"),
    Column("interval", BIGINT, "Difference between read and preread in nano-seconds"),
    Column("disk_read", BIGINT, "Total disk read bytes"),
    Column("disk_write", BIGINT, "Total disk write bytes"),
    Column("num_procs", INTEGER, "Number of processors"),
    Column("cpu_total_usage", BIGINT, "Total CPU usage"),
    Column("cpu_kernelmode_usage", BIGINT, "CPU kernel mode usage"),
    Column("cpu_usermode_usage", BIGINT, "CPU user mode usage"),
    Column("system_cpu_usage", BIGINT, "CPU system usage"),
    Column("online_cpus", INTEGER, "Online CPUs"),
    Column("pre_cpu_total_usage", BIGINT, "Last read total CPU usage"),
    Column("pre_cpu_kernelmode_usage", BIGINT, "Last read CPU kernel mode usage"),
    Column("pre_cpu_usermode_usage", BIGINT, "Last read CPU user mode usage"),
    Column("pre_system_cpu_usage", BIGINT, "Last read CPU system usage"),
    Column("pre_online_cpus", INTEGER, "Last read online CPUs"),
    Column("memory_usage", BIGINT, "Memory usage"),
    Column("memory_cached", BIGINT, "Memory cached"),
    Column("memory_inactive_file", BIGINT, "Memory inactive file"),
    Column("memory_total_inactive_file", BIGINT, "Memory total inactive file"),
    Column("memory_max_usage", BIGINT, "Memory maximum usage"),
    Column("memory_limit", BIGINT, "Memory limit"),
    Column("network_rx_bytes", BIGINT, "Total network bytes read"),
    Column("network_tx_bytes", BIGINT, "Total network bytes transmitted")
])
implementation("applications/docker@genContainerStats")
examples([
  "select * from docker_container_stats where id = 'de8cfdc74c850967'",
  "select * from docker_container_stats where id = 'de8cfdc74c850967fd3832e128f4d12e2d5476a4aea282734bfb7e57f66fce2f'"
])


#posix
table_name("docker_containers")
description("Docker containers information.")
schema([
    Column("id", TEXT, "Container ID", index=True),
    Column("name", TEXT, "Container name", index=True),
    Column("image", TEXT, "Docker image (name) used to launch this container"),
    Column("image_id", TEXT, "Docker image ID"),
    Column("command", TEXT, "Command with arguments"),
    Column("created", BIGINT, "Time of creation as UNIX time"),
    Column("state", TEXT, "Container state (created, restarting, running, removing, paused, exited, dead)"),
    Column("status", TEXT, "Container status information"),
    Column("pid", BIGINT, "Identifier of the initial process"),
    Column("path", TEXT, "Container path"),
    Column("config_entrypoint", TEXT, "Container entrypoint(s)"),
    Column("started_at", TEXT, "Container start time as string"),
    Column("finished_at", TEXT, "Container finish time as string"),
    Column("privileged", INTEGER, "Is the container privileged"),
    Column("security_options", TEXT, "List of container security options"),
    Column("env_variables", TEXT, "Container environmental variables"),
    Column("readonly_rootfs", INTEGER, "Is the root filesystem mounted as read only"),
])
extended_schema(LINUX, [
    Column("cgroup_namespace", TEXT, "cgroup namespace"),
    Column("ipc_namespace", TEXT, "IPC namespace"),
    Column("mnt_namespace", TEXT, "Mount namespace"),
    Column("net_namespace", TEXT, "Network namespace"),
    Column("pid_namespace", TEXT, "PID namespace"),
    Column("user_namespace", TEXT, "User namespace"),
    Column("uts_namespace", TEXT, "UTS namespace")
])
implementation("applications/docker@genContainers")
examples([
  "select * from docker_containers where id = '11b2399e1426d906e62a0c357650e363426d6c56dbe2f35cbaa9b452250e3355'",
  "select * from docker_containers where name = '/hello'"
])


#posix
table_name("docker_image_history")
description("Docker image history information.")
schema([
    Column("id", TEXT, "Image ID", index=True),
    Column("created", BIGINT, "Time of creation as UNIX time"),
    Column("size", BIGINT, "Size of instruction in bytes"),
    Column("created_by", TEXT, "Created by instruction"),
    Column("tags", TEXT, "Comma-separated list of tags"),
    Column("comment", TEXT, "Instruction comment")
])
implementation("applications/docker@genImageHistory")
examples([
  "select * from docker_image_history",
  "select * from docker_image_history where id = '6a2f32de169d'",
  "select * from docker_image_history where id = '6a2f32de169d14e6f8a84538eaa28f2629872d7d4f580a303b296c60db36fbd7'"
])


#posix
table_name("docker_image_labels")
description("Docker image labels.")
schema([
    Column("id", TEXT, "Image ID", index=True),
    Column("key", TEXT, "Label key"),
    Column("value", TEXT, "Optional label value")
])
implementation("applications/docker@genImageLabels")
examples([
  "select * from docker_image_labels",
  "select * from docker_image_labels where id = '1234567890abcdef'",
  "select * from docker_image_labels where id = '11b2399e1426d906e62a0c357650e363426d6c56dbe2f35cbaa9b452250e3355'"
])

#posix
table_name("docker_image_layers")
description("Docker image layers information.")
schema([
    Column("id", TEXT, "Image ID", index=True),
    Column("layer_id", TEXT, "Layer ID"),
    Column("layer_order", INTEGER, "Layer Order (1 = base layer)")
])
implementation("applications/docker@genImageLayers")
examples([
  "select * from docker_images",
  "select * from docker_images where id = '6a2f32de169d'",
  "select * from docker_images where id = '6a2f32de169d14e6f8a84538eaa28f2629872d7d4f580a303b296c60db36fbd7'"
])


#posix
table_name("docker_images")
description("Docker images information.")
schema([
    Column("id", TEXT, "Image ID"),
    Column("created", BIGINT, "Time of creation as UNIX time"),
    Column("size_bytes", BIGINT, "Size of image in bytes"),
    Column("tags", TEXT, "Comma-separated list of repository tags")
])
implementation("applications/docker@genImages")
examples([
  "select * from docker_images",
  "select * from docker_images where id = '6a2f32de169d'",
  "select * from docker_images where id = '6a2f32de169d14e6f8a84538eaa28f2629872d7d4f580a303b296c60db36fbd7'"
])

#posix
table_name("docker_info")
description("Docker system information.")
schema([
    Column("id", TEXT, "Docker system ID"),
    Column("containers", INTEGER, "Total number of containers"),
    Column("containers_running", INTEGER, "Number of containers currently running"),
    Column("containers_paused", INTEGER, "Number of containers in paused state"),
    Column("containers_stopped", INTEGER, "Number of containers in stopped state"),
    Column("images", INTEGER, "Number of images"),
    Column("storage_driver", TEXT, "Storage driver"),
    Column("memory_limit", INTEGER, "1 if memory limit support is enabled. 0 otherwise"),
    Column("swap_limit", INTEGER, "1 if swap limit support is enabled. 0 otherwise"),
    Column("kernel_memory", INTEGER, "1 if kernel memory limit support is enabled. 0 otherwise"),
    Column("cpu_cfs_period", INTEGER, "1 if CPU Completely Fair Scheduler (CFS) period support is enabled. 0 otherwise"),
    Column("cpu_cfs_quota", INTEGER, "1 if CPU Completely Fair Scheduler (CFS) quota support is enabled. 0 otherwise"),
    Column("cpu_shares", INTEGER, "1 if CPU share weighting support is enabled. 0 otherwise"),
    Column("cpu_set", INTEGER, "1 if CPU set selection support is enabled. 0 otherwise"),
    Column("ipv4_forwarding", INTEGER, "1 if IPv4 forwarding is enabled. 0 otherwise"),
    Column("bridge_nf_iptables", INTEGER, "1 if bridge netfilter iptables is enabled. 0 otherwise"),
    Column("bridge_nf_ip6tables", INTEGER, "1 if bridge netfilter ip6tables is enabled. 0 otherwise"),
    Column("oom_kill_disable", INTEGER, "1 if Out-of-memory kill is disabled. 0 otherwise"),
    Column("logging_driver", TEXT, "Logging driver"),
    Column("cgroup_driver", TEXT, "Control groups driver"),
    Column("kernel_version", TEXT, "Kernel version", collate="version"),
    Column("os", TEXT, "Operating system"),
    Column("os_type", TEXT, "Operating system type"),
    Column("architecture", TEXT, "Hardware architecture"),
    Column("cpus", INTEGER, "Number of CPUs"),
    Column("memory", BIGINT, "Total memory"),
    Column("http_proxy", TEXT, "HTTP proxy"),
    Column("https_proxy", TEXT, "HTTPS proxy"),
    Column("no_proxy", TEXT, "Comma-separated list of domain extensions proxy should not be used for"),
    Column("name", TEXT, "Name of the docker host"),
    Column("server_version", TEXT, "Server version", collate="version"),
    Column("root_dir", TEXT, "Docker root directory")
])
attributes(cacheable=True)
implementation("applications/docker@genInfo")
examples([
  "select * from docker_info"
])

#posix
table_name("docker_network_labels")
description("Docker network labels.")
schema([
    Column("id", TEXT, "Network ID", index=True),
    Column("key", TEXT, "Label key"),
    Column("value", TEXT, "Optional label value")
])
implementation("applications/docker@genNetworkLabels")
examples([
  "select * from docker_network_labels",
  "select * from docker_network_labels where id = '1234567890abcdef'",
  "select * from docker_network_labels where id = '11b2399e1426d906e62a0c357650e363426d6c56dbe2f35cbaa9b452250e3355'"
])

#posix
table_name("docker_networks")
description("Docker networks information.")
schema([
    Column("id", TEXT, "Network ID", index=True),
    Column("name", TEXT, "Network name"),
    Column("driver", TEXT, "Network driver"),
    Column("created", BIGINT, "Time of creation as UNIX time"),
    Column("enable_ipv6", INTEGER, "1 if IPv6 is enabled on this network. 0 otherwise"),
    Column("subnet", TEXT, "Network subnet"),
    Column("gateway", TEXT, "Network gateway")
])
implementation("applications/docker@genNetworks")
examples([
  "select * from docker_networks",
  "select * from docker_networks where id = 'cfd2ffd49439'",
  "select * from docker_networks where id = 'cfd2ffd494395b75d77539761df40cde06a2b6b497e0c9c1adc6c5a79539bfad'"
])

#posix
table_name("docker_version")
description("Docker version information.")
schema([
    Column("version", TEXT, "Docker version", collate="version"),
    Column("api_version", TEXT, "API version", collate="version"),
    Column("min_api_version", TEXT, "Minimum API version supported", collate="version"),
    Column("git_commit", TEXT, "Docker build git commit"),
    Column("go_version", TEXT, "Go version", collate="version"),
    Column("os", TEXT, "Operating system"),
    Column("arch", TEXT, "Hardware architecture"),
    Column("kernel_version", TEXT, "Kernel version", collate="version"),
    Column("build_time", TEXT, "Build time")
])
attributes(cacheable=True)
implementation("applications/docker@genVersion")
examples([
  "select version from docker_version"
])

#posix
table_name("docker_volume_labels")
description("Docker volume labels.")
schema([
    Column("name", TEXT, "Volume name", index=True),
    Column("key", TEXT, "Label key", index=True),
    Column("value", TEXT, "Optional label value")
])
implementation("applications/docker@genVolumeLabels")
examples([
  "select * from docker_volume_labels",
  "select * from docker_volume_labels where name = 'btrfs'"
])


#posix
table_name("docker_volumes")
description("Docker volumes information.")
schema([
    Column("name", TEXT, "Volume name", index=True),
    Column("driver", TEXT, "Volume driver"),
    Column("mount_point", TEXT, "Mount point"),
    Column("type", TEXT, "Volume type")
])
implementation("applications/docker@genVolumes")
examples([
  "select * from docker_volumes",
  "select * from docker_volumes where name = 'btrfs'"
])


#posix
table_name("extended_attributes")
description("Returns the extended attributes for files (similar to Windows ADS).")
schema([
    Column("path", TEXT, "Absolute file path", required=True, optimized=True),
    Column("directory", TEXT, "Directory of file(s)", required=True, optimized=True),
    Column("key", TEXT, "Name of the value generated from the extended attribute"),
    Column("value", TEXT, "The parsed information from the attribute"),
    Column("base64", INTEGER, "1 if the value is base64 encoded else 0"),
])
implementation("extended_attributes@genXattr")


#posix
table_name("file_events")
description("Track time/action changes to files specified in configuration data.")
schema([
    Column("target_path", TEXT, "The path associated with the event"),
    Column("category", TEXT, "The category of the file defined in the config"),
    Column("action", TEXT, "Change action (UPDATE, REMOVE, etc)"),
    Column("transaction_id", BIGINT, "ID used during bulk update"),
    Column("inode", BIGINT, "Filesystem inode number"),
    Column("uid", BIGINT, "Owning user ID"),
    Column("gid", BIGINT, "Owning group ID"),
    Column("mode", TEXT, "Permission bits"),
    Column("size", BIGINT, "Size of file in bytes"),
    Column("atime", BIGINT, "Last access time"),
    Column("mtime", BIGINT, "Last modification time"),
    Column("ctime", BIGINT, "Last status change time"),
    Column("md5", TEXT, "The MD5 of the file after change"),
    Column("sha1", TEXT, "The SHA1 of the file after change"),
    Column("sha256", TEXT, "The SHA256 of the file after change"),
    Column("hashed", INTEGER,
      "1 if the file was hashed, 0 if not, -1 if hashing failed"),
    Column("time", BIGINT, "Time of file event", additional=True),
    Column("eid", TEXT, "Event ID", hidden=True),
])
attributes(event_subscriber=True)
implementation("file_events@file_events::genTable")


#posix
table_name("hardware_events")
description("Hardware (PCI/USB/HID) events from UDEV or IOKit.")
schema([
    Column("action", TEXT, "Remove, insert, change properties, etc"),
    Column("path", TEXT, "Local device path assigned (optional)"),
    Column("type", TEXT, "Type of hardware and hardware event"),
    Column("driver", TEXT, "Driver claiming the device"),
    Column("vendor", TEXT, "Hardware device vendor"),
    Column("vendor_id", TEXT, "Hex encoded Hardware vendor identifier"),
    Column("model", TEXT, "Hardware device model"),
    Column("model_id", TEXT, "Hex encoded Hardware model identifier"),
    Column("serial", TEXT, "Device serial (optional)"),
    Column("revision", TEXT, "Device revision (optional)"),
    Column("time", BIGINT, "Time of hardware event", additional=True),
    Column("eid", TEXT, "Event ID", hidden=True),
])
attributes(event_subscriber=True)
implementation("events/hardware_events@hardware_events::genTable")


#posix
table_name("interface_ipv6")
description("IPv6 configuration and stats of network interfaces.")
schema([
    Column("interface", TEXT, "Interface name"),
    Column("hop_limit", INTEGER, "Current Hop Limit"),
    Column("forwarding_enabled", INTEGER, "Enable IP forwarding"),
    Column("redirect_accept", INTEGER, "Accept ICMP redirect messages"),
    Column("rtadv_accept", INTEGER, "Accept ICMP Router Advertisement"),
])
implementation("networking/interface_ip@genInterfaceIpv6")
fuzz_paths([
    "/proc/sys/net/ipv6/conf",
])


#posix
table_name("known_hosts")
description("A line-delimited known_hosts table.")
schema([
    Column("uid", BIGINT, "The local user that owns the known_hosts file", index=True, optimized=True),
    Column("key", TEXT, "parsed authorized keys line"),
    Column("key_file", TEXT, "Path to known_hosts file"),
    ForeignKey(column="uid", table="users"),
])
attributes(user_data=True, no_pkey=True)
implementation("known_hosts@getKnownHostsKeys")
examples([
    "select * from users join known_hosts using (uid)",
])
fuzz_paths([
    "/home",
    "/Users",
])


#posix
table_name("last")
description("System logins and logouts.")
schema([
    Column("username", TEXT, "Entry username"),
    Column("tty", TEXT, "Entry terminal"),
    Column("pid", INTEGER, "Process (or thread) ID"),
    Column("type", INTEGER, "Entry type, according to ut_type types (utmp.h)"),
    Column("type_name", TEXT, "Entry type name, according to ut_type types (utmp.h)"),
    Column("time", INTEGER, "Entry timestamp"),
    Column("host", TEXT, "Entry hostname"),
])
attributes(cacheable=True)
implementation("last@genLastAccess")
fuzz_paths([
    "/var/log/wtmpx",
])


#posix
table_name("load_average")
description("Displays information about the system wide load averages.")
schema([
    Column("period", TEXT, "Period over which the average is calculated."),
    Column("average", TEXT, "Load average over the specified period."),
])
implementation("load_average@genLoadAverage")
examples([
  "select * from load_average;",
])


#posix
table_name("magic")
description("Magic number recognition library table.")
schema([
    Column("path", TEXT, "Absolute path to target file", required=True, index=True),
    Column("magic_db_files", TEXT, "Colon(:) separated list of files where the magic db file can be found. By default one of the following is used: /usr/share/file/magic/magic, /usr/share/misc/magic or /usr/share/misc/magic.mgc", additional=True),
    Column("data", TEXT, "Magic number data from libmagic"),
    Column("mime_type", TEXT, "MIME type data from libmagic"),
    Column("mime_encoding", TEXT, "MIME encoding data from libmagic"),
])
implementation("system/magic@genMagicData")


#posix
table_name("memory_array_mapped_addresses")
description("Data associated for address mapping of physical memory arrays.")
schema([
    Column("handle",  TEXT, "Handle, or instance number, associated with the structure"),
    Column("memory_array_handle", TEXT,
      "Handle of the memory array associated with this structure"),
    Column("starting_address",  TEXT,
      "Physical stating address, in kilobytes, of a range of memory mapped to physical memory array"),
    Column("ending_address", TEXT,
      "Physical ending address of last kilobyte of a range of memory mapped to physical memory array"),
    Column("partition_width", INTEGER,
      "Number of memory devices that form a single row of memory for the address partition of this structure"),
])

implementation("smbios_tables@genMemoryArrayMappedAddresses")


#posix
table_name("memory_arrays")
description("Data associated with collection of memory devices that operate to form a memory address.")
schema([
    Column("handle",  TEXT, "Handle, or instance number, associated with the array"),
    Column("location",  TEXT, "Physical location of the memory array"),
    Column("use", TEXT, "Function for which the array is used"),
    Column("memory_error_correction", TEXT,
      "Primary hardware error correction or detection method supported"),
    Column("max_capacity", INTEGER, "Maximum capacity of array in gigabytes"),
    Column("memory_error_info_handle", TEXT,
      "Handle, or instance number, associated with any error that was detected for the array"),
    Column("number_memory_devices", INTEGER, "Number of memory devices on array"),
])

implementation("smbios_tables@genMemoryArrays")


#posix
table_name("memory_device_mapped_addresses")
description("Data associated for address mapping of physical memory devices.")
schema([
    Column("handle",  TEXT, "Handle, or instance number, associated with the structure"),
    Column("memory_device_handle", TEXT,
      "Handle of the memory device structure associated with this structure"),
    Column("memory_array_mapped_address_handle", TEXT,
      "Handle of the memory array mapped address to which this device range is mapped to"),
    Column("starting_address",  TEXT,
      "Physical stating address, in kilobytes, of a range of memory mapped to physical memory array"),
    Column("ending_address", TEXT,
      "Physical ending address of last kilobyte of a range of memory mapped to physical memory array"),
    Column("partition_row_position", INTEGER,
      "Identifies the position of the referenced memory device in a row of the address partition"),
    Column("interleave_position", INTEGER,
      "The position of the device in a interleave, i.e. 0 indicates non-interleave, 1 indicates 1st interleave, 2 indicates 2nd interleave, etc."),
    Column("interleave_data_depth", INTEGER,
      "The max number of consecutive rows from memory device that are accessed in a single interleave transfer; 0 indicates device is non-interleave"),
])

implementation("smbios_tables@genMemoryDeviceMappedAddresses")


#posix
table_name("memory_error_info")
description("Data associated with errors of a physical memory array.")
schema([
    Column("handle",  TEXT, "Handle, or instance number, associated with the structure"),
    Column("error_type",  TEXT,
      "type of error associated with current error status for array or device"),
    Column("error_granularity", TEXT,
      "Granularity to which the error can be resolved"),
    Column("error_operation", TEXT,
      "Memory access operation that caused the error"),
    Column("vendor_syndrome", TEXT,
      "Vendor specific ECC syndrome or CRC data associated with the erroneous access"),
    Column("memory_array_error_address", TEXT,
      "32 bit physical address of the error based on the addressing of the bus to which the memory array is connected"),
    Column("device_error_address", TEXT,
        "32 bit physical address of the error relative to the start of the failing memory address, in bytes"),
    Column("error_resolution", TEXT,
      "Range, in bytes, within which this error can be determined, when an error address is given"),
])

implementation("smbios_tables@genMemoryErrorInfo")


#posix
table_name("mounts")
description("System mounted devices and filesystems (not process specific).")
schema([
	Column("device", TEXT, "Mounted device"),
	Column("device_alias", TEXT, "Mounted device alias"),
	Column("path", TEXT, "Mounted device path"),
	Column("type", TEXT, "Mounted device type"),
	Column("blocks_size", BIGINT, "Block size in bytes"),
	Column("blocks", BIGINT, "Mounted device used blocks"),
	Column("blocks_free", BIGINT, "Mounted device blocks available to root users, a superset of blocks_available"),
	Column("blocks_available", BIGINT, "Mounted device blocks available to non-root users"),
	Column("inodes", BIGINT, "Mounted device used inodes"),
	Column("inodes_free", BIGINT, "Mounted device free inodes"),
	Column("flags", TEXT, "Mounted device flags"),
])
implementation("mounts@genMounts")
fuzz_paths([
    "/proc/mounts",
])


#posix
table_name("oem_strings")
description("OEM defined strings retrieved from SMBIOS.")
schema([
    Column("handle", TEXT, "Handle, or instance number, associated with the Type 11 structure"),
    Column("number", INTEGER, "The string index of the structure"),
    Column("value", TEXT, "The value of the OEM string"),
])

implementation("smbios_tables@genOEMStrings")


#posix
table_name("pci_devices")
description("PCI devices active on the host system.")
schema([
    Column("pci_slot", TEXT, "PCI Device used slot"),
    Column("pci_class", TEXT, "PCI Device class"),
    Column("driver", TEXT, "PCI Device used driver"),
    Column("vendor", TEXT, "PCI Device vendor"),
    Column("vendor_id", TEXT, "Hex encoded PCI Device vendor identifier"),
    Column("model", TEXT, "PCI Device model"),
    Column("model_id", TEXT, "Hex encoded PCI Device model identifier"),

    # Optional columns
    #Column("subsystem", TEXT, "PCI Device subsystem"),
    #Column("express", INTEGER, "1 If PCI device is express else 0"),
    #Column("thunderbolt", INTEGER, "1 If PCI device is thunderbolt else 0"),
    #Column("removable", INTEGER, "1 If PCI device is removable else 0"),
])

extended_schema(LINUX, [
    Column("pci_class_id", TEXT, "PCI Device class ID in hex format"),
    Column("pci_subclass_id", TEXT, "PCI Device  subclass in hex format"),
    Column("pci_subclass", TEXT, "PCI Device subclass"),
    Column("subsystem_vendor_id", TEXT, "Vendor ID of PCI device subsystem"),
    Column("subsystem_vendor", TEXT, "Vendor of PCI device subsystem"),
    Column("subsystem_model_id", TEXT, "Model ID of PCI device subsystem"),
    Column("subsystem_model", TEXT, "Device description of PCI device subsystem"),
])

implementation("pci_devices@genPCIDevices")


#posix
table_name("process_envs")
description("A key/value table of environment variables for each process.")
schema([
    Column("pid", INTEGER, "Process (or thread) ID", index=True, optimized=True),
    Column("key", TEXT, "Environment variable name"),
    Column("value", TEXT, "Environment variable value"),
])
implementation("system/processes@genProcessEnvs")
examples([
  "select * from process_envs where pid = 1",
  '''select pe.*
     from process_envs pe, (select * from processes limit 10) p
     where p.pid = pe.pid;'''
])


#posix
table_name("process_events")
description("Track time/action process executions.")
schema([
    Column("pid", BIGINT, "Process (or thread) ID"),
    Column("path", TEXT, "Path of executed file"),
    Column("mode", TEXT, "File mode permissions"),
    Column("cmdline", TEXT, "Command line arguments (argv)"),
    Column("cmdline_size", BIGINT, "Actual size (bytes) of command line arguments",
        hidden=True),
    Column("env", TEXT, "Environment variables delimited by spaces",
        aliases=["environment"], hidden=True),
    Column("env_count", BIGINT, "Number of environment variables",
        aliases=["environment_count"], hidden=True),
    Column("env_size", BIGINT, "Actual size (bytes) of environment list",
        aliases=["environment_size"], hidden=True),
    Column("cwd", TEXT, "The process current working directory"),
    Column("auid", BIGINT, "Audit User ID at process start"),
    Column("uid", BIGINT, "User ID at process start"),
    Column("euid", BIGINT, "Effective user ID at process start"),
    Column("gid", BIGINT, "Group ID at process start"),
    Column("egid", BIGINT, "Effective group ID at process start"),
    Column("owner_uid", BIGINT, "File owner user ID"),
    Column("owner_gid", BIGINT, "File owner group ID"),
    Column("atime", BIGINT, "File last access in UNIX time",
        aliases=["access_time"]),
    Column("mtime", BIGINT, "File modification in UNIX time",
        aliases=["modify_time"]),
    Column("ctime", BIGINT, "File last metadata change in UNIX time",
        aliases=["change_time"]),
    Column("btime", BIGINT, "File creation in UNIX time",
        aliases=["create_time"]),
    Column("overflows", TEXT, "List of structures that overflowed", hidden=True),
    Column("parent", BIGINT, "Process parent's PID, or -1 if cannot be determined."),
    Column("time", BIGINT, "Time of execution in UNIX time", additional=True),
    Column("uptime", BIGINT, "Time of execution in system uptime"),
    Column("eid", TEXT, "Event ID", hidden=True),
])
extended_schema(DARWIN, [
    Column("status", BIGINT, "OpenBSM Attribute: Status of the process"),
])
extended_schema(LINUX, [
    Column("fsuid", BIGINT, "Filesystem user ID at process start"),
    Column("suid", BIGINT, "Saved user ID at process start"),
    Column("fsgid", BIGINT, "Filesystem group ID at process start"),
    Column("sgid", BIGINT, "Saved group ID at process start"),
    Column("syscall", TEXT, "Syscall name: fork, vfork, clone, execve, execveat"),
])
attributes(event_subscriber=True)
implementation("process_events@process_events::genTable")


#posix
table_name("process_open_files")
description("File descriptors for each process.")
schema([
    Column("pid", BIGINT, "Process (or thread) ID", index=True),
    Column("fd", BIGINT, "Process-specific file descriptor number"),
    Column("path", TEXT, "Filesystem path of descriptor"),
])
implementation("system/process_open_files@genOpenFiles")
examples([
  "select * from process_open_files where pid = 1",
])


#posix
table_name("prometheus_metrics")
description("Retrieve metrics from a Prometheus server.")
schema([
    Column("target_name", TEXT, "Address of prometheus target"),
    Column("metric_name", TEXT, "Name of collected Prometheus metric"),
    Column("metric_value", DOUBLE, "Value of collected Prometheus metric"),
    Column("timestamp_ms", BIGINT, "Unix timestamp of collected data in MS"),
])
implementation("applications/prometheus_metrics@genPrometheusMetrics")


#posix
table_name("shell_history")
description("A line-delimited (command) table of per-user .*_history data.")
schema([
    Column("uid", BIGINT, "Shell history owner", additional=True, optimized=True),
    Column("time", INTEGER, "Entry timestamp. It could be absent, default value is 0."),
    Column("command", TEXT, "Unparsed date/line/command history line"),
    Column("history_file", TEXT, "Path to the .*_history for this user"),
    ForeignKey(column="uid", table="users"),
])
attributes(user_data=True, no_pkey=True)
implementation("shell_history@genShellHistory", generator=True)
examples([
    "select * from users join shell_history using (uid)",
])
fuzz_paths([
    "/home",
    "/Users",
])


#posix
table_name("smbios_tables")
description("BIOS (DMI) structure common details and content.")
schema([
    Column("number", INTEGER, "Table entry number"),
    Column("type", INTEGER, "Table entry type"),
    Column("description", TEXT, "Table entry description"),
    Column("handle", INTEGER, "Table entry handle"),
    Column("header_size", INTEGER, "Header size in bytes"),
    Column("size", INTEGER, "Table entry size in bytes"),
    Column("md5", TEXT, "MD5 hash of table entry"),
])
implementation("system/smbios_tables@genSMBIOSTables")
fuzz_paths([
    "/sys/firmware/efi/systab",
])


#posix
table_name("socket_events")
description("Track network socket bind, connect, and accepts.")
schema([
    Column("action", TEXT, "The socket action (bind, connect, accept)"),
    Column("pid", BIGINT, "Process (or thread) ID"),
    Column("path", TEXT, "Path of executed file"),
    Column("fd", TEXT, "The file description for the process socket"),
    Column("auid", BIGINT, "Audit User ID"),
    Column("family", INTEGER, "The Internet protocol family ID"),
    Column("protocol", INTEGER, "The network protocol ID",
        hidden=True),
    Column("local_address", TEXT, "Local address associated with socket"),
    Column("remote_address", TEXT, "Remote address associated with socket"),
    Column("local_port", INTEGER, "Local network protocol port number"),
    Column("remote_port", INTEGER, "Remote network protocol port number"),
    Column("socket", TEXT, "The local path (UNIX domain socket only)",
        hidden=True),
    Column("time", BIGINT, "Time of execution in UNIX time", additional=True),
    Column("uptime", BIGINT, "Time of execution in system uptime"),
    Column("eid", TEXT, "Event ID", hidden=True),
    Column("success", INTEGER, "Deprecated. Use the 'status' column instead", hidden=True),
])
extended_schema(LINUX, [
        Column("status", TEXT, "Either 'succeeded', 'failed', 'in_progress' (connect() on non-blocking socket) or 'no_client' (null accept() on non-blocking socket)"),
])
attributes(event_subscriber=True)
implementation("socket_events@socket_events::genTable")


#posix
table_name("sudoers")
description("Rules for running commands as other users via sudo.")
schema([
    Column("source", TEXT, "Source file containing the given rule"),
    Column("header", TEXT, "Symbol for given rule"),
    Column("rule_details", TEXT, "Rule definition")
])
implementation("sudoers@genSudoers")


#posix
table_name("suid_bin")
description("suid binaries in common locations.")
schema([
    Column("path", TEXT, "Binary path"),
    Column("username", TEXT, "Binary owner username"),
    Column("groupname", TEXT, "Binary owner group"),
    Column("permissions", TEXT, "Binary permissions"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
attributes(cacheable=True)
implementation("suid_bin@genSuidBin")


#posix
table_name("system_controls")
description("sysctl names, values, and settings information.")
schema([
    Column("name", TEXT, "Full sysctl MIB name", index=True),
    Column("oid", TEXT, "Control MIB", additional=True),
    Column("subsystem", TEXT, "Subsystem ID, control type", additional=True),
    Column("current_value", TEXT, "Value of setting"),
    Column("config_value", TEXT, "The MIB value set in /etc/sysctl.conf"),
    Column("type", TEXT, "Data type"),
])
extended_schema(DARWIN, [
    Column("field_name", TEXT, "Specific attribute of opaque type"),
])

implementation("system_controls@genSystemControls")
fuzz_paths([
    "/run/sysctl.d/",
    "/usr/lib/sysctl.d/",
    "/lib/sysctl.d/",
    "/sys"
])


#posix
table_name("ulimit_info")
description("System resource usage limits.")
schema([
    Column("type", TEXT, "System resource to be limited"),
    Column("soft_limit", TEXT, "Current limit value"),
    Column("hard_limit", TEXT, "Maximum limit value")
])
implementation("ulimit_info@genUlimitInfo")
examples([
  "select * from ulimit_info"
])


#posix
table_name("usb_devices")
description("USB devices that are actively plugged into the host system.")
schema([
    Column("usb_address", INTEGER, "USB Device used address"),
    Column("usb_port", INTEGER, "USB Device used port"),
    Column("vendor", TEXT, "USB Device vendor string"),
    Column("vendor_id", TEXT, "Hex encoded USB Device vendor identifier"),
    Column("version", TEXT, "USB Device version number"),
    Column("model", TEXT, "USB Device model string"),
    Column("model_id", TEXT, "Hex encoded USB Device model identifier"),
    Column("serial", TEXT, "USB Device serial connection"),
    Column("class", TEXT, "USB Device class"),
    Column("subclass", TEXT, "USB Device subclass"),
    Column("protocol", TEXT, "USB Device protocol"),
    Column("removable", INTEGER, "1 If USB device is removable else 0"),
])
implementation("usb_devices@genUSBDevices")


#posix
table_name("user_events")
description("Track user events from the audit framework.")
schema([
    Column("uid", BIGINT, "User ID"),
    Column("auid", BIGINT, "Audit User ID"),
    Column("pid", BIGINT, "Process (or thread) ID"),
    Column("message", TEXT, "Message from the event"),
    Column("type", INTEGER, "The file description for the process socket"),
    Column("path", TEXT, "Supplied path from event"),
    Column("address", TEXT, "The Internet protocol address or family ID"),
    Column("terminal", TEXT, "The network protocol ID"),
    Column("time", BIGINT, "Time of execution in UNIX time", additional=True),
    Column("uptime", BIGINT, "Time of execution in system uptime"),
    Column("eid", TEXT, "Event ID", hidden=True),
])
attributes(event_subscriber=True)
implementation("user_events@user_events::genTable")


#cross-platform
table_name("process_memory_map")
description("Process memory mapped files and pseudo device/regions.")
schema([
    Column("pid", INTEGER, "Process (or thread) ID", index=True, optimized=True),
    Column("start", TEXT, "Virtual start address (hex)"),
    Column("end", TEXT, "Virtual end address (hex)"),
    Column("permissions", TEXT, "r=read, w=write, x=execute, p=private (cow)"),
    Column("offset", BIGINT, "Offset into mapped path"),
    Column("device", TEXT, "MA:MI Major/minor device ID"),
    Column("inode", INTEGER, "Mapped path inode, 0 means uninitialized (BSS)"),
    Column("path", TEXT, "Path to mapped file or mapped type"),
    Column("pseudo", INTEGER, "1 If path is a pseudo path, else 0"),
])
implementation("processes@genProcessMemoryMap")
examples([
  "select * from process_memory_map where pid = 1",
])


#cross-platform
table_name("process_open_sockets")
description("Processes which have open network sockets on the system.")
schema([
    Column("pid", INTEGER, "Process (or thread) ID", additional=True),
    Column("fd", BIGINT, "Socket file descriptor number"),
    Column("socket", BIGINT, "Socket handle or inode number"),
    Column("family", INTEGER, "Network protocol (IPv4, IPv6)"),
    Column("protocol", INTEGER, "Transport protocol (TCP/UDP)"),
    Column("local_address", TEXT, "Socket local address"),
    Column("remote_address", TEXT, "Socket remote address"),
    Column("local_port", INTEGER, "Socket local port"),
    Column("remote_port", INTEGER, "Socket remote port"),
    Column("path", TEXT, "For UNIX sockets (family=AF_UNIX), the domain path"),
    Column("state", TEXT, "TCP socket state"),
])
extended_schema(LINUX, [
    Column("net_namespace", TEXT, "The inode number of the network namespace"),
])
implementation("system/process_open_sockets@genOpenSockets")
examples([
  "select * from process_open_sockets where pid = 1",
])


#cross-platform
table_name("processes")
description("All running processes on the host system.")
schema([
    Column("pid", BIGINT, "Process (or thread) ID", index=True, optimized=True),
    Column("name", TEXT, "The process path or shorthand argv[0]"),
    Column("path", TEXT, "Path to executed binary"),
    Column("cmdline", TEXT, "Complete argv"),
    Column("state", TEXT, "Process state"),
    Column("cwd", TEXT, "Process current working directory"),
    Column("root", TEXT, "Process virtual root directory"),
    Column("uid", BIGINT, "Unsigned user ID"),
    Column("gid", BIGINT, "Unsigned group ID"),
    Column("euid", BIGINT, "Unsigned effective user ID"),
    Column("egid", BIGINT, "Unsigned effective group ID"),
    Column("suid", BIGINT, "Unsigned saved user ID"),
    Column("sgid", BIGINT, "Unsigned saved group ID"),
    Column("on_disk", INTEGER,
        "The process path exists yes=1, no=0, unknown=-1"),
    Column("wired_size", BIGINT, "Bytes of unpageable memory used by process"),
    Column("resident_size", BIGINT, "Bytes of private memory used by process"),
    Column("total_size", BIGINT, "Total virtual memory size (Linux, Windows) or 'footprint' (macOS)"),
    Column("user_time", BIGINT, "CPU time in milliseconds spent in user space"),
    Column("system_time", BIGINT, "CPU time in milliseconds spent in kernel space"),
    Column("disk_bytes_read", BIGINT, "Bytes read from disk"),
    Column("disk_bytes_written", BIGINT, "Bytes written to disk"),
    Column("start_time", BIGINT, "Process start time in seconds since Epoch, in case of error -1"),
    Column("parent", BIGINT, "Process parent's PID"),
    Column("pgroup", BIGINT, "Process group"),
    Column("threads", INTEGER, "Number of threads used by process"),
    Column("nice", INTEGER, "Process nice level (-20 to 20, default 0)"),
])
extended_schema(WINDOWS, [
    Column("elevated_token", INTEGER, "Process uses elevated token yes=1, no=0"),
    Column("secure_process", INTEGER, "Process is secure (IUM) yes=1, no=0"),
    Column("protection_type", TEXT, "The protection type of the process"),
    Column("virtual_process", INTEGER, "Process is virtual (e.g. System, Registry, vmmem) yes=1, no=0"),
    Column("elapsed_time", BIGINT, "Elapsed time in seconds this process has been running."),
    Column("handle_count", BIGINT, "Total number of handles that the process has open. This number is the sum of the handles currently opened by each thread in the process."),
    Column("percent_processor_time", BIGINT, "Returns elapsed time that all of the threads of this process used the processor to execute instructions in 100 nanoseconds ticks."),
])
extended_schema(DARWIN, [
    Column("upid", BIGINT, "A 64bit pid that is never reused. Returns -1 if we couldn't gather them from the system."),
    Column("uppid", BIGINT, "The 64bit parent pid that is never reused. Returns -1 if we couldn't gather them from the system."),
    Column("cpu_type", INTEGER, "Indicates the specific processor designed for installation."),
    Column("cpu_subtype", INTEGER, "Indicates the specific processor on which an entry may be used."),
    Column("translated", INTEGER, "Indicates whether the process is running under the Rosetta Translation Environment, yes=1, no=0, error=-1."),
])
extended_schema(LINUX, [
    Column("cgroup_path", TEXT, "The full hierarchical path of the process's control group"),
])
attributes(cacheable=True, strongly_typed_rows=True)
implementation("system/processes@genProcesses")
examples([
  "select * from processes where pid = 1",
])


#cross-platform
table_name("python_packages")
description("Python packages installed in a system. NOTE: when querying on windows, even without a users cross join, all user installed python packages will be returned. This special behavior is to not break original functionality.")
schema([
    Column("name", TEXT, "Package display name"),
    Column("uid", BIGINT, "The local user that owns the python package", index=True),
    Column("version", TEXT, "Package-supplied version", collate="version"),
    Column("summary", TEXT, "Package-supplied summary"),
    Column("author", TEXT, "Optional package author"),
    Column("license", TEXT, "License under which package is launched"),
    Column("path", TEXT, "Path at which this module resides"),
    Column("directory", TEXT, "Directory where Python modules are located", index=True, optimized=True),
    ForeignKey(column="uid", table="users"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
attributes(user_data=True)
implementation("system/linux/python_packages@genPythonPackages")
examples([
    "select * from python_packages where directory='/usr/'",
    "select * from users cross join python_packages using (uid)"
])


#cross-platform
table_name("routes")
description("The active route table for the host system.")
schema([
    Column("destination", TEXT, "Destination IP address"),
    Column("netmask", INTEGER, "Netmask length"),
    Column("gateway", TEXT, "Route gateway"),
    Column("source", TEXT, "Route source"),
    Column("flags", INTEGER, "Flags to describe route"),
    Column("interface", TEXT, "Route local interface"),
    Column("mtu", INTEGER, "Maximum Transmission Unit for the route"),
    Column("metric", INTEGER, "Cost of route. Lowest is preferred"),
    Column("type", TEXT, "Type of route", additional=True),
])

extended_schema(POSIX, [
    Column("hopcount", INTEGER, "Max hops expected"),
])
attributes(cacheable=True)
implementation("networking/routes@genRoutes")


#cross-platform
table_name("secureboot")
description("Secure Boot UEFI Settings.")
schema([
    Column("secure_boot", INTEGER, "Whether secure boot is enabled"),
])

extended_schema(DARWIN, [
    Column("secure_mode", INTEGER, "(Intel) Secure mode: 0 disabled, 1 full security, 2 medium security"),
    Column("description", TEXT, "(Apple Silicon) Human-readable description: 'Full Security', 'Reduced Security', or 'Permissive Security'"),
    Column("kernel_extensions", INTEGER, "(Apple Silicon) Allow user management of kernel extensions from identified developers (1 if allowed)"),
    Column("mdm_operations", INTEGER, "(Apple Silicon) Allow remote (MDM) management of kernel extensions and automatic software updates (1 if allowed)"),
])

extended_schema(LINUX + WINDOWS, [
    Column("setup_mode", INTEGER, "Whether setup mode is enabled"),
])

implementation("secureboot@genSecureBoot")
fuzz_paths([
  "/sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data",
  "/sys/firmware/efi/vars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c/data",
])


#sleuthkit
table_name("device_file")
description("Similar to the file table, but use TSK and allow block address access.")
schema([
    Column("device", TEXT, "Absolute file path to device node",
        index=True, required=True),
    Column("partition", TEXT, "A partition number",
        index=True, required=True),
    Column("path", TEXT, "A logical path within the device node",
        additional=True),
    Column("filename", TEXT, "Name portion of file path"),
    Column("inode", BIGINT, "Filesystem inode number", index=True),
    Column("uid", BIGINT, "Owning user ID"),
    Column("gid", BIGINT, "Owning group ID"),
    Column("mode", TEXT, "Permission bits"),
    Column("size", BIGINT, "Size of file in bytes"),
    Column("block_size", INTEGER, "Block size of filesystem"),
    Column("atime", BIGINT, "Last access time"),
    Column("mtime", BIGINT, "Last modification time"),
    Column("ctime", BIGINT, "Creation time"),
    Column("hard_links", INTEGER, "Number of hard links"),
    Column("type", TEXT, "File status"),
])
implementation("forensic/sleuthkit@genDeviceFile")


#sleuthkit
table_name("device_hash")
description("Similar to the hash table, but use TSK and allow block address access.")
schema([
    Column("device", TEXT, "Absolute file path to device node", required=True),
    Column("partition", TEXT, "A partition number", required=True),
    Column("inode", BIGINT, "Filesystem inode number", required=True),
    Column("md5", TEXT, "MD5 hash of provided inode data"),
    Column("sha1", TEXT, "SHA1 hash of provided inode data"),
    Column("sha256", TEXT, "SHA256 hash of provided inode data"),
])
implementation("forensic/sleuthkit@genDeviceHash")


#sleuthkit
table_name("device_partitions")
description("Use TSK to enumerate details about partitions on a disk device.")
schema([
    Column("device", TEXT, "Absolute file path to device node", required=True),
    Column("partition", INTEGER, "A partition number or description"),
    Column("label", TEXT, "The partition name as stored in the partition table"),
    Column("type", TEXT, "Filesystem type if recognized, otherwise, 'meta', 'normal', or 'unallocated'"),
    Column("offset", BIGINT, "Byte offset from the start of the volume"),
    Column("blocks_size", BIGINT, "Byte size of each block"),
    Column("blocks", BIGINT, "Number of blocks"),
    Column("inodes", BIGINT, "Number of meta nodes"),
    Column("flags", INTEGER, "Value that describes the partition (TSK_VS_PART_FLAG_ENUM)"),
])
implementation("forensic/sleuthkit@genDevicePartitions")


#cross-platform
table_name("ssh_configs")
description("A table of parsed ssh_configs.")
schema([
    Column("uid", BIGINT, "The local owner of the ssh_config file", additional=True, optimized=True),
    Column("block",TEXT,"The host or match block"),
    Column("option", TEXT, "The option and value"),
    Column("ssh_config_file", TEXT, "Path to the ssh_config file"),
    ForeignKey(column="uid", table="users"),
])
attributes(user_data=True, no_pkey=True)
implementation("ssh_configs@getSshConfigs")
examples([
  "select * from users join ssh_configs using (uid)",
])
fuzz_paths([
  "/home",
  "/Users",
])


#cross-platform
table_name("startup_items")
description("Applications and binaries set as startup items.")
schema([
    Column("name", TEXT, "Name of startup item"),
    Column("path", TEXT, "Path of startup item"),
    Column("args", TEXT, "Arguments provided to startup executable"),
    Column("type", TEXT, "Type of startup item. On macOS this can be app, agent (LaunchAgent), daemon (LaunchDaemon), login item, or user item."),
    Column("source", TEXT, "Directory containing startup item (on macOS, the subsystem providing it)"),
    Column("status", TEXT, "Startup status. On Linux: enabled or disabled. On macOS: Combination of enabled, allowed, notified, and hidden. Apple does not seem to document these status values, but allowed seems to indicate whether it is enabled in System Settings."),
    Column("username", TEXT, "The user associated with the startup item"),
])
attributes(cacheable=True)
implementation("startup_items@genStartupItems")
fuzz_paths([
    "/System/Library/StartupItems/",
    "/Library/StartupItems/"
])


#cross-platform
table_name("system_info")
description("System information for identification.")
schema([
    Column("hostname", TEXT, "Network hostname including domain"),
    Column("uuid", TEXT, "Unique ID provided by the system"),
    Column("cpu_type", TEXT, "CPU type"),
    Column("cpu_subtype", TEXT, "CPU subtype"),
    Column("cpu_brand", TEXT, "CPU brand string, contains vendor and model"),
    Column("cpu_physical_cores", INTEGER, "Number of physical CPU cores in to the system"),
    Column("cpu_logical_cores", INTEGER, "Number of logical CPU cores available to the system"),
    Column("cpu_sockets", INTEGER, "Number of processor sockets in the system"),
    Column("cpu_microcode", TEXT, "Microcode version"),
    Column("physical_memory", BIGINT, "Total physical memory in bytes"),
    Column("hardware_vendor", TEXT, "Hardware vendor"),
    Column("hardware_model", TEXT, "Hardware model"),
    Column("hardware_version", TEXT, "Hardware version"),
    Column("hardware_serial", TEXT, "Device serial number"),
    Column("board_vendor", TEXT, "Board vendor"),
    Column("board_model", TEXT, "Board model"),
    Column("board_version", TEXT, "Board version"),
    Column("board_serial", TEXT, "Board serial number"),
    Column("computer_name", TEXT, "Friendly computer name (optional)"),
    Column("local_hostname", TEXT, "Local hostname (optional)"),
])
extended_schema(WINDOWS, [
    Column("emulated_cpu_type", TEXT, "Emulated CPU type"),
])
implementation("system/system_info@genSystemInfo")


#cross-platform
table_name("uptime")
description("Track time passed since last boot. Some systems track this as calendar time, some as runtime.")
schema([
    Column("days", INTEGER, "Days of uptime"),
    Column("hours", INTEGER, "Hours of uptime"),
    Column("minutes", INTEGER, "Minutes of uptime"),
    Column("seconds", INTEGER, "Seconds of uptime"),
    Column("total_seconds", BIGINT, "Total uptime seconds"),
])
implementation("system/uptime@genUptime")


#cross-platform
table_name("user_groups")
description("Local system user group relationships.")
schema([
    Column("uid", BIGINT, "User ID", index=True, optimized=True),
    Column("gid", BIGINT, "Group ID", index=True)
])
implementation("user_groups@genUserGroups")


#cross-platform
table_name("user_ssh_keys")
description("Returns the private keys in the users ~/.ssh directory and whether or not they are encrypted.")
schema([
    Column("uid", BIGINT, "The local user that owns the key file", additional=True, optimized=True),
    Column("path", TEXT, "Path to key file", index=True),
    Column("encrypted", INTEGER, "1 if key is encrypted, 0 otherwise"),
    Column("key_type", TEXT, "The type of the private key. One of [rsa, dsa, dh, ec, hmac, cmac], or the empty string."),
    Column("key_group_name", TEXT, "The group of the private key. Supported for a subset of key_types implemented by OpenSSL"),
    Column("key_length", INTEGER, "The cryptographic length of the cryptosystem to which the private key belongs, in bits. Definition of cryptographic length is specific to cryptosystem. -1 if unavailable"),
    Column("key_security_bits", INTEGER, "The number of security bits of the private key, bits of security as defined in NIST SP800-57. -1 if unavailable"),
    ForeignKey(column="uid", table="users"),
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
attributes(user_data=True, no_pkey=True)
implementation("user_ssh_keys@getUserSshKeys")
examples([
    "select * from users join user_ssh_keys using (uid) where encrypted = 0",
])
fuzz_paths([
    "/home",
    "/Users",
])


#cross-platform
table_name("users")
description("Local user accounts (including domain accounts that have logged on locally (Windows)).")
schema([
    Column("uid", BIGINT, "User ID", index=True),
    Column("gid", BIGINT, "Group ID (unsigned)"),
    Column("uid_signed", BIGINT, "User ID as int64 signed (Apple)"),
    Column("gid_signed", BIGINT, "Default group ID as int64 signed (Apple)"),
    Column("username", TEXT, "Username", additional=True),
    Column("description", TEXT, "Optional user description"),
    Column("directory", TEXT, "User's home directory"),
    Column("shell", TEXT, "User's configured default shell"),
    Column("uuid", TEXT, "User's UUID (Apple) or SID (Windows)", index=True),
])
extended_schema(WINDOWS, [
    Column("type", TEXT, "Whether the account is roaming (domain), local, or a system profile"),
])
extended_schema(DARWIN, [
    Column("is_hidden", INTEGER, "IsHidden attribute set in OpenDirectory")
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
extended_schema(LINUX, [
    Column("include_remote", INTEGER, "1 to include remote (LDAP/AD) accounts (default 0). Warning: without any uid/username filtering it may list whole LDAP directories", additional=True, hidden=True),
])
implementation("users@genUsers")
examples([
  "select * from users where uid = 1000",
  "select * from users where username = 'root'",
  "select count(*) from users u, user_groups ug where u.uid = ug.uid",
])


#utility
table_name("file")
description("Interactive filesystem attributes and metadata.")
schema([
    Column("path", TEXT, "Absolute file path", required=True, index=True, optimized=True),
    Column("directory", TEXT, "Directory of file(s)", required=True, optimized=True),
    Column("filename", TEXT, "Name portion of file path"),
    Column("inode", BIGINT, "Filesystem inode number"),
    Column("uid", BIGINT, "Owning user ID"),
    Column("gid", BIGINT, "Owning group ID"),
    Column("mode", TEXT, "Permission bits"),
    Column("device", BIGINT, "Device ID (optional)"),
    Column("size", BIGINT, "Size of file in bytes"),
    Column("block_size", INTEGER, "Block size of filesystem"),
    Column("atime", BIGINT, "Last access time"),
    Column("mtime", BIGINT, "Last modification time"),
    Column("ctime", BIGINT, "Last status change time"),
    Column("btime", BIGINT, "(B)irth or (cr)eate time"),
    Column("hard_links", INTEGER, "Number of hard links"),
    Column("symlink", INTEGER, "1 if the path is a symlink, otherwise 0"),
    Column("type", TEXT, "File status"),
    Column("symlink_target_path", TEXT, "Full path of the symlink target if any")
])
extended_schema(WINDOWS, [
    Column("attributes", TEXT, "File attrib string. See: https://ss64.com/nt/attrib.html"),
    Column("volume_serial", TEXT, "Volume serial number"),
    Column("file_id", TEXT, "file ID"),
    Column("file_version", TEXT, "File version", collate="version"),
    Column("product_version", TEXT, "File product version", collate="version"),
    Column("original_filename", TEXT, "(Executable files only) Original filename"),
    Column("shortcut_target_path", TEXT, "Full path to the file the shortcut points to"),
    Column("shortcut_target_type", TEXT, "Display name for the target type"),
    Column("shortcut_target_location", TEXT, "Folder name where the shortcut target resides"),
    Column("shortcut_start_in", TEXT, "Full path to the working directory to use when executing the shortcut target"),
    Column("shortcut_run", TEXT, "Window mode the target of the shortcut should be run in"),
    Column("shortcut_comment", TEXT, "Comment on the shortcut"),
])
extended_schema(DARWIN, [
    Column("bsd_flags", TEXT, "The BSD file flags (chflags). Possible values: NODUMP, UF_IMMUTABLE, UF_APPEND, OPAQUE, HIDDEN, ARCHIVED, SF_IMMUTABLE, SF_APPEND")
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
    Column("mount_namespace_id", TEXT, "Mount namespace id", hidden=True),
])
attributes(utility=True)
implementation("utility/file@genFile")
examples([
  "select * from file where path = '/etc/passwd'",
  "select * from file where directory = '/etc/'",
  "select * from file where path LIKE '/etc/%'",
])


#utility
table_name("osquery_events")
description("Information about the event publishers and subscribers.")
schema([
    Column("name", TEXT, "Event publisher or subscriber name"),
    Column("publisher", TEXT, "Name of the associated publisher"),
    Column("type", TEXT, "Either publisher or subscriber"),
    Column("subscriptions", INTEGER,
      "Number of subscriptions the publisher received or subscriber used"),
    Column("events", INTEGER,
      "Number of events emitted or received since osquery started"),
    Column("refreshes", INTEGER, "Publisher only: number of runloop restarts"),
    Column("active", INTEGER,
      "1 if the publisher or subscriber is active else 0"),
])
attributes(utility=True)
implementation("osquery@genOsqueryEvents")


#utility
table_name("osquery_extensions")
description("List of active osquery extensions.")
schema([
    Column("uuid", BIGINT, "The transient ID assigned for communication"),
    Column("name", TEXT, "Extension's name"),
    Column("version", TEXT, "Extension's version", collate="version"),
    Column("sdk_version", TEXT, "osquery SDK version used to build the extension", collate="version"),
    Column("path", TEXT, "Path of the extension's Thrift connection or library path"),
    Column("type", TEXT, "SDK extension type: core, extension, or module")
])
attributes(utility=True)
implementation("osquery@genOsqueryExtensions")


#utility
table_name("osquery_flags")
description("Configurable flags that modify osquery's behavior.")
schema([
    Column("name", TEXT, "Flag name"),
    Column("type", TEXT, "Flag type"),
    Column("description", TEXT, "Flag description"),
    Column("default_value", TEXT, "Flag default value"),
    Column("value", TEXT, "Flag value"),
    Column("shell_only", INTEGER, "Is the flag shell only?"),
])
attributes(utility=True)
implementation("osquery@genOsqueryFlags")


#utility
table_name("osquery_info")
description("Top level information about the running version of osquery.")
schema([
    Column("pid", INTEGER, "Process (or thread/handle) ID"),
    Column("uuid", TEXT, "Unique ID provided by the system"),
    Column("instance_id", TEXT, "Unique, long-lived ID per instance of osquery"),
    Column("version", TEXT, "osquery toolkit version", collate="version"),
    Column("config_hash", TEXT, "Hash of the working configuration state"),
    Column("config_valid", INTEGER, "1 if the config was loaded and considered valid, else 0"),
    Column("extensions", TEXT, "osquery extensions status"),
    Column("build_platform", TEXT, "osquery toolkit build platform"),
    Column("build_distro", TEXT, "osquery toolkit platform distribution name (os version)"),
    Column("start_time", INTEGER, "UNIX time in seconds when the process started"),
    Column("watcher", INTEGER, "Process (or thread/handle) ID of optional watcher process"),
    Column("platform_mask", INTEGER, "The osquery platform bitmask"),
])
attributes(utility=True)
implementation("osquery@genOsqueryInfo")


#utility
table_name("osquery_packs")
description("Information about the current query packs that are loaded in osquery.")
schema([
    Column("name", TEXT, "The given name for this query pack"),
    Column("platform", TEXT, "Platforms this query is supported on"),
    Column("version", TEXT, "Minimum osquery version that this query will run on"),
    Column("shard", INTEGER, "Shard restriction limit, 1-100, 0 meaning no restriction"),
    Column("discovery_cache_hits", INTEGER, "The number of times that the discovery query used cached values since the last time the config was reloaded"),
    Column("discovery_executions", INTEGER, "The number of times that the discovery queries have been executed since the last time the config was reloaded"),
    Column("active", INTEGER, "Whether this pack is active (the version, platform and discovery queries match) yes=1, no=0."),
])
attributes(utility=True)
implementation("osquery@genOsqueryPacks")


#utility
table_name("osquery_registry")
description("List the osquery registry plugins.")
schema([
    Column("registry", TEXT, "Name of the osquery registry"),
    Column("name", TEXT, "Name of the plugin item"),
    Column("owner_uuid", INTEGER, "Extension route UUID (0 for core)"),
    Column("internal", INTEGER, "1 If the plugin is internal else 0"),
    Column("active", INTEGER, "1 If this plugin is active else 0"),
])
attributes(utility=True)
implementation("osquery@genOsqueryRegistry")


#utility
table_name("osquery_schedule")
description("Information about the current queries that are scheduled in osquery.")
schema([
    Column("name", TEXT, "The given name for this query"),
    Column("query", TEXT, "The exact query to run"),
    Column("interval", INTEGER,
      "The interval in seconds to run this query, not an exact interval"),
    Column("executions", BIGINT, "Number of times the query was executed"),
    Column("last_executed", BIGINT,
      "UNIX time stamp in seconds of the last completed execution"),
    Column("denylisted", INTEGER, "1 if the query is denylisted else 0",
        aliases=["blacklisted"]), # 'blacklist' now deprecated
    Column("output_size", BIGINT,
      "Cumulative total number of bytes generated by the resultant rows of the query"),
    Column("wall_time", BIGINT, "Total wall time in seconds spent executing (deprecated), hidden=True"),
    Column("wall_time_ms", BIGINT, "Total wall time in milliseconds spent executing"),
    Column("last_wall_time_ms", BIGINT, "Wall time in milliseconds of the latest execution"),
    Column("user_time", BIGINT, "Total user time in milliseconds spent executing"),
    Column("last_user_time", BIGINT, "User time in milliseconds of the latest execution"),
    Column("system_time", BIGINT, "Total system time in milliseconds spent executing"),
    Column("last_system_time", BIGINT, "System time in milliseconds of the latest execution"),
    Column("average_memory", BIGINT, "Average of the bytes of resident memory left allocated after collecting results"),
    Column("last_memory", BIGINT, "Resident memory in bytes left allocated after collecting results of the latest execution"),
])
attributes(utility=True)
implementation("osquery@genOsquerySchedule")


#utility
table_name("time")
description("Track current date and time in UTC.")
schema([
    Column("weekday", TEXT, "Current weekday in UTC"),
    Column("year", INTEGER, "Current year in UTC"),
    Column("month", INTEGER, "Current month in UTC"),
    Column("day", INTEGER, "Current day in UTC"),
    Column("hour", INTEGER, "Current hour in UTC"),
    Column("minutes", INTEGER, "Current minutes in UTC"),
    Column("seconds", INTEGER, "Current seconds in UTC"),
    Column("timezone", TEXT, "Timezone for reported time (hardcoded to UTC)"),
    Column("local_timezone", TEXT, "Current local timezone in of the system"),
    Column("unix_time", INTEGER, "Current UNIX time in UTC"),
    Column("timestamp", TEXT, "Current timestamp (log format) in UTC"),
    Column("datetime", TEXT, "Current date and time (ISO format) in UTC",
        aliases=["date_time"]),
    Column("iso_8601", TEXT, "Current time (ISO format) in UTC"),
])
extended_schema(WINDOWS, [
    Column("win_timestamp", BIGINT, "Timestamp value in 100 nanosecond units"),
])
attributes(utility=True)
implementation("time@genTime")


#cross-platform
table_name("vscode_extensions")
description("Lists all vscode extensions.")
schema([
    Column("name", TEXT, "Extension Name"),
    Column("uuid", TEXT, "Extension UUID"),
    Column("version", TEXT, "Extension version"),
    Column("path", TEXT, "Extension path"),
    Column("publisher", TEXT, "Publisher Name"),
    Column("publisher_id", TEXT, "Publisher ID"),
    Column("installed_at", BIGINT, "Installed Timestamp"),
    Column("prerelease", INTEGER, "Pre release version"),
    Column("uid", BIGINT, "The local user that owns the plugin", additional=True, optimized=True),
    Column("vscode_edition", TEXT, "The VSCode edition (vscode, vscode_insiders, vscodium, vscodium_insiders, cursor, windsurf, trae)")
])
attributes(user_data=True)
implementation("applications/vscode_extensions@genVSCodeExtensions")
examples([
  "select * from vscode_extensions",
])


#windows
table_name("appcompat_shims")
description("Application Compatibility shims are a way to persist malware. This table presents the AppCompat Shim information from the registry in a nice format. See http://files.brucon.org/2015/Tomczak_and_Ballenthin_Shims_for_the_Win.pdf for more details.")
schema([
    Column("executable", TEXT, "Name of the executable that is being shimmed. This is pulled from the registry."),
    Column("path", TEXT, "This is the path to the SDB database."),
    Column("description", TEXT, "Description of the SDB."),
    Column("install_time", INTEGER, "Install time of the SDB"),
    Column("type", TEXT, "Type of the SDB database."),
    Column("sdb_id", TEXT, "Unique GUID of the SDB."),
])
implementation("appcompat_shims@genShims")
examples([
  "select * from appcompat_shims;",
])


#windows
table_name("authenticode")
description("File (executable, bundle, installer, disk) code signing status.")
schema([
    Column("path", TEXT, "Must provide a path or directory", required=True, optimized=True),
    Column("original_program_name", TEXT, "The original program name that the publisher has signed"),
    Column("serial_number", TEXT, "The certificate serial number"),
    Column("issuer_name", TEXT, "The certificate issuer name"),
    Column("subject_name", TEXT, "The certificate subject name"),
    Column("result", TEXT, "The signature check result")
])
implementation("authenticode@genAuthenticode")
examples([
  "SELECT * FROM authenticode WHERE path = 'C:\\Windows\\notepad.exe'",
  ("SELECT process.pid, process.path, signature.result FROM "
   "processes as process LEFT JOIN authenticode AS signature ON "
   "process.path = signature.path;")
])


#windows
table_name("autoexec")
description("Aggregate of executables that will automatically "
	    "execute on the target machine. This is an amalgamation "
	    "of other tables like services, scheduled_tasks, "
	    "startup_items and more.")
schema([
    Column("path", TEXT, "Path to the executable", index=True),
    Column("name", TEXT, "Name of the program"),
    Column("source", TEXT, "Source table of the autoexec item")
])
implementation("autoexec@genAutoexec")


#windows
table_name("background_activities_moderator")
description("Background Activities Moderator (BAM) tracks application execution.")
schema([
	Column("path", TEXT, "Application file path."),
	Column("last_execution_time", BIGINT, "Most recent time application was executed."),
	Column("sid", TEXT, "User SID."),
])
implementation("background_activities_moderator@genBackgroundActivitiesModerator")
examples([
	"select * from background_activities_moderator;",
])

#windows

table_name("bitlocker_info")
description("Retrieve bitlocker status of the machine.")
schema([
  Column("device_id", TEXT, "ID of the encrypted drive."),
  Column("drive_letter", TEXT, "Drive letter of the encrypted drive."),
  Column("persistent_volume_id", TEXT, "Persistent ID of the drive."),
  Column("conversion_status", INTEGER, "The bitlocker conversion status of the drive."),
  Column("protection_status", INTEGER, "The bitlocker protection status of the drive."),
  Column("encryption_method", TEXT, "The encryption type of the device."),
  Column("version", INTEGER, "The FVE metadata version of the drive."),
  Column("percentage_encrypted", INTEGER, "The percentage of the drive that is encrypted."),
  Column("lock_status", INTEGER, "The accessibility status of the drive from Windows."),
])
implementation("bitlocker_info@genBitlockerInfo")


#windows
table_name("chassis_info")
description("Display information pertaining to the chassis and its security status.")
schema([
    Column("audible_alarm", TEXT, "If TRUE, the frame is equipped with an audible alarm."),
    Column("breach_description", TEXT, "If provided, gives a more detailed description of a detected security breach."),
    Column("chassis_types", TEXT, "A comma-separated list of chassis types, such as Desktop or Laptop."),
    Column("description", TEXT, "An extended description of the chassis if available."),
    Column("lock", TEXT, "If TRUE, the frame is equipped with a lock."),
    Column("manufacturer", TEXT, "The manufacturer of the chassis."),
    Column("model", TEXT, "The model of the chassis."),
    Column("security_breach", TEXT, "The physical status of the chassis such as Breach Successful, Breach Attempted, etc."),
    Column("serial", TEXT, "The serial number of the chassis."),
    Column("smbios_tag", TEXT, "The assigned asset tag number of the chassis."),
    Column("sku", TEXT, "The Stock Keeping Unit number if available."),
    Column("status", TEXT, "If available, gives various operational or nonoperational statuses such as OK, Degraded, and Pred Fail."),
    Column("visible_alarm", TEXT, "If TRUE, the frame is equipped with a visual alarm."),
])
implementation("chassis_info@genChassisInfo")
examples([
  "select * from chassis_info",
])


#windows
table_name("chocolatey_packages")
description("Chocolatey packages installed in a system.")
schema([
    Column("name", TEXT, "Package display name"),
    Column("version", TEXT, "Package-supplied version"),
    Column("summary", TEXT, "Package-supplied summary"),
    Column("author", TEXT, "Optional package author"),
    Column("license", TEXT, "License under which package is launched"),
    Column("path", TEXT, "Path at which this package resides")
])
implementation("system/windows/chocolatey_packages@genChocolateyPackages")


#windows
table_name("connectivity")
description("Provides the overall system's network state.")
schema([
    Column("disconnected", INTEGER, "True if the all interfaces are not connected to any network"),
    Column("ipv4_no_traffic", INTEGER, "True if any interface is connected via IPv4, but has seen no traffic"),
    Column("ipv6_no_traffic", INTEGER, "True if any interface is connected via IPv6, but has seen no traffic"),
    Column("ipv4_subnet", INTEGER, "True if any interface is connected to the local subnet via IPv4"),
    Column("ipv4_local_network", INTEGER, "True if any interface is connected to a routed network via IPv4"),
    Column("ipv4_internet", INTEGER, "True if any interface is connected to the Internet via IPv4"),
    Column("ipv6_subnet", INTEGER, "True if any interface is connected to the local subnet via IPv6"),
    Column("ipv6_local_network", INTEGER, "True if any interface is connected to a routed network via IPv6"),
    Column("ipv6_internet", INTEGER, "True if any interface is connected to the Internet via IPv6"),
])
implementation("connectivity@genConnectivity")
examples([
    "select * from connectivity",
    "select ipv4_internet from connectivity",
])


#windows
table_name("default_environment")
description("Default environment variables and values.")
schema([
    Column("variable", TEXT, "Name of the environment variable"),
    Column("value", TEXT, "Value of the environment variable"),
    Column("expand", INTEGER, "1 if the variable needs expanding, 0 otherwise"),
])
implementation("system/windows/default_environment@genDefaultEnvironment")


#windows
table_name("deviceguard_status", aliases=["hvci_status"])
description("Retrieve DeviceGuard info of the machine.")
schema([
  Column("version", TEXT, "The version number of the Device Guard build.", collate="version"),
  Column("instance_identifier", TEXT, "The instance ID of Device Guard."),
  Column("vbs_status", TEXT, "The status of the virtualization based security settings. Returns UNKNOWN if an error is encountered."),
  Column("code_integrity_policy_enforcement_status", TEXT, "The status of the code integrity policy enforcement settings. Returns UNKNOWN if an error is encountered."),
  Column("configured_security_services", TEXT, "The list of configured Device Guard services. Returns UNKNOWN if an error is encountered."),
  Column("running_security_services", TEXT, "The list of running Device Guard services. Returns UNKNOWN if an error is encountered."),
  Column("umci_policy_status", TEXT, "The status of the User Mode Code Integrity security settings. Returns UNKNOWN if an error is encountered."), 
])
implementation("system/windows/deviceguard_status@genDeviceGuardStatus")


#windows
table_name("disk_info")
description("Retrieve basic information about the physical disks of a system.")
schema([
    Column("partitions", INTEGER, "Number of detected partitions on disk."),
    Column("disk_index", INTEGER, "Physical drive number of the disk."),
    Column("type", TEXT, "The interface type of the disk."),
    Column("id", TEXT, "The unique identifier of the drive on the system."),
    Column("pnp_device_id", TEXT, "The unique identifier of the drive on the system."),
    Column("disk_size", BIGINT, "Size of the disk."),
    Column("manufacturer", TEXT, "The manufacturer of the disk."),
    Column("hardware_model", TEXT, "Hard drive model."),
    Column("name", TEXT, "The label of the disk object."),
    Column("serial", TEXT, "The serial number of the disk."),
    Column("description", TEXT, "The OS's description of the disk."),
])
implementation("disk_info@genDiskInfo")

#windows
table_name("dns_cache")
description("Enumerate the DNS cache using the undocumented DnsGetCacheDataTable function in dnsapi.dll.")
schema([
    Column("name", TEXT, "DNS record name"),
    Column("type", TEXT, "DNS record type"),
    Column("flags", INTEGER, "DNS record flags"),
])
implementation("dns_cache@genDnsCache")
examples([
  "select * from dns_cache",
])


#windows
table_name("dns_lookup_events")
description("DNS lookups performed through the Windows DNS stack.")
schema([
    Column("eid", INTEGER, "Event ID", hidden=True),
    Column("time", BIGINT, "Event timestamp in Unix format", hidden=True, additional=True),
    Column("time_windows", BIGINT, "Event timestamp in Windows format", hidden=True),
    Column("datetime", DATETIME, "Event timestamp in DATETIME format"),
    Column("pid", BIGINT, "Process ID of process making the lookup"),
    Column("path", TEXT, "Path to binary of process making the lookup (sometimes unavailable for very short-lived processes)"),
    Column("username", TEXT, "User rights - primary token username"),
    Column("name", TEXT, "Name being queried in lookup"),
    Column("type", TEXT, "DNS record type of lookup as string"),
    Column("type_id", INTEGER, "Integer type ID for record type"),
    Column("status", INTEGER, "Response status code"),
    Column("response", TEXT, "Results returned by lookup"),
])
attributes(event_subscriber=True)
implementation("dns_lookup_events@dns_lookup_events::genTable")
examples([
	"select * from dns_lookup_events;",
])


#windows
table_name("drivers")
description("Details for in-use Windows device drivers. This does not display installed but unused drivers.")
schema([
    Column("device_id", TEXT, "Device ID"),
    Column("device_name", TEXT, "Device name"),
    Column("image", TEXT, "Path to driver image file"),
    Column("description", TEXT, "Driver description"),
    Column("service", TEXT, "Driver service name, if one exists"),
    Column("service_key", TEXT, "Driver service registry key"),
    Column("version", TEXT, "Driver version", collate="version"),
    Column("inf", TEXT, "Associated inf file"),
    Column("class", TEXT, "Device/driver class name"),
    Column("provider", TEXT, "Driver provider"),
    Column("manufacturer", TEXT, "Device manufacturer"),
    Column("driver_key", TEXT, "Driver key"),
    Column("date", BIGINT, "Driver date"),
    Column("signed", INTEGER, "Whether the driver is signed or not")
])
implementation("system/windows/Drivers@genDrivers")
examples([
  "select * from drivers",
])


#windows
table_name("ie_extensions")
description("Internet Explorer browser extensions.")
schema([
    Column("name", TEXT, "Extension display name"),
    Column("registry_path", TEXT, "Extension identifier"),
    Column("version", TEXT, "Version of the executable", collate="version"),
    Column("path", TEXT, "Path to executable"),
])
implementation("system/windows/ie_extensions@genIEExtensions")


#windows
table_name("kva_speculative_info")
description("Display kernel virtual address and speculative execution information for the system.")
schema([
  Column("kva_shadow_enabled", INTEGER, "Kernel Virtual Address shadowing is enabled."),
  Column("kva_shadow_user_global", INTEGER, "User pages are marked as global."),
  Column("kva_shadow_pcid", INTEGER, "Kernel VA PCID flushing optimization is enabled."),
  Column("kva_shadow_inv_pcid", INTEGER, "Kernel VA INVPCID is enabled."),
  Column("bp_mitigations", INTEGER, "Branch Prediction mitigations are enabled."),
  Column("bp_system_pol_disabled", INTEGER, "Branch Predictions are disabled via system policy."),
  Column("bp_microcode_disabled", INTEGER, "Branch Predictions are disabled due to lack of microcode update."),
  Column("cpu_spec_ctrl_supported", INTEGER, "SPEC_CTRL MSR supported by CPU Microcode."),
  Column("ibrs_support_enabled", INTEGER, "Windows uses IBRS."),
  Column("stibp_support_enabled", INTEGER, "Windows uses STIBP."),
  Column("cpu_pred_cmd_supported", INTEGER, "PRED_CMD MSR supported by CPU Microcode."),
])
implementation("system/windows/kva_speculative_info@genKvaSpeculative")
examples([
  "select * from kva_speculative_info",
])


#windows
table_name("logical_drives")
description("Details for logical drives on the system. A logical drive generally represents a single partition.")
schema([
    Column("device_id", TEXT, "The drive id, usually the drive name, e.g., 'C:'."),
    Column("type", TEXT, "Deprecated (always 'Unknown')."),
    Column("description", TEXT, "The canonical description of the drive, e.g. 'Logical Fixed Disk', 'CD-ROM Disk'."),
    Column("free_space", BIGINT, "The amount of free space, in bytes, of the drive (-1 on failure)."),
    Column("size", BIGINT, "The total amount of space, in bytes, of the drive (-1 on failure)."),
    Column("file_system", TEXT, "The file system of the drive."),
    Column("boot_partition", INTEGER, "True if Windows booted from this drive."),
])
implementation("logical_drives@genLogicalDrives")
examples([
  "select * from logical_drives",
  "select free_space from logical_drives where device_id = 'C:'"
])


#windows
table_name("logon_sessions")
description("Windows Logon Session.")
schema([
    Column("logon_id", INTEGER, "A locally unique identifier (LUID) that identifies a logon session."),
    Column("user", TEXT, "The account name of the security principal that owns the logon session."),
    Column("logon_domain", TEXT, "The name of the domain used to authenticate the owner of the logon session."),
    Column("authentication_package", TEXT, "The authentication package used to authenticate the owner of the logon session."),
    Column("logon_type", TEXT, "The logon method."),
    Column("session_id", INTEGER, "The Terminal Services session identifier."),
    Column("logon_sid", TEXT, "The user's security identifier (SID)."),
    Column("logon_time", BIGINT, "The time the session owner logged on."),
    Column("logon_server", TEXT, "The name of the server used to authenticate the owner of the logon session."),
    Column("dns_domain_name", TEXT, "The DNS name for the owner of the logon session."),
    Column("upn", TEXT, "The user principal name (UPN) for the owner of the logon session."),
    Column("logon_script", TEXT, "The script used for logging on."),
    Column("profile_path", TEXT, "The home directory for the logon session."),
    Column("home_directory", TEXT, "The home directory for the logon session."),
    Column("home_directory_drive", TEXT, "The drive location of the home directory of the logon session.")
])
implementation("logon_sessions@queryLogonSessions")
examples([
  "select * from logon_sessions;"
])


#windows
table_name("ntdomains")
description("Display basic NT domain information of a Windows machine.")
schema([
    Column("name", TEXT, "The label by which the object is known."),
    Column("client_site_name", TEXT, "The name of the site where the domain controller is configured."),
    Column("dc_site_name", TEXT, "The name of the site where the domain controller is located."),
    Column("dns_forest_name", TEXT, "The name of the root of the DNS tree."),
    Column("domain_controller_address", TEXT, "The IP Address of the discovered domain controller.."),
    Column("domain_controller_name", TEXT, "The name of the discovered domain controller."),
    Column("domain_name", TEXT, "The name of the domain."),
    Column("status", TEXT, "The current status of the domain object."),
])
implementation("system/windows/ntdomains@genNtdomains")
examples([
  "select * from ntdomains",
])

#windows
table_name("ntfs_acl_permissions")
description("Retrieve NTFS ACL permission information for files and directories.")
schema([
  Column("path", TEXT, "Path to the file or directory.", required=True, index=True, optimized=True),
  Column("type", TEXT, "Type of access mode for the access control entry."),
  Column("principal", TEXT, "User or group to which the ACE applies."),
  Column("access", TEXT, "Specific permissions that indicate the rights described by the ACE."),
  Column("inherited_from", TEXT, "The inheritance policy of the ACE."),
])
implementation("system/windows/ntfs_acl_permissions@genNtfsAclPerms")


#windows
table_name("ntfs_journal_events")
description("Track time/action changes to files specified in configuration data.")
schema ([
    Column("action", TEXT, "Change action (Write, Delete, etc)"),
    Column("category", TEXT, "The category that the event originated from"),
    Column("old_path", TEXT, "Old path (renames only)"),
    Column("path", TEXT, "Path"),
    Column("record_timestamp", TEXT, "Journal record timestamp"),
    Column("record_usn", TEXT, "The update sequence number that identifies the journal record"),
    Column("node_ref_number", TEXT, "The ordinal that associates a journal record with a filename"),
    Column("parent_ref_number", TEXT, "The ordinal that associates a journal record with a filename's parent directory"),
    Column("drive_letter", TEXT, "The drive letter identifying the source journal"),
    Column("file_attributes", TEXT, "File attributes"),
    Column("partial", BIGINT, "Set to 1 if either path or old_path only contains the file or folder name"),
    Column("time", BIGINT, "Time of file event", additional=True),
    Column("eid", TEXT, "Event ID", hidden=True),
])

attributes(event_subscriber=True)
implementation("ntfs_journal_events@NTFSEventSubscriber::genTable")


#windows
table_name("office_mru")
description("View recently opened Office documents.")
schema([
	Column("application", TEXT, "Associated Office application"),
	Column("version", TEXT, "Office application version number"),
	Column("path", TEXT, "File path"),
	Column("last_opened_time", BIGINT, "Most recent opened time file was opened"),
	Column("sid", TEXT, "User SID"),
])
implementation("office_mru@genOfficeMru")
examples([
	"select * from office_mru;",
])


#windows
table_name("patches")
description("Lists all the patches applied. Note: This does not include patches applied via MSI or downloaded from Windows Update (e.g. Service Packs).")
schema([
  Column("csname", TEXT, "The name of the host the patch is installed on."),
  Column("hotfix_id", TEXT, "The KB ID of the patch."),
  Column("caption", TEXT, "Short description of the patch."),
  Column("description", TEXT, "Fuller description of the patch."),
  Column("fix_comments", TEXT, "Additional comments about the patch."),
  Column("installed_by", TEXT, "The system context in which the patch as installed."),
  Column("install_date", TEXT, "Indicates when the patch was installed. Lack of a value does not indicate that the patch was not installed."),
  Column("installed_on", TEXT, "The date when the patch was installed."),
])
implementation("system/windows/patches@genInstalledPatches")
examples([
  "select * from patches",
])


#windows
table_name("physical_disk_performance")
description("Provides provides raw data from performance counters that monitor hard or fixed disk drives on the system.")
schema([
    Column("name", TEXT, "Name of the physical disk"),
    Column("avg_disk_bytes_per_read", BIGINT, "Average number of bytes transferred from the disk during read operations"),
    Column("avg_disk_bytes_per_write", BIGINT, "Average number of bytes transferred to the disk during write operations"),
    Column("avg_disk_read_queue_length", BIGINT, "Average number of read requests that were queued for the selected disk during the sample interval"),
    Column("avg_disk_write_queue_length", BIGINT, "Average number of write requests that were queued for the selected disk during the sample interval"),
    Column("avg_disk_sec_per_read", INTEGER, "Average time, in seconds, of a read operation of data from the disk"),
    Column("avg_disk_sec_per_write", INTEGER, "Average time, in seconds, of a write operation of data to the disk"),
    Column("current_disk_queue_length", INTEGER, "Number of requests outstanding on the disk at the time the performance data is collected"),
    Column("percent_disk_read_time", BIGINT, "Percentage of elapsed time that the selected disk drive is busy servicing read requests"),
    Column("percent_disk_write_time", BIGINT, "Percentage of elapsed time that the selected disk drive is busy servicing write requests"),
    Column("percent_disk_time", BIGINT, "Percentage of elapsed time that the selected disk drive is busy servicing read or write requests"),
    Column("percent_idle_time", BIGINT, "Percentage of time during the sample interval that the disk was idle")
])
implementation("system/windows/physical_disk_performance@genPhysicalDiskPerformance")


#windows
table_name("pipes")
description("Named and Anonymous pipes.")
schema([
    Column("pid", BIGINT, "Process ID of the process to which the pipe belongs", index=True),
    Column("name", TEXT, "Name of the pipe"),
    Column("instances", INTEGER, "Number of instances of the named pipe"),
    Column("max_instances", INTEGER, "The maximum number of instances creatable for this pipe"),
    Column("flags", TEXT, "The flags indicating whether this pipe connection is a server or client end, and if the pipe for sending messages or bytes"),
])
implementation("pipes@genPipes")
examples([
  "select * from pipes",
])


#windows
table_name("powershell_events")
description("Powershell script blocks reconstructed to their full script content, this table requires script block logging to be enabled.")
schema([
    Column("time", BIGINT, "Timestamp the event was received by the osquery event publisher", additional=True),
    Column("datetime", TEXT, "System time at which the Powershell script event occurred"),
    Column("script_block_id", TEXT, "The unique GUID of the powershell script to which this block belongs"),
    Column("script_block_count", INTEGER, "The total number of script blocks for this script"),
    Column("script_text", TEXT, "The text content of the Powershell script"),
    Column("script_name", TEXT, "The name of the Powershell script"),
    Column("script_path", TEXT, "The path for the Powershell script"),
    Column("cosine_similarity", DOUBLE, "How similar the Powershell script is to a provided 'normal' character frequency"),
])
attributes(event_subscriber=True)
implementation("powershell_events@PowershellEventSubscriber::genTable")
examples([
  "select * from powershell_events;",
  "select * from powershell_events where script_text like '%Invoke-Mimikatz%';",
  "select * from powershell_events where cosine_similarity < 0.25;",
])


#windows
table_name("prefetch")
description("Prefetch files show metadata related to file execution.")
schema([
    Column("path", TEXT, "Prefetch file path.", additional=True, optimized=True),
    Column("filename", TEXT, "Executable filename."),
    Column("hash", TEXT, "Prefetch CRC hash."),
    Column("last_run_time", INTEGER, "Most recent time application was run."),
    Column("other_run_times", TEXT, "Other execution times in prefetch file."),
    Column("run_count", INTEGER, "Number of times the application has been run."),
    Column("size", INTEGER, "Application file size."),
    Column("volume_serial", TEXT, "Volume serial number."),
    Column("volume_creation", TEXT, "Volume creation time."),
    Column("accessed_files_count", INTEGER, "Number of files accessed."),
    Column("accessed_directories_count", INTEGER, "Number of directories accessed."),
    Column("accessed_files", TEXT, "Files accessed by application within ten seconds of launch."),
    Column("accessed_directories", TEXT, "Directories accessed by application within ten seconds of launch.")
])
implementation("prefetch@genPrefetch", generator=True)
examples([
  "select * from prefetch;",
])

#windows
table_name("process_etw_events")
description("Windows process execution events.")
schema([
    Column("type", TEXT, "Event Type (ProcessStart, ProcessStop)"),
    Column("pid", BIGINT, "Process ID"),
    Column("ppid", BIGINT, "Parent Process ID"),
    Column("session_id", INTEGER, "Session ID"),
    Column("flags", INTEGER, "Process Flags"),
    Column("exit_code", INTEGER, "Exit Code - Present only on ProcessStop events"),
    Column("path", TEXT, "Path of executed binary"),
    Column("cmdline", TEXT, "Command Line"),
    Column("username", TEXT, "User rights - primary token username"),
    Column("token_elevation_type", TEXT, "Primary token elevation type - Present only on ProcessStart events"),
    Column("token_elevation_status", INTEGER, "Primary token elevation status - Present only on ProcessStart events"),
    Column("mandatory_label", TEXT, "Primary token mandatory label sid - Present only on ProcessStart events"),
    Column("datetime", DATETIME, "Event timestamp in DATETIME format"),
    Column("time_windows", BIGINT, "Event timestamp in Windows format", hidden=True),
    Column("time", BIGINT, "Event timestamp in Unix format", hidden=True, additional=True),
    Column("eid", INTEGER, "Event ID", hidden=True),
    Column("header_pid", BIGINT, "Process ID of the process reporting the event", hidden=True),
    Column("process_sequence_number", BIGINT, "Process Sequence Number - Present only on ProcessStart events", hidden=True),
    Column("parent_process_sequence_number", BIGINT, "Parent Process Sequence Number - Present only on ProcessStart events", hidden=True),
])
attributes(event_subscriber=True)
implementation("process_etw_events@etw_process_events::genTable")
examples([
	"select * from process_etw_events;",
	"select * from process_etw_events WHERE time >= (( SELECT unix_time FROM time) - 60 );",
	"select * from process_etw_events WHERE datetime > '2022-11-18 16:48:00';",
	"select * from process_etw_events WHERE datetime BETWEEN '2022-11-18 16:40:00' AND '2022-11-18 16:50:00';"
])


#windows
table_name("programs", aliases=["programs_and_features"])
description("Represents products as they are installed by Windows Installer. A product generally correlates to one installation package on Windows. Some fields may be blank as Windows installation details are left to the discretion of the product author.")
schema([
    Column("name", TEXT, "Commonly used product name."),
    Column("version", TEXT, "Product version information.", collate="version"),
    Column("install_location", TEXT, "The installation location directory of the product."),
    Column("install_source", TEXT, "The installation source of the product."),
    Column("language", TEXT, "The language of the product."),
    Column("publisher", TEXT, "Name of the product supplier."),
    Column("uninstall_string", TEXT, "Path and filename of the uninstaller."),
    Column("install_date", TEXT, "Date that this product was installed on the system. "),
    Column("identifying_number", TEXT, "Product identification such as a serial number on software, or a die number on a hardware chip."),
    Column("package_family_name", TEXT, "A combination of PackageName and PublisherHash that is used to uniquely identify applications across versions and architectures."),
    Column("upgrade_code", TEXT, "Specific to MSI applications, a GUID used to identify a product suite across multiple versions.")
])
implementation("programs@genPrograms")
examples([
  "select * from programs",
  "select name, install_location from programs where install_location not like 'C:\Program Files%';",
])

#windows
table_name("recent_files")
description("Recently files (as displayed in Start Menu or File Explorer).")
schema([
    Column("uid", BIGINT, "The local user ID", index=True, optimized=True),
    Column("filename", TEXT, "The name of the file"),
    Column("path", TEXT, "The full path of the file"),
    Column("type", TEXT, "Display type for the file"),
    Column("mtime", BIGINT, "Last modification time of the shortcut (usually corresponds to last opened time for the file)"),
    Column("shortcut_path", TEXT, "Path to the shortcut where Windows stores the recent file data"),
])
attributes(user_data=True)
implementation("system/windows/recent_files@genRecentFiles")
examples([
    "SELECT * FROM users CROSS JOIN recent_files USING (uid)",
    "SELECT recent_files.* FROM users CROSS JOIN recent_files USING (uid) WHERE mtime > unixepoch('now') - 3600",
])

#windows
table_name("registry")
description("All of the Windows registry hives.")
schema([
    Column("key", TEXT, "Name of the key to search for", additional=True, optimized=True, collate="nocase"),
    Column("path", TEXT, "Full path to the value", index=True, optimized=True),
    Column("name", TEXT, "Name of the registry value entry"),
    Column("type", TEXT, "Type of the registry value, or 'subkey' if item is a subkey"),
    Column("data", TEXT, "Data content of registry value"),
    Column("mtime", BIGINT, "timestamp of the most recent registry write"),
])
implementation("system/windows/registry@genRegistry")
examples([
  "select path, key, name from registry where key = 'HKEY_USERS'; -- get user SIDS. Note: path is key+name",
  "select path from registry where key like 'HKEY_USERS\\.Default\\%'; -- a SQL wildcard match; will not recurse subkeys",
  "select path from registry where key like 'HKEY_USERS\\.Default\\Software\\%%'; -- recursing query (compare with 1 %)",
  "select path from registry where key like 'HKEY_LOCAL_MACHINE\\Software\\Micr%ft\\%' and type = 'subkey' LIMIT 10; -- midfix wildcard match",
  "select name, type, data from registry where path like 'HKEY_USERS\\%\\Control Panel\\International\\User Profile\\Languages'; -- get users' current UI language. Note: osquery cannot reference HKEY_CURRENT_USER",
  "select name, type, data from registry where path like 'HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpapers\\%';  -- list all of the desktop wallpapers",
  "select name, type, data from registry where key like 'HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpapers'; -- same, but filtering by key instead of path",
])


#windows
table_name("scheduled_tasks")
description("Lists all of the tasks in the Windows task scheduler.")
schema([
  Column("name", TEXT, "Name of the scheduled task"),
  Column("action", TEXT, "Actions executed by the scheduled task"),
  Column("path", TEXT, "Path to the executable to be run"),
  Column("enabled", INTEGER, "Whether or not the scheduled task is enabled"),
  Column("state", TEXT, "State of the scheduled task"),
  Column("hidden", INTEGER, "Whether or not the task is visible in the UI"),
  Column("last_run_time", BIGINT, "Timestamp the task last ran"),
  Column("next_run_time", BIGINT, "Timestamp the task is scheduled to run next"),
  Column("last_run_message", TEXT, "Exit status message of the last task run"),
  Column("last_run_code", TEXT, "Exit status code of the last task run"),
])
implementation("scheduled_tasks@genScheduledTasks")
examples([
  "select * from scheduled_tasks",
  "select * from scheduled_tasks where hidden=1 and enabled=1",
])


#windows
table_name("security_profile_info")
description("Information on the security profile of a given system by listing the system Account and Audit Policies. This table mimics the exported securitypolicy output from the secedit tool.")
schema([
    Column("minimum_password_age", INTEGER, "Determines the minimum number of days that a password must be used before the user can change it"),
    Column("maximum_password_age", INTEGER, "Determines the maximum number of days that a password can be used before the client requires the user to change it"),
    Column("minimum_password_length", INTEGER, "Determines the least number of characters that can make up a password for a user account"),
    Column("password_complexity", INTEGER, "Determines whether passwords must meet a series of strong-password guidelines"),
    Column("password_history_size", INTEGER, "Number of unique new passwords that must be associated with a user account before an old password can be reused"),
    Column("lockout_bad_count", INTEGER, "Number of failed logon attempts after which a user account MUST be locked out"),
    Column("logon_to_change_password", INTEGER, "Determines if logon session is required to change the password"),
    Column("force_logoff_when_expire", INTEGER, "Determines whether SMB client sessions with the SMB server will be forcibly disconnected when the client's logon hours expire"),
    Column("new_administrator_name", TEXT, "Determines the name of the Administrator account on the local computer"),
    Column("new_guest_name", TEXT, "Determines the name of the Guest account on the local computer"),
    Column("clear_text_password", INTEGER, "Determines whether passwords MUST be stored by using reversible encryption"),
    Column("lsa_anonymous_name_lookup", INTEGER, "Determines if an anonymous user is allowed to query the local LSA policy"),
    Column("enable_admin_account", INTEGER, "Determines whether the Administrator account on the local computer is enabled"),
    Column("enable_guest_account", INTEGER, "Determines whether the Guest account on the local computer is enabled"),
    Column("audit_system_events", INTEGER, "Determines whether the operating system MUST audit System Change, System Startup, System Shutdown, Authentication Component Load, and Loss or Excess of Security events"),
    Column("audit_logon_events", INTEGER, "Determines whether the operating system MUST audit each instance of a user attempt to log on or log off this computer"),
    Column("audit_object_access", INTEGER, "Determines whether the operating system MUST audit each instance of user attempts to access a non-Active Directory object that has its own SACL specified"),
    Column("audit_privilege_use", INTEGER, "Determines whether the operating system MUST audit each instance of user attempts to exercise a user right"),
    Column("audit_policy_change", INTEGER, "Determines whether the operating system MUST audit each instance of user attempts to change user rights assignment policy, audit policy, account policy, or trust policy"),
    Column("audit_account_manage", INTEGER, "Determines whether the operating system MUST audit each event of account management on a computer"),
    Column("audit_process_tracking", INTEGER, "Determines whether the operating system MUST audit process-related events"),
    Column("audit_ds_access", INTEGER, "Determines whether the operating system MUST audit each instance of user attempts to access an Active Directory object that has its own system access control list (SACL) specified"),
    Column("audit_account_logon", INTEGER, "Determines whether the operating system MUST audit each time this computer validates the credentials of an account"),
])
implementation("security_profile_info@genSecurityProfileInformation")


#windows
table_name("services")
description("Lists all installed Windows services and their relevant data.")
schema([
    Column("name", TEXT, "Service name", collate="nocase"),
    Column("service_type", TEXT, "Service Type: OWN_PROCESS, SHARE_PROCESS and maybe Interactive (can interact with the desktop)"),
    Column("display_name", TEXT, "Service Display name"),
    Column("status", TEXT, "Service Current status: STOPPED, START_PENDING, STOP_PENDING, RUNNING, CONTINUE_PENDING, PAUSE_PENDING, PAUSED"),
    Column("pid", INTEGER, "the Process ID of the service"),
    Column("start_type", TEXT, "Service start type: BOOT_START, SYSTEM_START, AUTO_START, DEMAND_START, DISABLED"),
    Column("win32_exit_code", INTEGER, "The error code that the service uses to report an error that occurs when it is starting or stopping"),
    Column("service_exit_code", INTEGER, "The service-specific error code that the service returns when an error occurs while the service is starting or stopping"),
    Column("path", TEXT, "Path to Service Executable"),
    Column("module_path", TEXT, "Path to ServiceDll"),
    Column("description", TEXT, "Service Description"),
    Column("user_account", TEXT, "The name of the account that the service process will be logged on as when it runs. This name can be of the form Domain\\UserName. If the account belongs to the built-in domain, the name can be of the form .\\UserName."),
])
implementation("system/windows/services@genServices")
examples([
  "select * from services",
])


#windows
table_name("shared_resources")
description("Displays shared resources on a computer system running Windows. This may be a disk drive, printer, interprocess communication, or other sharable device.")
schema([
    Column("description", TEXT, "A textual description of the object"),
    Column("install_date", TEXT, "Indicates when the object was installed. Lack of a value does not indicate that the object is not installed."),
    Column("status", TEXT, "String that indicates the current status of the object."),
    Column("allow_maximum", INTEGER, "Number of concurrent users for this resource has been limited. If True, the value in the MaximumAllowed property is ignored."),
    Column("maximum_allowed", BIGINT, "Limit on the maximum number of users allowed to use this resource concurrently. The value is only valid if the AllowMaximum property is set to FALSE."),
    Column("name", TEXT, "Alias given to a path set up as a share on a computer system running Windows."),
    Column("path", TEXT, "Local path of the Windows share."),
    Column("type", BIGINT, "Type of resource being shared. Types include: disk drives, print queues, interprocess communications (IPC), and general devices."),
    Column("type_name", TEXT, "Human readable value for the 'type' column"),

])
implementation("shared_resources@genShares")
examples([
  "select * from shared_resources",
])

#windows
table_name("shellbags")
description("Shows directories accessed via Windows Explorer.")
schema([
    Column("sid", TEXT, "User SID"),
    Column("source", TEXT, "Shellbags source Registry file"),
    Column("path", TEXT, "Directory name."),
    Column("modified_time", BIGINT, "Directory Modified time."),
    Column("created_time", BIGINT, "Directory Created time."),
    Column("accessed_time", BIGINT, "Directory Accessed time."),
    Column("mft_entry", BIGINT, "Directory master file table entry."),
    Column("mft_sequence", INTEGER, "Directory master file table sequence."),
])
implementation("shellbags@genShellbags")
examples([
  "select * from shellbags;",
])

#windows
table_name("shimcache")
description("Application Compatibility Cache, contains artifacts of execution.")
schema([
    Column("entry", INTEGER, "Execution order."),
    Column("path", TEXT, "This is the path to the executed file."),
    Column("modified_time", INTEGER, "File Modified time."),
    Column("execution_flag", INTEGER, "Boolean Execution flag, 1 for execution, 0 for no execution, -1 for missing (this flag does not exist on Windows 10 and higher)."),
])
implementation("shimcache@genShimcache")
examples([
  "select * from shimcache;",
])


#windows
table_name("tpm_info")
description("A table that lists the TPM related information.")
schema([
  Column("activated", INTEGER, "TPM is activated"),
  Column("enabled", INTEGER, "TPM is enabled"),
  Column("owned", INTEGER, "TPM is owned"),
  Column("manufacturer_version", TEXT, "TPM version"),
  Column("manufacturer_id", INTEGER, "TPM manufacturers ID"),
  Column("manufacturer_name", TEXT, "TPM manufacturers name"),
  Column("product_name", TEXT, "Product name of the TPM"),
  Column("physical_presence_version", TEXT, "Version of the Physical Presence Interface"),
  Column("spec_version", TEXT, "Trusted Computing Group specification that the TPM supports", collate="version"),
])
implementation("tpm_info@genTpmInfo")
examples([
  "select * from tpm_info",
])


#windows
table_name("userassist")
description("UserAssist Registry Key tracks when a user executes an application from Windows Explorer.")
schema([
    Column("path", TEXT, "Application file path."),
    Column("last_execution_time", BIGINT, "Most recent time application was executed."),
    Column("count", INTEGER, "Number of times the application has been executed."),
    Column("sid", TEXT, "User SID."),
])
implementation("userassist@genUserAssist")
examples([
  "select * from userassist;",
])


#windows
table_name("video_info")
description("Retrieve video card information of the machine.")
schema([
    Column("color_depth", INTEGER, "The amount of bits per pixel to represent color."),
    Column("driver", TEXT, "The driver of the device."),
    Column("driver_date", BIGINT, "The date listed on the installed driver."),
    Column("driver_version", TEXT, "The version of the installed driver.", collate="version"),
    Column("manufacturer", TEXT, "The manufacturer of the gpu."),
    Column("model", TEXT, "The model of the gpu."),
    Column("series", TEXT, "The series of the gpu."),
    Column("video_mode", TEXT, "The current resolution of the display."),
])
implementation("video_info@genVideoInfo")


#windows
table_name("winbaseobj")
description("Lists named Windows objects in the default object directories, across all terminal services sessions.  Example Windows ojbect types include Mutexes, Events, Jobs and Semaphors.")
schema([
    Column("session_id", INTEGER, "Terminal Services Session Id"),
    Column("object_name", TEXT, "Object Name"),
    Column("object_type", TEXT, "Object Type"),
])
implementation("system/windows/Objects@genBaseNamedObjects")
examples([
  "select object_name, object_type from winbaseobj",
  "select * from winbaseobj where type='Mutant'",
])


#windows
table_name("windows_crashes")
description("Extracted information from Windows crash logs (Minidumps).")
schema([
	Column("datetime", TEXT, "Timestamp (log format) of the crash"),
	Column("module", TEXT, "Path of the crashed module within the process"),
	Column("path", TEXT, "Path of the executable file for the crashed process"),
	Column("pid", BIGINT, "Process ID of the crashed process"),
	Column("tid", BIGINT, "Thread ID of the crashed thread"),
	Column("version", TEXT, "File version info of the crashed process"),
	Column("process_uptime", BIGINT, "Uptime of the process in seconds"),
	Column("stack_trace", TEXT, "Multiple stack frames from the stack trace"),
	Column("exception_code", TEXT, "The Windows exception code"),
	Column("exception_message", TEXT, "The NTSTATUS error message associated with the exception code"),
	Column("exception_address", TEXT, "Address (in hex) where the exception occurred"),
	Column("registers", TEXT, "The values of the system registers"),
	Column("command_line", TEXT, "Command-line string passed to the crashed process"),
	Column("current_directory", TEXT, "Current working directory of the crashed process"),
	Column("username", TEXT, "Username of the user who ran the crashed process"),
	Column("machine_name", TEXT, "Name of the machine where the crash happened"),
	Column("major_version", INTEGER, "Windows major version of the machine"),
	Column("minor_version", INTEGER, "Windows minor version of the machine"),
	Column("build_number", INTEGER, "Windows build number of the crashing machine"),
	Column("type", TEXT, "Type of crash log"),
	Column("crash_path", TEXT, "Path of the log file")
])
implementation("windows_crashes@genCrashLogs")
examples([
	"select * from windows_crashes",
	"select * from windows_crashes where module like '%electron.exe%'",
	"select * from windows_crashes where datetime < '2016-10-14'",
	"select * from windows_crashes where registers like '%rax=0000000000000004%'",
	"select * from windows_crashes where stack_trace like '%vlc%'",
])

#windows
table_name("windows_eventlog")
description("Table for querying all recorded Windows event logs.")
schema([
    Column("channel", TEXT, "Source or channel of the event", required=True),
    Column("datetime", TEXT, "System time at which the event occurred"),
    Column("task", INTEGER, "Task value associated with the event"),
    Column("level", INTEGER, "Severity level associated with the event"),
    Column("provider_name", TEXT, "Provider name of the event"),
    Column("provider_guid", TEXT, "Provider guid of the event"),
    Column("computer_name", TEXT, "Hostname of system where event was generated"),
    Column("eventid", INTEGER, "Event ID of the event", additional=True),
    Column("keywords", TEXT, "A bitmask of the keywords defined in the event"),
    Column("data", TEXT, "Data associated with the event"),
    Column("pid", INTEGER, "Process ID which emitted the event record", additional=True),
    Column("tid", INTEGER, "Thread ID which emitted the event record"),
    Column("time_range", TEXT, "System time to selectively filter the events", hidden=True, additional=True),
    Column("timestamp", TEXT, "Timestamp to selectively filter the events", hidden=True, additional=True),
    Column("xpath", TEXT, "The custom query to filter events", hidden=True, required=True),
])

implementation("system/windows_eventlog@genWindowsEventLog", generator=True)
examples([
  "select * from windows_eventlog where eventid=4625 and channel='Security'",
])


#windows
table_name("windows_events")
description("Windows Event logs.")
schema([
    Column("time", BIGINT, "Timestamp the event was received", additional=True),
    Column("datetime", TEXT, "System time at which the event occurred"),
    Column("source", TEXT, "Source or channel of the event"),
    Column("provider_name", TEXT, "Provider name of the event"),
    Column("provider_guid", TEXT, "Provider guid of the event"),
    Column("computer_name", TEXT, "Hostname of system where event was generated"),
    Column("eventid", INTEGER, "Event ID of the event"),
    Column("task", INTEGER, "Task value associated with the event"),
    Column("level", INTEGER, "The severity level associated with the event"),
    Column("keywords", TEXT, "A bitmask of the keywords defined in the event"),
    Column("data", TEXT, "Data associated with the event"),
    Column("eid", TEXT, "Event ID", hidden=True),
])
attributes(event_subscriber=True)
implementation("windows_events@WindowsEventSubscriber::genTable")
examples([
  "select * from windows_events where eventid=4104 and source='Security'",
])


#windows
table_name("windows_firewall_rules")
description("Provides the list of Windows firewall rules.")
schema([
    Column("name", TEXT, "Friendly name of the rule"),
    Column("app_name", TEXT, "Friendly name of the application to which the rule applies"),
    Column("action", TEXT, "Action for the rule or default setting"),
    Column("enabled", INTEGER, "1 if the rule is enabled"),
    Column("grouping", TEXT, "Group to which an individual rule belongs"),
    Column("direction", TEXT, "Direction of traffic for which the rule applies"),
    Column("protocol", TEXT, "IP protocol of the rule"),
    Column("local_addresses", TEXT, "Local addresses for the rule"),
    Column("remote_addresses", TEXT, "Remote addresses for the rule"),
    Column("local_ports", TEXT, "Local ports for the rule"),
    Column("remote_ports", TEXT, "Remote ports for the rule"),
    Column("icmp_types_codes", TEXT, "ICMP types and codes for the rule"),
    Column("profile_domain", INTEGER, "1 if the rule profile type is domain"),
    Column("profile_private", INTEGER, "1 if the rule profile type is private"),
    Column("profile_public", INTEGER, "1 if the rule profile type is public"),
    Column("service_name", TEXT, "Service name property of the application"),
])
implementation("windows_firewall_rules@genWindowsFirewallRules")
examples([
    "select * from windows_firewall_rules",
])


#windows
table_name("windows_optional_features")
description("Lists names and installation states of windows features. Maps to Win32_OptionalFeature WMI class.")
schema([
  Column("name", TEXT, "Name of the feature"),
  Column("caption", TEXT, "Caption of feature in settings UI"),
  Column("state", INTEGER, "Installation state value. 1 == Enabled, 2 == Disabled, 3 == Absent"),
  Column("statename", TEXT, "Installation state name. 'Enabled','Disabled','Absent'"),
])
implementation("system/windows/windows_optional_features@genWinOptionalFeatures")
examples([
  "select * from windows_optional_features",
  "select * from windows_optional_features where name = 'SMB1Protocol' AND state = 1",
])


#windows
table_name("windows_search")
description("Run searches against the Windows system index database using Advanced Query Syntax. See https://learn.microsoft.com/en-us/windows/win32/search/-search-3x-advancedquerysyntax for details.")
schema([
    Column("name", TEXT, "The name of the item"),
    Column("path", TEXT, "The full path of the item."),
    Column("size", BIGINT, "The item size in bytes."),
    Column("date_created", INTEGER, "The unix timestamp of when the item was created."),
    Column("date_modified", INTEGER, "The unix timestamp of when the item was last modified"),
    Column("owner", TEXT, "The owner of the item"),
    Column("type", TEXT, "The item type"),
    Column("properties", TEXT, "Additional property values JSON"),
    Column("query", TEXT, "Windows search query", additional=True, hidden=True),
    Column("sort", TEXT, "Sort for windows api", additional=True, hidden=True),
    Column("max_results", INTEGER, "Maximum number of results returned by windows api, set to -1 for unlimited", additional=True, hidden=True),
    Column("additional_properties", TEXT, "Comma separated list of columns to include in properties JSON", additional=True, hidden=True),
])
implementation("system/windows/windows_search@genWindowsSearch")
examples([
    "select * from windows_search",
    "select * from windows_search where query = 'folder:documents'",
    "select * from windows_search where query = '\"some text in file\" folder:documents'",
    "select * from windows_search where query = '\"some text in file\" folder:documents' and additional_properties = 'system.mimetype,system.itemurl'",
    "select * from windows_search where sort = 'system.size desc'",
    "select * from windows_search where sort = 'system.size desc' and max_results = 10",
    "select *, json_extract(properties, '$.\"system.itemurl\"') as itemurl from windows_search where max_results = 5 and additional_properties = 'system.itemurl' and sort = 'system.size desc'",
    "select properties -> '$.\"system.itemurl\"' as itemurl from windows_search where max_results = 5 and additional_properties = 'system.itemurl' and sort = 'system.size desc'",
    "select * from windows_search WHERE query = 'folder:documents' AND date_created >= (( SELECT unix_time FROM time) - 60 )",
    "select *, datetime(date_created, 'unixepoch') as datetime from windows_search WHERE query = 'folder:documents' AND datetime > '2022-11-18 16:48:00'",
    "select *, datetime(date_created, 'unixepoch') as datetime from windows_search WHERE query = 'folder:documents' AND datetime BETWEEN '2022-11-18 16:40:00' AND '2023-11-18 16:50:00'",
])


#windows
table_name("windows_security_center")
description("The health status of Window Security features. Health values can be \"Good\", \"Poor\". \"Snoozed\", \"Not Monitored\", and \"Error\".")
schema([
    Column("firewall", TEXT, "The health of the monitored Firewall (see windows_security_products)"),
    Column("autoupdate", TEXT, "The health of the Windows Autoupdate feature"),
    Column("antivirus", TEXT, "The health of the monitored Antivirus solution (see windows_security_products)"),
    Column("antispyware", TEXT, "Deprecated (always 'Good').", hidden=True),
    Column("internet_settings", TEXT, "The health of the Internet Settings"),
    Column("windows_security_center_service", TEXT, "The health of the Windows Security Center Service"),
    Column("user_account_control", TEXT, "The health of the User Account Control (UAC) capability in Windows"),
])
implementation("system/windows/windows_security_center@gen_wsc")
examples([
  "select * from windows_security_center",
])


#windows
table_name("windows_security_products")
description("Enumeration of registered Windows security products. Note: Not compatible with Windows Server.")
schema([
    Column("type", TEXT, "Type of security product", collate="nocase"),
    Column("name", TEXT, "Name of product"),
    Column("state", TEXT, "State of protection", collate="nocase"),
    Column("state_timestamp", TEXT, "Timestamp for the product state"),
    Column("remediation_path", TEXT, "Remediation path"),
    Column("signatures_up_to_date", INTEGER, "1 if product signatures are up to date, else 0"),
])
implementation("system/windows/windows_security_products@gen_wsp")
examples([
  "select * from windows_security_products",
])


#windows
table_name("windows_update_history")
description("Provides the history of the windows update events.")
schema([
    Column("client_app_id", TEXT, "Identifier of the client application that processed an update"),
    Column("date", BIGINT, "Date and the time an update was applied"),
    Column("description", TEXT, "Description of an update"),
    Column("hresult", BIGINT, "HRESULT value that is returned from the operation on an update"),
    Column("operation", TEXT, "Operation on an update"),
    Column("result_code", TEXT, "Result of an operation on an update"),
    Column("server_selection", TEXT, "Value that indicates which server provided an update"),
    Column("service_id", TEXT, "Service identifier of an update service that is not a Windows update"),
    Column("support_url", TEXT, "Hyperlink to the language-specific support information for an update"),
    Column("title", TEXT, "Title of an update"),
    Column("update_id", TEXT, "Revision-independent identifier of an update"),
    Column("update_revision", BIGINT, "Revision number of an update"),
])
implementation("windows_update_history@genWindowsUpdateHistory")
examples([
    "select * from windows_update_history",
])


#windows
table_name("wmi_bios_info")
description("Lists important information from the system bios.")
schema([
  Column("name", TEXT, "Name of the Bios setting"),
  Column("value", TEXT, "Value of the Bios setting"),
])
implementation("wmi_bios_info@genBiosInfo")
examples([
  "select * from wmi_bios_info",
  "select * from wmi_bios_info where name = 'AMTControl'",
])


#windows
table_name("wmi_cli_event_consumers")
description("WMI CommandLineEventConsumer, which can be used for persistence on Windows. See https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf for more details.")
schema([
    Column("name", TEXT, "Unique name of a consumer."),
    Column("command_line_template", TEXT, "Standard string template that specifies the process to be started. This property can be NULL, and the ExecutablePath property is used as the command line."),
    Column("executable_path", TEXT, "Module to execute. The string can specify the full path and file name of the module to execute, or it can specify a partial name. If a partial name is specified, the current drive and current directory are assumed."),
    Column("class", TEXT, "The name of the class."),
    Column("relative_path", TEXT, "Relative path to the class or instance."),
])
implementation("wmi_cli_event_consumers@genWmiCliConsumers")
examples([
  "select filter,consumer,query,command_line_template,wcec.name from wmi_cli_event_consumers wcec left outer join wmi_filter_consumer_binding wcb on consumer = wcec.relative_path left outer join wmi_event_filters wef on wef.relative_path = wcb.filter;",
])

#windows
table_name("wmi_event_filters")
description("Lists WMI event filters.")
schema([
    Column("name", TEXT, "Unique identifier of an event filter."),
    Column("query", TEXT, "Windows Management Instrumentation Query Language (WQL) event query that specifies the set of events for consumer notification, and the specific conditions for notification."),
    Column("query_language", TEXT, "Query language that the query is written in."),
    Column("class", TEXT, "The name of the class."),
    Column("relative_path", TEXT, "Relative path to the class or instance."),
])
implementation("wmi_event_filters@genWmiFilters")
examples([
  "select * from wmi_event_filters",
])

#windows
table_name("wmi_filter_consumer_binding")
description("Lists the relationship between event consumers and filters.")
schema([
    Column("consumer", TEXT, "Reference to an instance of __EventConsumer that represents the object path to a logical consumer, the recipient of an event."),
    Column("filter", TEXT, "Reference to an instance of __EventFilter that represents the object path to an event filter which is a query that specifies the type of event to be received."),
    Column("class", TEXT, "The name of the class."),
    Column("relative_path", TEXT, "Relative path to the class or instance."),
])
implementation("wmi_filter_consumer_binding@genFilterConsumer")
examples([
  "select * from wmi_filter_consumer_binding",
])

#windows
table_name("wmi_script_event_consumers")
description("WMI ActiveScriptEventConsumer, which can be used for persistence on Windows. See https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf for more details.")
schema([
    Column("name", TEXT, "Unique identifier for the event consumer. "),
    Column("scripting_engine", TEXT, "Name of the scripting engine to use, for example, 'VBScript'. This property cannot be NULL."),
    Column("script_file_name", TEXT, "Name of the file from which the script text is read, intended as an alternative to specifying the text of the script in the ScriptText property."),
    Column("script_text", TEXT, "Text of the script that is expressed in a language known to the scripting engine. This property must be NULL if the ScriptFileName property is not NULL."),
    Column("class", TEXT, "The name of the class."),
    Column("relative_path", TEXT, "Relative path to the class or instance."),
])
implementation("wmi_script_event_consumers@genScriptConsumers")
examples([
  "select filter,consumer,query,scripting_engine,script_file_name,script_text,wsec.name from wmi_script_event_consumers wsec left outer join wmi_filter_consumer_binding wcb on consumer = wsec.relative_path left outer join wmi_event_filters wef on wef.relative_path = wcb.filter;",
])


#cross-platform
table_name("yara")
description("Triggers one-off YARA query for files at the specified path. Requires one of `sig_group`, `sigfile`, or `sigrule`.")
schema([
    Column("path", TEXT, "The path scanned",
        index=True, required=True),
    Column("matches", TEXT, "List of YARA matches"),
    Column("count", INTEGER, "Number of YARA matches"),
    Column("sig_group", TEXT, "Signature group used",
        additional=True),
    Column("sigfile", TEXT, "Signature file used",
        additional=True),
    Column("sigrule", TEXT, "Signature strings used",
        additional=True, hidden=True),
    Column("strings", TEXT, "Matching strings"),
    Column("tags", TEXT, "Matching tags"),
    Column("sigurl", TEXT, "Signature url",
        additional=True, hidden=True)
])
extended_schema(LINUX, [
    Column("pid_with_namespace", INTEGER, "Pids that contain a namespace", additional=True, hidden=True),
])
implementation("yara@genYara")
examples([
  "select * from yara where path = '/etc/passwd'",
  "select * from yara where path LIKE '/etc/%'",
  "select * from yara where path = '/etc/passwd' and sigfile = '/etc/osquery/yara/test.yara'",
  "select * from yara where path = '/etc/passwd' and sigrule = 'rule always_true { condition: true }'",
])


#cross-platform
table_name("yara_events")
description("Track YARA matches for files specified in configuration data.")
schema([
    Column("target_path", TEXT, "The path scanned"),
    Column("category", TEXT, "The category of the file"),
    Column("action", TEXT, "Change action (UPDATE, REMOVE, etc)"),
    Column("matches", TEXT, "List of YARA matches"),
    Column("count", INTEGER, "Number of YARA matches"),
    Column("strings", TEXT, "Matching strings"),
    Column("tags", TEXT, "Matching tags"),
    Column("time", BIGINT, "Time of the scan"),
    Column("eid", TEXT, "Event ID", hidden=True),
])
extended_schema(DARWIN, [
    Column("transaction_id", BIGINT, "ID used during bulk update"),
])
attributes(event_subscriber=True)
implementation("yara@yara_events::genTable")


#cross-platform
table_name("ycloud_instance_metadata")
description("Yandex.Cloud instance metadata.")
schema([
    Column("instance_id", TEXT, "Unique identifier for the VM", index=True),
    Column("folder_id", TEXT, "Folder identifier for the VM"),
    Column("cloud_id", TEXT, "Cloud identifier for the VM"),
    Column("name", TEXT, "Name of the VM"),
    Column("description", TEXT, "Description of the VM"),
    Column("hostname", TEXT, "Hostname of the VM"),
    Column("zone", TEXT, "Availability zone of the VM"),
    Column("ssh_public_key", TEXT, "SSH public key. Only available if supplied at instance launch time"),
    Column("serial_port_enabled", TEXT, "Indicates if serial port is enabled for the VM"),
    Column("metadata_endpoint", TEXT, "Endpoint used to fetch VM metadata", index=True),
])
attributes(cacheable=True)
implementation("cloud/ycloud_metadata@genYCloudMetadata")
examples([
    "select * from ycloud_instance_metadata",
    "select * from ycloud_instance_metadata where metadata_endpoint=\"http://169.254.169.254\""
])



# CIBER Security Command Catalog

CyberShield contains **149 unique security-focused commands**.

GitHub/Vercel deployment commands are intentionally excluded.
Commands should execute real local security operations; unavailable engines must be reported as unavailable, never as a fake PASS.

## System

- `system.info` — System OS/build, architecture and host information
- `system.uptime` — System uptime and boot time
- `system.users` — List local user accounts
- `system.sessions` — Show interactive logon sessions
- `system.processes` — List running processes with PID/path
- `system.process` — Inspect one process by PID
- `system.services` — List Windows services and startup state
- `system.service` — Inspect one Windows service
- `system.drivers` — List loaded kernel drivers
- `system.startup` — Inspect common Windows startup locations
- `system.scheduled` — List scheduled tasks
- `system.task` — Inspect a scheduled task
- `system.environment` — Inspect non-secret environment metadata
- `system.hotfixes` — List installed Windows updates/hotfixes
- `system.defender` — Show Microsoft Defender status
- `system.firewall` — Show Windows Firewall profiles
- `system.network` — Show network interfaces and addresses
- `system.routes` — Show routing table
- `system.connections` — Show active network connections
- `system.dns` — Show DNS configuration
- `system.arp` — Show ARP cache

## Scan

- `scan.file` — Deep scan one file without executing it
- `scan.folder` — Deep scan a directory recursively
- `scan.process` — Scan the executable backing a running process
- `scan.startup` — Scan startup persistence targets
- `scan.downloads` — Scan the user's Downloads directory
- `scan.desktop` — Scan the user's Desktop directory
- `scan.quarantine` — Review quarantine candidates
- `scan.recent` — Scan recently modified executable/script files
- `scan.hash` — Calculate SHA-256/SHA-1/MD5 hashes
- `scan.signature` — Check Authenticode signature
- `scan.pe` — Inspect PE headers, sections and anomalies
- `scan.strings` — Extract and analyze suspicious strings
- `scan.entropy` — Measure entropy/packing indicators
- `scan.archive` — Inspect archive contents without executing members
- `scan.script` — Inspect script indicators
- `scan.office` — Inspect Office/PDF macro or active-content indicators
- `scan.yara` — Run installed YARA rules if available
- `scan.clamav` — Run ClamAV if available
- `scan.defender` — Run Microsoft Defender custom scan
- `scan.reputation` — Check hash reputation when configured
- `scan.compare` — Compare file hash against a known-good baseline

## Threat Hunting

- `hunt.process_tree` — Build a parent/child process tree
- `hunt.suspicious_processes` — Find unsigned/unusual processes
- `hunt.unsigned` — Find unsigned executables and drivers
- `hunt.temp_exec` — Find executables launched from temporary paths
- `hunt.user_exec` — Find executable content in user-writable locations
- `hunt.lolbins` — Find suspicious use of Windows utility binaries
- `hunt.powershell` — Review PowerShell process/activity indicators
- `hunt.wscript` — Review script-host process indicators
- `hunt.rundll32` — Review rundll32 activity indicators
- `hunt.regsvr32` — Review regsvr32 activity indicators
- `hunt.mshta` — Review mshta activity indicators
- `hunt.certutil` — Review certutil activity indicators
- `hunt.bitsadmin` — Review BITS activity indicators
- `hunt.wmic` — Review WMI process/activity indicators
- `hunt.psexec` — Review service/process indicators associated with remote execution
- `hunt.persistence` — Correlate common persistence locations
- `hunt.encoded` — Find suspicious encoded command-line indicators
- `hunt.lolbin_paths` — Inspect LOLBin paths and signatures
- `hunt.network_process` — Map processes to network connections
- `hunt.listening` — Identify listening processes
- `hunt.outbound` — Identify active outbound connections

## Network

- `net.adapters` — Detailed adapter information
- `net.ipconfig` — IP configuration and DNS details
- `net.connections` — Current TCP/UDP connections
- `net.listening` — Listening TCP/UDP endpoints
- `net.dns_cache` — Inspect DNS client cache
- `net.dns_test` — Resolve and test a domain safely
- `net.route` — Routing table
- `net.arp` — ARP neighbors
- `net.proxy` — Inspect Windows proxy configuration
- `net.firewall` — Firewall profile/state overview
- `net.firewall_rules` — List relevant firewall rules
- `net.public_ip` — Show configured public-IP lookup only when network access is allowed
- `net.port_check` — Check a specified host/port for connectivity
- `net.domain_info` — Resolve domain records
- `net.tls` — Inspect TLS certificate metadata for a URL
- `net.url_scan` — Static URL/phishing-indicator analysis
- `net.phishing` — Analyze a URL for phishing indicators
- `net.blocklist` — Check configured local/domain blocklists
- `net.reset_dns` — Flush the local DNS resolver cache

## Forensics

- `forensic.timeline` — Create a file activity timeline
- `forensic.recent_files` — List recently changed files
- `forensic.prefetch` — Inspect Windows Prefetch metadata when available
- `forensic.amcache` — Inspect Amcache metadata when permitted
- `forensic.usn` — Inspect USN journal metadata when permitted
- `forensic.eventlog` — Query security-relevant Windows event logs
- `forensic.logon` — Review recent logon events
- `forensic.defender_log` — Review Defender operational events
- `forensic.task_history` — Review scheduled-task operational history
- `forensic.service_events` — Review service creation/start events
- `forensic.network_events` — Review relevant network events
- `forensic.browser_artifacts` — Inspect supported browser security artifacts
- `forensic.downloads` — Correlate downloaded files with timestamps
- `forensic.hash_report` — Generate forensic hash report
- `forensic.case_export` — Export a case report
- `forensic.ioc_extract` — Extract hashes/domains/IPs from evidence
- `forensic.ioc_search` — Search evidence for a supplied IOC
- `forensic.baseline` — Create a system security baseline
- `forensic.diff` — Compare current state to a saved baseline

## Hardening

- `hardening.defender` — Verify Defender protections
- `hardening.realtime` — Verify real-time protection state
- `hardening.firewall` — Verify firewall state
- `hardening.uac` — Inspect UAC configuration
- `hardening.smb` — Inspect SMB security configuration
- `hardening.rdp` — Inspect RDP exposure/configuration
- `hardening.remote_services` — Audit remote-service exposure
- `hardening.autorun` — Audit autorun locations
- `hardening.admins` — Audit local administrators
- `hardening.guest` — Audit guest account state
- `hardening.password_policy` — Inspect local password policy
- `hardening.audit_policy` — Inspect Windows audit policy
- `hardening.bitlocker` — Inspect BitLocker status
- `hardening.secureboot` — Inspect Secure Boot state
- `hardening.tpm` — Inspect TPM state
- `hardening.updates` — Check update state
- `hardening.smart_app_control` — Inspect Smart App Control state when available
- `hardening.exploit_protection` — Inspect exploit protection settings
- `hardening.attack_surface` — Audit selected attack-surface settings

## Response

- `response.isolate_file` — Move a suspicious file to protected quarantine
- `response.restore_file` — Restore a quarantined file after explicit confirmation
- `response.hash` — Generate evidence hashes before response
- `response.collect` — Collect safe forensic metadata
- `response.kill_process` — Terminate a selected suspicious process after confirmation
- `response.disable_task` — Disable a selected suspicious scheduled task after confirmation
- `response.stop_service` — Stop a selected suspicious service after confirmation
- `response.block_domain` — Add a domain to CyberShield's local blocklist
- `response.unblock_domain` — Remove a domain from the local blocklist
- `response.block_hash` — Add a hash to CyberShield's local denylist
- `response.allow_hash` — Remove a hash from the local denylist
- `response.snapshot` — Create a security-state snapshot
- `response.rollback` — Restore CyberShield-managed changes from a snapshot
- `response.report` — Generate a security incident report

## Diagnostics

- `diag.health` — CyberShield engine health
- `diag.engines` — Show available scan engines
- `diag.permissions` — Check required Windows permissions
- `diag.dependencies` — Check optional scanner dependencies
- `diag.performance` — Measure scanner performance
- `diag.disk` — Check available disk space
- `diag.memory` — Check memory pressure
- `diag.cpu` — Check CPU pressure
- `diag.locked_files` — Find files currently locked by another process
- `diag.path` — Validate a scan path
- `diag.config` — Validate CyberShield configuration
- `diag.rules` — Validate installed YARA/rule packs
- `diag.logs` — Review CyberShield logs
- `diag.errors` — Show recent CyberShield errors
- `diag.selftest` — Run CyberShield self-test

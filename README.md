

## 1. Advanced System Health Monitoring and Reporting

This script collects detailed metrics (CPU, memory, disk), applies dynamic threshold checks, logs the data with timestamps, and sends alerts when resource usage exceeds critical limits. It also demonstrates advanced error handling and cleanup routines.

```bash
#!/bin/bash
# advanced-monitor.sh
# Purpose: Collect system metrics, log detailed performance data, and send alert notifications if thresholds are breached.
# Features:
# - Uses mpstat (if available) for more accurate CPU stats.
# - Robust error handling using 'set -euo pipefail' and temporary file cleanup.
# - Threshold-based alerts with dynamic message composition.

set -euo pipefail
LOG_FILE="/var/log/advanced-monitor.log"
ALERT_EMAIL="sysadmin@example.com"
TMPFILE=$(mktemp)

cleanup() {
    rm -f "$TMPFILE"
}
trap cleanup EXIT

# Collect CPU usage using mpstat if available, fallback to top
if command -v mpstat &>/dev/null; then
    CPU_IDLE=$(mpstat 1 1 | awk '/Average/ {print $NF}')
    CPU_USAGE=$(echo "100 - $CPU_IDLE" | bc)
else
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
fi

# Collect memory usage
MEM_USAGE=$(free | awk '/Mem/ {printf("%.2f"), $3/$2 * 100}')
# Collect disk usage (root filesystem)
DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | tr -d '%')

TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
echo "[$TIMESTAMP] CPU: ${CPU_USAGE}% | MEM: ${MEM_USAGE}% | DISK: ${DISK_USAGE}%" >> "$LOG_FILE"

# Define threshold values
CPU_THRESHOLD=80.0
MEM_THRESHOLD=75.0
DISK_THRESHOLD=90

ALERT_MSG=""

if (( $(echo "$CPU_USAGE > $CPU_THRESHOLD" | bc -l) )); then
    ALERT_MSG+="High CPU usage at ${CPU_USAGE}%. "
fi

if (( $(echo "$MEM_USAGE > $MEM_THRESHOLD" | bc -l) )); then
    ALERT_MSG+="Memory usage is high at ${MEM_USAGE}%. "
fi

if [ "$DISK_USAGE" -gt "$DISK_THRESHOLD" ]; then
    ALERT_MSG+="Disk usage is critical at ${DISK_USAGE}%. "
fi

if [ -n "$ALERT_MSG" ]; then
    echo "$ALERT_MSG" | mail -s "Advanced Monitor Alert on $(hostname)" "$ALERT_EMAIL"
fi

exit 0
```

---

## 2. Service Health with Auto-Rollback and Error Pattern Analysis

This script monitors critical services and analyzes recent journal logs for error patterns. If unusual error activity is detected or a service is inactive, it initiates a rollback using predefined commands. It leverages associative arrays, conditional log analysis, and robust logging.

```bash
#!/bin/bash
# service-rollback.sh
# Purpose: Monitor service health, analyze service logs for error patterns, and automatically rollback to stable versions if issues arise.
# Features:
# - Checks service status using systemctl.
# - Analyzes logs with journalctl to count error occurrences in a defined timeframe.
# - Uses rollback commands stored in an associative array.
# - Sends alert emails if critical thresholds are exceeded.

set -euo pipefail

LOG_FILE="/var/log/service-rollback.log"
ALERT_EMAIL="ops@example.com"

# Define critical services and their rollback commands
declare -A services=(
  ["myapp"]="systemctl restart myapp-stable"
  ["nginx"]="systemctl reload nginx"
)

ERROR_THRESHOLD=5       # Error count threshold
TIMEFRAME=600           # Last 10 minutes in seconds

for service in "${!services[@]}"; do
    STATUS=$(systemctl is-active "$service")
    if [ "$STATUS" != "active" ]; then
        echo "$(date): $service is down!" | tee -a "$LOG_FILE"
        echo "$(date): Initiating rollback for $service" | tee -a "$LOG_FILE"
        if eval "${services[$service]}"; then
            echo "$(date): Rollback successful for $service." | tee -a "$LOG_FILE"
        else
            echo "$(date): Rollback failed for $service!" | tee -a "$LOG_FILE"
        fi
    else
        # Check for recurring error patterns in the service logs
        error_count=$(journalctl -u "$service" --since "-$TIMEFRAME seconds" | grep -ic "error")
        if [ "$error_count" -ge "$ERROR_THRESHOLD" ]; then
            echo "$(date): Detected $error_count errors in $service. Initiating rollback." | tee -a "$LOG_FILE"
            if eval "${services[$service]}"; then
                echo "$(date): Rollback successful for $service after error surge." | tee -a "$LOG_FILE"
            else
                echo "$(date): Rollback attempt failed for $service." | tee -a "$LOG_FILE"
            fi
            echo "Details: $error_count errors in the last $TIMEFRAME seconds for $service." \
                | mail -s "Service $service Alert" "$ALERT_EMAIL"
        else
            echo "$(date): $service is running normally with $error_count recent errors." >> "$LOG_FILE"
        fi
    fi
done
```

---

## 3. Distributed Log Aggregator

This advanced script tail-follows multiple log files concurrently, filters log lines based on defined patterns, and forwards matching entries to a remote log server via TCP (using netcat). It demonstrates background process management and real-time log analysis.

```bash
#!/bin/bash
# log-aggregator.sh
# Purpose: Continuously monitor and aggregate logs from multiple sources, then forward error/warning messages to a centralized log collector.
# Features:
# - Monitors multiple log files concurrently.
# - Filters entries for critical patterns using regex.
# - Forwards matching log lines via TCP using netcat.
# - Utilizes background processes to handle multiple log streams concurrently.

REMOTE_LOG_SERVER="logserver.example.com"
REMOTE_LOG_PORT=5140

# Define the log files to monitor
LOG_FILES=(
  "/var/log/nginx/access.log"
  "/var/log/myapp/app.log"
)

# Regex pattern to capture error or warning messages
PATTERN="(ERROR|WARN)"

# Function to monitor a single log file and forward matching lines
tail_and_forward() {
    local file="$1"
    tail -F "$file" 2>/dev/null | while read -r line; do
        if echo "$line" | grep -Eq "$PATTERN"; then
            echo "$line" | nc "$REMOTE_LOG_SERVER" "$REMOTE_LOG_PORT"
        fi
    done
}

# Launch tailing for each log file concurrently
for logfile in "${LOG_FILES[@]}"; do
    tail_and_forward "$logfile" &
done

# Wait for all background processes
wait
```

---

## 4. Advanced Incremental Backup with Encryption

Combining incremental backup using `rsync`, archiving with `tar`, and encryption via GPG, this script provides a secure backup solution with retention policies and detailed logging.

```bash
#!/bin/bash
# advanced-backup.sh
# Purpose: Perform incremental backups with rsync, archive the backup, encrypt it using GPG,
# and enforce backup retention policies.
# Features:
# - Uses rsync to create an incremental backup of a source directory.
# - Archives the backup directory into a compressed tarball.
# - Encrypts the backup archive for security.
# - Removes local unencrypted artifacts and purges backups older than a defined retention period.
#
# Requirements: rsync, tar, gpg

set -euo pipefail

SOURCE_DIR="/opt/data"
BACKUP_BASE_DIR="/var/backups/data"
GPG_RECIPIENT="your.email@example.com"
DATE=$(date +'%Y-%m-%d_%H-%M')
BACKUP_DIR="${BACKUP_BASE_DIR}/${DATE}"
LOG_FILE="/var/log/advanced-backup.log"
RETENTION_DAYS=7

mkdir -p "$BACKUP_DIR"

# Perform incremental backup
rsync -a --delete "$SOURCE_DIR/" "$BACKUP_DIR/" | tee -a "$LOG_FILE"

# Create a compressed archive of the backup directory
tar -czf "${BACKUP_DIR}.tar.gz" -C "$BACKUP_BASE_DIR" "$DATE" | tee -a "$LOG_FILE"

# Encrypt the archive with GPG
gpg --output "${BACKUP_DIR}.tar.gz.gpg" --encrypt --recipient "$GPG_RECIPIENT" "${BACKUP_DIR}.tar.gz" | tee -a "$LOG_FILE"

if [ $? -eq 0 ]; then
    echo "$(date): Backup archived and encrypted successfully: ${BACKUP_DIR}.tar.gz.gpg" >> "$LOG_FILE"
else
    echo "$(date): Backup encryption failed for ${BACKUP_DIR}.tar.gz" >> "$LOG_FILE"
fi

# Remove temporary backup folder and unencrypted tarball
rm "${BACKUP_DIR}.tar.gz"
rm -rf "$BACKUP_DIR"

# Purge backups older than the retention period
find "$BACKUP_BASE_DIR" -maxdepth 1 -type f -mtime +$RETENTION_DAYS -exec rm -f {} \; -print | tee -a "$LOG_FILE"

exit 0
```

---

## 5. Comprehensive Security Audit and Remediation

This script integrates a third-party auditing tool (Lynis) when available, then performs manual checks on file permissions and unapproved SUID binaries. It logs every step and sends alert emails for critical findings.

```bash
#!/bin/bash
# advanced-security.sh
# Purpose: Conduct a detailed security audit by integrating Lynis (if installed) alongside manual system checks.
# Features:
# - Runs a security audit using Lynis for in-depth vulnerability scanning.
# - Checks for misconfigured file permissions and unapproved SUID binaries.
# - Sends immediate alerts when a risky configuration or vulnerability is detected.
#
# Requirements: lynis, mailx

set -euo pipefail

ALERT_EMAIL="security@example.com"
LOG_FILE="/var/log/advanced-security.log"
AUDIT_REPORT="/tmp/lynis_audit_report.txt"

echo "Starting security audit at $(date)" | tee -a "$LOG_FILE"

# Run Lynis audit (if available)
if command -v lynis &>/dev/null; then
    lynis audit system --quiet --report-file "$AUDIT_REPORT" | tee -a "$LOG_FILE"
    echo "Lynis audit completed." | tee -a "$LOG_FILE"
else
    echo "Lynis not installed. Skipping automated Lynis audit." | tee -a "$LOG_FILE"
fi

# Check for world-writable files in critical directories
world_writable=$(find /etc /usr/bin -xdev -type f -perm -002 2>/dev/null)
if [ -n "$world_writable" ]; then
    echo "World writable files found:" | tee -a "$LOG_FILE"
    echo "$world_writable" | tee -a "$LOG_FILE"
    echo "Alert: World writable files detected." | mail -s "Security Alert on $(hostname)" "$ALERT_EMAIL"
fi

# Validate SUID binaries against a whitelist
whitelist=(/usr/bin/passwd)
suid_files=$(find / -perm -4000 2>/dev/null)
for file in $suid_files; do
    if [[ ! " ${whitelist[@]} " =~ " ${file} " ]]; then
        echo "Unapproved SUID binary detected: $file" | tee -a "$LOG_FILE"
        echo "Alert: Unapproved SUID binary $file" | mail -s "Security Alert on $(hostname)" "$ALERT_EMAIL"
    fi
done

echo "Security audit completed at $(date)" | tee -a "$LOG_FILE"
```

---


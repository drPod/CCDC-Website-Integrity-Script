#!/usr/bin/env python3
"""
Web Integrity Monitor - Defacement Detection System
Monitors critical web server files for unauthorized changes using SHA-256 hashing.
"""

import os
import sys
import json
import hashlib
import argparse
import syslog
import glob
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Set


class WebIntegrityMonitor:
    """Monitor web server files for unauthorized changes."""

    def __init__(self, baseline_file: str = "/var/lib/web-integrity/baseline.json"):
        """
        Initialize the Web Integrity Monitor.

        Args:
            baseline_file: Path to store/read the baseline hash database
        """
        self.baseline_file = baseline_file
        self.baseline_dir = os.path.dirname(baseline_file)

        # Default paths to monitor - can be customized
        self.monitored_paths = [
            "/var/www/html",
            "/etc/apache2/*.conf",
            "/etc/apache2/sites-available/*",
            "/etc/apache2/sites-enabled/*",
            "/var/www/**/.htaccess",
            "/etc/nginx/*.conf",
            "/etc/nginx/sites-available/*",
            "/etc/nginx/sites-enabled/*",
        ]

    def _ensure_baseline_directory(self) -> None:
        """Create baseline directory if it doesn't exist."""
        try:
            os.makedirs(self.baseline_dir, mode=0o700, exist_ok=True)
            # Try to set ownership to root if running as root
            if os.geteuid() == 0:
                os.chown(self.baseline_dir, 0, 0)
        except PermissionError:
            self._log_error(f"Permission denied creating directory: {self.baseline_dir}")
            sys.exit(1)

    def _calculate_file_hash(self, filepath: str) -> str:
        """
        Calculate SHA-256 hash of a file.

        Args:
            filepath: Path to the file

        Returns:
            Hexadecimal SHA-256 hash string
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                # Read file in chunks to handle large files efficiently
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (IOError, PermissionError) as e:
            self._log_error(f"Error reading file {filepath}: {e}")
            return ""

    def _expand_paths(self) -> Set[str]:
        """
        Expand glob patterns and directories to individual files.

        Returns:
            Set of file paths to monitor
        """
        files_to_monitor = set()

        for path_pattern in self.monitored_paths:
            # Check if path exists as-is (directory)
            if os.path.isdir(path_pattern):
                # Recursively find all files in directory
                for root, _, files in os.walk(path_pattern):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        if os.path.isfile(filepath):
                            files_to_monitor.add(os.path.abspath(filepath))

            # Check if path exists as a file
            elif os.path.isfile(path_pattern):
                files_to_monitor.add(os.path.abspath(path_pattern))

            # Try glob expansion for patterns
            else:
                for filepath in glob.glob(path_pattern, recursive=True):
                    if os.path.isfile(filepath):
                        files_to_monitor.add(os.path.abspath(filepath))

        return files_to_monitor

    def create_baseline(self) -> None:
        """Create baseline hash database of all monitored files."""
        self._ensure_baseline_directory()

        print(f"Creating baseline for web integrity monitoring...")
        print(f"Monitored paths: {', '.join(self.monitored_paths)}")

        files_to_monitor = self._expand_paths()

        if not files_to_monitor:
            print("WARNING: No files found to monitor. Check your paths.")
            self._log_warning("No files found to monitor during baseline creation")
            return

        print(f"Found {len(files_to_monitor)} files to monitor")

        baseline = {}
        for filepath in sorted(files_to_monitor):
            file_hash = self._calculate_file_hash(filepath)
            if file_hash:
                baseline[filepath] = {
                    "hash": file_hash,
                    "size": os.path.getsize(filepath),
                    "mtime": os.path.getmtime(filepath)
                }
                print(f"  Added: {filepath}")

        # Save baseline to file
        baseline_data = {
            "created": datetime.now().isoformat(),
            "files": baseline
        }

        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)

            # Secure the baseline file
            os.chmod(self.baseline_file, 0o600)
            if os.geteuid() == 0:
                os.chown(self.baseline_file, 0, 0)

            print(f"\nBaseline created successfully: {self.baseline_file}")
            print(f"Total files in baseline: {len(baseline)}")
            self._log_info(f"Baseline created with {len(baseline)} files")

        except (IOError, PermissionError) as e:
            self._log_error(f"Error saving baseline: {e}")
            sys.exit(1)

    def _load_baseline(self) -> Dict:
        """
        Load baseline hash database.

        Returns:
            Dictionary containing baseline data
        """
        if not os.path.exists(self.baseline_file):
            self._log_error(f"Baseline file not found: {self.baseline_file}")
            print(f"ERROR: Baseline file not found: {self.baseline_file}")
            print("Please run with --baseline first to create a baseline.")
            sys.exit(1)

        try:
            with open(self.baseline_file, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            self._log_error(f"Error loading baseline: {e}")
            print(f"ERROR: Could not load baseline: {e}")
            sys.exit(1)

    def monitor(self) -> Tuple[int, int, int, int]:
        """
        Monitor files and compare against baseline.

        Returns:
            Tuple of (changed, new, deleted, unchanged) file counts
        """
        baseline_data = self._load_baseline()
        baseline = baseline_data.get("files", {})

        current_files = self._expand_paths()
        baseline_files = set(baseline.keys())

        changed_files = []
        new_files = []
        deleted_files = []
        unchanged_count = 0

        # Check for changed or unchanged files
        for filepath in current_files:
            if filepath in baseline:
                current_hash = self._calculate_file_hash(filepath)
                if current_hash and current_hash != baseline[filepath]["hash"]:
                    changed_files.append(filepath)
                    self._log_alert(f"FILE MODIFIED: {filepath}")
                else:
                    unchanged_count += 1
            else:
                new_files.append(filepath)
                self._log_alert(f"NEW FILE DETECTED: {filepath}")

        # Check for deleted files
        for filepath in baseline_files:
            if filepath not in current_files:
                deleted_files.append(filepath)
                self._log_alert(f"FILE DELETED: {filepath}")

        return len(changed_files), len(new_files), len(deleted_files), unchanged_count

    def monitor_verbose(self) -> None:
        """Monitor files with detailed console output."""
        print(f"Monitoring web integrity...")
        print(f"Baseline: {self.baseline_file}")

        baseline_data = self._load_baseline()
        baseline = baseline_data.get("files", {})
        baseline_created = baseline_data.get("created", "Unknown")

        print(f"Baseline created: {baseline_created}")
        print(f"Baseline contains: {len(baseline)} files\n")

        current_files = self._expand_paths()
        baseline_files = set(baseline.keys())

        changed_files = []
        new_files = []
        deleted_files = []
        unchanged_count = 0

        # Check for changed or unchanged files
        print("Checking files...")
        for filepath in sorted(current_files):
            if filepath in baseline:
                current_hash = self._calculate_file_hash(filepath)
                if current_hash and current_hash != baseline[filepath]["hash"]:
                    changed_files.append(filepath)
                    print(f"  [MODIFIED] {filepath}")
                    self._log_alert(f"FILE MODIFIED: {filepath}")
                else:
                    unchanged_count += 1
            else:
                new_files.append(filepath)
                print(f"  [NEW] {filepath}")
                self._log_alert(f"NEW FILE DETECTED: {filepath}")

        # Check for deleted files
        for filepath in sorted(baseline_files):
            if filepath not in current_files:
                deleted_files.append(filepath)
                print(f"  [DELETED] {filepath}")
                self._log_alert(f"FILE DELETED: {filepath}")

        # Summary
        print(f"\n{'='*60}")
        print(f"INTEGRITY CHECK SUMMARY")
        print(f"{'='*60}")
        print(f"Changed files:   {len(changed_files)}")
        print(f"New files:       {len(new_files)}")
        print(f"Deleted files:   {len(deleted_files)}")
        print(f"Unchanged files: {unchanged_count}")
        print(f"{'='*60}")

        if changed_files or new_files or deleted_files:
            print("\nWARNING: Changes detected! Review logs for details.")
            self._log_warning(
                f"Integrity check completed: {len(changed_files)} modified, "
                f"{len(new_files)} new, {len(deleted_files)} deleted"
            )
        else:
            print("\nAll files match baseline - No changes detected.")
            self._log_info("Integrity check completed: No changes detected")

    def add_path(self, path: str) -> None:
        """
        Add a new path to monitor.

        Args:
            path: Path or glob pattern to add
        """
        if path not in self.monitored_paths:
            self.monitored_paths.append(path)
            print(f"Added path to monitoring: {path}")
        else:
            print(f"Path already monitored: {path}")

    def _log_info(self, message: str) -> None:
        """Log informational message to syslog."""
        syslog.openlog("web-integrity-monitor", syslog.LOG_PID, syslog.LOG_DAEMON)
        syslog.syslog(syslog.LOG_INFO, message)
        syslog.closelog()

    def _log_warning(self, message: str) -> None:
        """Log warning message to syslog."""
        syslog.openlog("web-integrity-monitor", syslog.LOG_PID, syslog.LOG_DAEMON)
        syslog.syslog(syslog.LOG_WARNING, message)
        syslog.closelog()

    def _log_alert(self, message: str) -> None:
        """Log alert message to syslog."""
        syslog.openlog("web-integrity-monitor", syslog.LOG_PID, syslog.LOG_DAEMON)
        syslog.syslog(syslog.LOG_ALERT, message)
        syslog.closelog()

    def _log_error(self, message: str) -> None:
        """Log error message to syslog."""
        syslog.openlog("web-integrity-monitor", syslog.LOG_PID, syslog.LOG_DAEMON)
        syslog.syslog(syslog.LOG_ERR, message)
        syslog.closelog()


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Web Integrity Monitor - Detect website defacement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create initial baseline
  sudo python3 web_integrity_monitor.py --baseline

  # Run monitoring check (silent mode for cron/timer)
  sudo python3 web_integrity_monitor.py --monitor

  # Run monitoring with verbose output
  sudo python3 web_integrity_monitor.py --monitor --verbose

  # Add custom path to monitor
  sudo python3 web_integrity_monitor.py --add-path /opt/webapp
        """
    )

    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Create baseline hash database of monitored files"
    )

    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Monitor files and compare against baseline"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output during monitoring"
    )

    parser.add_argument(
        "--baseline-file",
        default="/var/lib/web-integrity/baseline.json",
        help="Path to baseline database file (default: /var/lib/web-integrity/baseline.json)"
    )

    parser.add_argument(
        "--add-path",
        metavar="PATH",
        help="Add custom path to monitor (use with --baseline)"
    )

    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        print("WARNING: Not running as root. This may cause permission issues.")
        print("Recommended: Run with sudo\n")

    monitor = WebIntegrityMonitor(baseline_file=args.baseline_file)

    # Add custom path if specified
    if args.add_path:
        monitor.add_path(args.add_path)

    if args.baseline:
        monitor.create_baseline()

    elif args.monitor:
        if args.verbose:
            monitor.monitor_verbose()
        else:
            # Silent mode for automated runs
            changed, new, deleted, unchanged = monitor.monitor()
            if changed > 0 or new > 0 or deleted > 0:
                sys.exit(1)  # Exit with error code if changes detected
            else:
                sys.exit(0)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

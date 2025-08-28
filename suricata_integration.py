import os
import sys
import json
import yaml
import time
import threading
import platform
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("suricata_alerts.log", encoding="utf-8")
    ],
)
logger = logging.getLogger("suricata_integration")

WIN_DEFAULT_LOG_DIR = Path(r"C:\Program Files\Suricata\log")
REPO_BASE = Path(os.getcwd())
REPO_SURICATA_DIR = REPO_BASE / "suricata"
REPO_LOG_DIR = REPO_SURICATA_DIR / "logs"
REPO_CONF = REPO_SURICATA_DIR / "suricata.yaml"

def ensure_dirs():
    for p in [REPO_SURICATA_DIR, REPO_LOG_DIR, REPO_SURICATA_DIR / "rules", REPO_SURICATA_DIR / "configs"]:
        p.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directory: {p}")

ensure_dirs()

def resolve_eve_paths():
    """Decide which eve.json to tail, preferring Windows service location when present."""
    win_eve = WIN_DEFAULT_LOG_DIR / "eve.json"
    repo_eve = REPO_LOG_DIR / "eve.json"
    candidates = []
    if platform.system().lower() == "windows" and win_eve.exists():
        candidates.append(win_eve)
    if repo_eve.exists():
        candidates.append(repo_eve)
    # If none exist yet, prefer Windows path if directory exists, else repo path
    if not candidates:
        if WIN_DEFAULT_LOG_DIR.exists():
            return win_eve, True
        return repo_eve, False
    # Choose the most recently modified file
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    return latest, (latest == win_eve)

class EveTailHandler(FileSystemEventHandler):
    def __init__(self, file_path: Path, on_alert):
        super().__init__()
        self.file_path = file_path
        self.on_alert = on_alert
        self._pos = 0
        self._lock = threading.Lock()
        # Initialize position to EOF if file exists
        if self.file_path.exists():
            self._pos = self.file_path.stat().st_size

    def process_new_lines(self):
        with self._lock:
            if not self.file_path.exists():
                return
            try:
                with self.file_path.open("r", encoding="utf-8", errors="replace") as f:
                    f.seek(self._pos)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                        except json.JSONDecodeError:
                            # Partial writes or rotate: wait next tick
                            continue
                        if evt.get("event_type") == "alert" and "alert" in evt:
                            try:
                                self.on_alert(evt)
                            except Exception as cb_err:
                                logger.error(f"Alert callback error: {cb_err}")
                    self._pos = f.tell()
            except FileNotFoundError:
                # Rotation: reset position
                self._pos = 0

    def on_modified(self, event):
        if Path(event.src_path) == self.file_path:
            self.process_new_lines()

    def on_created(self, event):
        # Reset on recreation (rotate/truncate)
        if Path(event.src_path) == self.file_path:
            self._pos = 0
            self.process_new_lines()

class SuricataWatcher:
    def __init__(self, on_alert):
        self.on_alert = on_alert
        self.observer = None
        self.handler = None
        self.dir_to_watch = None
        self.eve_path, self.using_windows_service = resolve_eve_paths()
        logger.info(f"EVE target: {self.eve_path} (windows_service={self.using_windows_service})")

    def start(self):
        self.dir_to_watch = self.eve_path.parent
        self.handler = EveTailHandler(self.eve_path, self.on_alert)
        self.observer = Observer()
        self.observer.schedule(self.handler, str(self.dir_to_watch), recursive=False)
        self.observer.start()
        logger.info(f"Watching directory for eve.json changes: {self.dir_to_watch}")

        # Background thread to poll in case some editors don't trigger modify events
        threading.Thread(target=self._poller, daemon=True).start()

    def _poller(self):
        while True:
            try:
                self.handler.process_new_lines()
            except Exception as e:
                logger.error(f"Poller error: {e}")
            time.sleep(1.5)

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()

# Example alert callback: enrich/route to DB, JIRA, Slack, etc.
def handle_suricata_alert(evt: dict):
    # Minimal demonstration log
    sig = evt.get("alert", {}).get("signature", "unknown")
    sev = evt.get("alert", {}).get("severity")
    src = f"{evt.get('src_ip')}:{evt.get('src_port')}"
    dst = f"{evt.get('dest_ip')}:{evt.get('dest_port')}"
    logger.info(f"SURICATA ALERT: [{sev}] {sig} {src} -> {dst}")

def start_suricata_tail(on_alert=handle_suricata_alert):
    watcher = SuricataWatcher(on_alert=on_alert)
    watcher.start()
    return watcher

if __name__ == "__main__":
    # Manual run for local testing
    watcher = start_suricata_tail()
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        watcher.stop()

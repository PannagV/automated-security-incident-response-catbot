import os
import json
import time
import threading
import platform
import logging
from pathlib import Path
from typing import Callable, Optional, Tuple, Dict, Any, List
from network_utils import detect_primary_network_interface
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging


# --------------------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("suricata_alerts.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("suricata_integration")
# --------------------------------------------------------------------------------------
# Paths and helpers
# --------------------------------------------------------------------------------------
WIN_DEFAULT_LOG_DIR: Path = Path(r"C:\Program Files\Suricata\log")
REPO_BASE: Path = Path(os.getcwd())
REPO_SURICATA_DIR: Path = REPO_BASE / "suricata"
REPO_CONFIG_DIR: Path = REPO_SURICATA_DIR / "configs"
REPO_RULES_DIR: Path = REPO_SURICATA_DIR / "rules"
REPO_LOG_DIR: Path = REPO_SURICATA_DIR / "logs"
REPO_CONF: Path = REPO_SURICATA_DIR / "suricata.yaml"

def ensure_dirs() -> None:
    """Create necessary directories with proper error handling."""
    dirs: List[Path] = [REPO_SURICATA_DIR, REPO_CONFIG_DIR, REPO_RULES_DIR, REPO_LOG_DIR]
    for p in dirs:
        try:
            p.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {p}")
        except OSError as e:
            logger.error(f"Failed to create directory {p}: {e}")
            # Continue with other directories

def resolve_eve_paths() -> Tuple[Path, bool]:
    """
    Decide which eve.json to tail, preferring the Windows service default if present.
    Returns (eve_path, using_windows_service_flag).
    """
    win_eve: Path = WIN_DEFAULT_LOG_DIR / "eve.json"
    repo_eve: Path = REPO_LOG_DIR / "eve.json"

    candidates: List[Path] = []
    
    # Check Windows service location
    try:
        if platform.system().lower() == "windows" and win_eve.exists():
            candidates.append(win_eve)
    except OSError:
        pass  # Path might be inaccessible
    
    # Check repository location
    try:
        if repo_eve.exists():
            candidates.append(repo_eve)
    except OSError:
        pass

    if not candidates:
        # No existing files, prefer Windows path if directory exists
        try:
            if platform.system().lower() == "windows" and WIN_DEFAULT_LOG_DIR.exists():
                return win_eve, True
        except OSError:
            pass
        return repo_eve, False

    # Choose most recently modified file
    try:
        latest: Path = max(candidates, key=lambda p: p.stat().st_mtime)
        return latest, (latest == win_eve)
    except OSError:
        # Fallback to first candidate if stat fails
        return candidates[0], (candidates[0] == win_eve)

# Initialize directories after defining the function
ensure_dirs()

# --------------------------------------------------------------------------------------
# EVE tailing
# --------------------------------------------------------------------------------------
class EveTailHandler(FileSystemEventHandler):
    file_path: Path
    on_alert: Callable[[dict], None]
    _pos: int
    _lock: threading.Lock

    def __init__(self, file_path: Path, on_alert: Callable[[dict], None]) -> None:
        super().__init__()
        self.file_path = file_path
        self.on_alert = on_alert
        self._pos = 0
        self._lock = threading.Lock()
        
        # Initialize position to EOF if file exists
        try:
            if self.file_path.exists():
                self._pos = self.file_path.stat().st_size
        except OSError as e:
            logger.warning(f"Could not get file size for {self.file_path}: {e}")
            self._pos = 0

    def process_new_lines(self) -> None:
        """Process new lines with robust error handling."""
        with self._lock:
            try:
                if not self.file_path.exists():
                    logger.debug(f"File {self.file_path} does not exist yet")
                    return
                
                # Check if file is readable
                if not os.access(self.file_path, os.R_OK):
                    logger.error(f"No read permission for {self.file_path}")
                    return
                    
                with self.file_path.open("r", encoding="utf-8", errors="replace") as f:
                    f.seek(self._pos)
                    for raw in f:
                        line: str = raw.strip()
                        if not line:
                            continue
                        
                        try:
                            evt: dict = json.loads(line)
                        except json.JSONDecodeError as e:
                            logger.debug(f"JSON decode error: {e} for line: {line[:100]}")
                            continue
                        
                        if evt.get("event_type") == "alert" and "alert" in evt:
                            try:
                                self.on_alert(evt)
                            except Exception as cb_err:
                                logger.error(f"Alert callback error: {cb_err}", exc_info=True)
                    
                    self._pos = f.tell()
                    
            except PermissionError as e:
                logger.error(f"Permission error reading {self.file_path}: {e}")
            except FileNotFoundError:
                logger.info(f"File {self.file_path} was removed/rotated")
                self._pos = 0
            except OSError as e:
                logger.error(f"OS error processing {self.file_path}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error in process_new_lines: {e}", exc_info=True)


        def on_modified(self, event) -> None:
            if Path(event.src_path) == self.file_path:
                self.process_new_lines()

        def on_created(self, event) -> None:
            if Path(event.src_path) == self.file_path:
                logger.info(f"File {self.file_path} was created")
                self._pos = 0
                self.process_new_lines()

class SuricataWatcher:
    """
    Tails eve.json and invokes a callback for each alert.
    Exposes attributes/methods expected by app.py for compatibility.
    """
    on_alert: Callable[[dict], None]
    interface: Optional[str]
    observer: Optional[Observer] # type: ignore
    handler: Optional[EveTailHandler]
    dir_to_watch: Optional[Path]
    eve_path: Path
    using_windows_service: bool
    eve_json_path: Path
    _running: bool
    _stop_event: threading.Event

    def __init__(self, on_alert: Callable[[dict], None], interface: Optional[str] = None) -> None:
        self.on_alert = on_alert
        self.interface = interface
        self.observer = None
        self.handler = None
        self.dir_to_watch = None
        self._stop_event = threading.Event()

        eve_path, win_flag = resolve_eve_paths()
        self.eve_path = eve_path
        self.using_windows_service = win_flag

        # Compatibility attribute expected by app.py
        self.eve_json_path = self.eve_path
        self._running = False

        logger.info(
            f"EVE target: {self.eve_path} "
            f"(windows_service={self.using_windows_service}, interface={self.interface})"
        )

    def start(self) -> None:
        """Start with validation."""
        try:
            # Validate paths and permissions before starting threads
            if not self.eve_path.parent.exists():
                logger.error(f"Directory {self.eve_path.parent} does not exist")
                raise FileNotFoundError(f"Directory {self.eve_path.parent} does not exist")
            
            self.dir_to_watch = self.eve_path.parent
            self.handler = EveTailHandler(self.eve_path, self.on_alert)
            self.observer = Observer()
            self.observer.schedule(self.handler, str(self.dir_to_watch), recursive=False)
            self.observer.start()
            self._running = True
            self._stop_event.clear()
            
            logger.info(f"Watching directory: {self.dir_to_watch}")

            # Validate _poller is callable before starting thread
            if not callable(self._poller):
                raise TypeError("_poller is not callable")
                
            threading.Thread(target=self._poller, daemon=True).start()
            
        except Exception as e:
            logger.error(f"Failed to start Suricata watcher: {e}", exc_info=True)
            self._cleanup()
            raise


    def _poller(self) -> None:
        """Background polling thread with enhanced error handling."""
        try:
            while not self._stop_event.is_set():
                try:
                    if self._running and self.handler is not None:
                        self.handler.process_new_lines()
                except PermissionError as e:
                    logger.error(f"Permission denied accessing eve.json: {e}")
                    self._stop_event.wait(5)  # Wait longer on permission issues
                except FileNotFoundError as e:
                    logger.error(f"Eve.json file not found: {e}")
                    self._stop_event.wait(2)
                except OSError as e:
                    logger.error(f"OS error in poller: {e}")
                    self._stop_event.wait(2)
                except Exception as e:
                    logger.error(f"Unexpected error in poller: {e}", exc_info=True)
                    self._stop_event.wait(1)
                
                self._stop_event.wait(1.5)
        except Exception as e:
            logger.error(f"Critical error in poller thread: {e}", exc_info=True)


    def stop(self) -> None:
        """Stop the file watcher and cleanup resources."""
        logger.info("Stopping Suricata watcher...")
        self._running = False
        self._stop_event.set()
        
        self._cleanup()
        logger.info("Stopped Suricata watcher")

    def _cleanup(self) -> None:
        """Clean up observer and handler resources."""
        try:
            if self.observer is not None:
                self.observer.stop()
                self.observer.join(timeout=5.0)  # Don't wait forever
                if self.observer.is_alive():
                    logger.warning("Observer thread did not stop within timeout")
        except Exception as e:
            logger.error(f"Error stopping observer: {e}")
        finally:
            self.observer = None
            self.handler = None

    def start_with_detected_interface(self) -> bool:
        """Start Suricata manager with automatically detected network interface."""
        try:
            # Run network detection before starting Suricata
            detected_interface = detect_primary_network_interface()
            logger.info(f"Detected network interface: {detected_interface}")
            
            # Update the interface for the watcher
            if not self._running:
                self.watcher = SuricataWatcher(on_alert=self.watcher.on_alert, interface=detected_interface)
                self.eve_json_path = self.watcher.eve_json_path
                return self.start()
            return True
        except Exception as e:
            logger.error(f"Failed to start with detected interface: {e}")
            return False


    def get_status(self) -> Dict[str, Any]:
        """Get current status of the watcher."""
        eve_exists = False
        try:
            eve_exists = self.eve_json_path.exists()
        except OSError:
            pass  # Path might be inaccessible

        return {
            "suricata_running": self._running,
            "eve_json_path": str(self.eve_json_path),
            "eve_exists": eve_exists,
            "using_windows_service": self.using_windows_service,
        }

class SuricataManager:
    """
    Facade to avoid changing existing app.py routes:
      - get_status()
      - start(), stop()  
      - eve_json_path attribute
    Internally uses SuricataWatcher (log tailer).
    """
    watcher: SuricataWatcher
    eve_json_path: Path
    _running: bool

    def __init__(self, on_alert: Optional[Callable[[dict], None]] = None, interface: Optional[str] = None) -> None:
        # Provide a safe default callback if none is provided
        if on_alert is None:
            def default_alert_handler(evt: dict) -> None:
                logger.info(f"Default alert handler: {evt.get('alert', {}).get('signature', 'Unknown alert')}")
            on_alert = default_alert_handler

        self.watcher = SuricataWatcher(on_alert=on_alert, interface=interface)
        self.eve_json_path = self.watcher.eve_json_path
        self._running = False

    def start(self) -> bool:
        """Start the Suricata manager."""
        try:
            if not self._running:
                self.watcher.start()
                self._running = True
                # Update path in case it changed
                self.eve_json_path = self.watcher.eve_json_path
            return True
        except Exception as e:
            logger.error(f"Failed to start SuricataManager: {e}")
            return False

    def stop(self) -> bool:
        """Stop the Suricata manager."""
        try:
            if self._running:
                self.watcher.stop()
                self._running = False
            return True
        except Exception as e:
            logger.error(f"Error stopping SuricataManager: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get status from the underlying watcher."""
        try:
            status: Dict[str, Any] = self.watcher.get_status()
            status["suricata_running"] = self._running and status.get("suricata_running", False)
            status["eve_json_path"] = str(self.eve_json_path)
            return status
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return {
                "suricata_running": False,
                "eve_json_path": str(self.eve_json_path),
                "eve_exists": False,
                "using_windows_service": False,
                "error": str(e)
            }
def update_suricata_config_interface(config_path: Path, interface: str) -> bool:
    """Update the Suricata configuration file with the detected interface."""
    try:
        if not config_path.exists():
            logger.error(f"Suricata config file not found: {config_path}")
            return False
            
        # Read the current config
        with open(config_path, 'r') as f:
            content = f.read()
        
        # Replace the interface in af-packet section
        import re
        pattern = r'(af-packet:\s*\n\s*-\s*interface:\s*)["\']?[^"\'\s]+["\']?'
        replacement = f'\\1"{interface}"'
        
        updated_content = re.sub(pattern, replacement, content)
        
        # Write back the updated config
        with open(config_path, 'w') as f:
            f.write(updated_content)
            
        logger.info(f"Updated Suricata config with interface: {interface}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to update Suricata config: {e}")
        return False

def handle_suricata_alert(evt: dict) -> None:
    """Default alert handler that logs alerts."""
    try:
        alert_obj: dict = evt.get("alert", {}) if isinstance(evt, dict) else {}
        sig: str = str(alert_obj.get("signature", "unknown"))
        sev = alert_obj.get("severity", "unknown")
        src = f"{evt.get('src_ip')}:{evt.get('src_port')}" if evt.get("src_ip") else "?:?"
        dst = f"{evt.get('dest_ip')}:{evt.get('dest_port')}" if evt.get("dest_ip") else "?:?"
        logger.info(f"SURICATA ALERT: [{sev}] {sig} {src} -> {dst}")
    except Exception as e:
        logger.error(f"Error in handle_suricata_alert: {e}")

def start_suricata_tail(
    on_alert: Optional[Callable[[dict], None]] = None,
    interface: Optional[str] = None,
) -> SuricataManager:
    """Convenience function to create and start a SuricataManager."""
    cb: Callable[[dict], None] = on_alert if on_alert is not None else handle_suricata_alert
    mgr: SuricataManager = SuricataManager(on_alert=cb, interface=interface)
    
    # Use detected interface if none provided
    if interface is None:
        success = mgr.start_with_detected_interface()
    else:
        success = mgr.start()
    
    if not success:
        logger.error("Failed to start Suricata manager")
    return mgr


if __name__ == "__main__":
    manager = start_suricata_tail()
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        manager.stop()

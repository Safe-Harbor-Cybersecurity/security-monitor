import logging
import psutil
import time
from datetime import datetime
import hashlib
import os
from typing import Dict, List, Tuple
import json

class SecurityMonitor:
    def __init__(self, config_path: str = "monitor_config.json"):
        """Initialize security monitoring system."""
        # Set up logging
        logging.basicConfig(
            filename='security_monitor.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Load configuration
        self.config = self._load_config(config_path)
        self.baseline_hashes = {}
        self.suspicious_events = []
        
    def _load_config(self, config_path: str) -> Dict:
        """Load monitoring configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Default configuration
            return {
                "critical_paths": ["/etc", "/bin", "/sbin"],
                "monitored_ports": [80, 443, 22],
                "resource_thresholds": {
                    "cpu_percent": 90,
                    "memory_percent": 85,
                    "disk_percent": 90
                },
                "scan_interval": 300  # 5 minutes
            }

    def establish_baseline(self) -> None:
        """Create baseline hashes of critical system files."""
        logging.info("Establishing baseline file signatures...")
        for path in self.config["critical_paths"]:
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        try:
                            with open(full_path, 'rb') as f:
                                file_hash = hashlib.sha256(f.read()).hexdigest()
                                self.baseline_hashes[full_path] = file_hash
                        except (PermissionError, FileNotFoundError):
                            continue
        
        logging.info(f"Baseline established for {len(self.baseline_hashes)} files")

    def check_system_resources(self) -> List[str]:
        """Monitor system resource usage for anomalies."""
        alerts = []
        
        # Check CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > self.config["resource_thresholds"]["cpu_percent"]:
            alerts.append(f"High CPU usage detected: {cpu_percent}%")
            
        # Check memory usage
        memory = psutil.virtual_memory()
        if memory.percent > self.config["resource_thresholds"]["memory_percent"]:
            alerts.append(f"High memory usage detected: {memory.percent}%")
            
        # Check disk usage
        disk = psutil.disk_usage('/')
        if disk.percent > self.config["resource_thresholds"]["disk_percent"]:
            alerts.append(f"High disk usage detected: {disk.percent}%")
            
        return alerts

    def check_open_ports(self) -> List[str]:
        """Monitor for unauthorized open ports."""
        alerts = []
        connections = psutil.net_connections()
        
        open_ports = set(conn.laddr.port for conn in connections if conn.status == 'LISTEN')
        unauthorized_ports = open_ports - set(self.config["monitored_ports"])
        
        if unauthorized_ports:
            alerts.append(f"Unauthorized open ports detected: {unauthorized_ports}")
            
        return alerts

    def verify_file_integrity(self) -> List[str]:
        """Check for modifications to critical system files."""
        alerts = []
        
        for path, original_hash in self.baseline_hashes.items():
            try:
                with open(path, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != original_hash:
                    alert = f"File modification detected: {path}"
                    alerts.append(alert)
                    logging.warning(alert)
            except (PermissionError, FileNotFoundError):
                continue
                
        return alerts

    def monitor_system(self) -> None:
        """Main monitoring loop."""
        try:
            self.establish_baseline()
            
            while True:
                alerts = []
                alerts.extend(self.check_system_resources())
                alerts.extend(self.check_open_ports())
                alerts.extend(self.verify_file_integrity())
                
                if alerts:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    for alert in alerts:
                        logging.warning(f"{timestamp} - {alert}")
                    self.suspicious_events.extend(alerts)
                
                time.sleep(self.config["scan_interval"])
                
        except KeyboardInterrupt:
            logging.info("Monitoring stopped by user")
        except Exception as e:
            logging.error(f"Monitoring error: {str(e)}")

if __name__ == "__main__":
    monitor = SecurityMonitor()
    monitor.monitor_system()

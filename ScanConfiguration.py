import json
import logging
import os

#
# represent a scan configuration file.
#
# The file describes scan configurations, and provides a name for each of them.
# It allows preset scan configurations to be set up to prevent typing in lengthy args at the command line.
# Instead, just run with -n <scan name> and it uses the args that are set up for the named scan.
# The location of the scan config file is controlled by the environment var "SNYK_R3_SCAN_CONFIG".
#
# The config file is a JSON formatted file; this class just thinly wraps that.
#
class ScanConfiguration:

    def __init__(self):
        self.filename = ""
        if "SNYK_R3_SCAN_CONFIG" in os.environ:
            self.filename = os.environ["SNYK_R3_SCAN_CONFIG"]
            self.json_data = self._load_config()

    def _load_config(self):
        try:
            with open(self.filename, 'r') as f:
                config = json.load(f)
            return config
        except FileNotFoundError:
            logging.info("No scan configuration file found")
            return None
        except json.JSONDecodeError:
            log.error("Failed to read scan configuration file - JSON error")
            return None
    
    def has_scan(self,scan_name):
        if self.json_data:
            if scan_name in self.json_data["scans"]:
                return True
            else:
                return False
        else:
            return False

    def get_scan_property(self, scan_name, property_name):
        return self.json_data["scans"][scan_name][property_name]

    def get_scan_names(self):
        scansList = []

        for name in self.json_data["scans"]:
            scansList.append(name)
        return scansList

    def get_scan_config_filename(self):
        pass




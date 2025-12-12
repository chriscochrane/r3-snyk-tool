import json
import logging
import os

from .Vulnerability import Vulnerability

class ScanReport:

    def __init__(self, reportFile):
        self.criteria = {}
        self.filename = reportFile
        self.json_data = self._load_report()

    def _load_report(self):
        try:
            with open(self.filename, 'r') as f:
                report_data = json.load(f)
            return report_data
        except FileNotFoundError:
            logging.info("Report file not found")
            return None
        except json.JSONDecodeError:
            log.error("Failed to read scan report file - JSON error")
            return None
    

    # set the criteria for matching vulns
    # delimited list of key:value pairs
    # e.g
    # type:open;severity:high;score:7.9
    def set_criteria(self, crit):
        if not crit:
            print("Warning: Input string is empty.")
            return {}

        # Split the string into individual key-value pair segments
        pairs = crit.split(';')

        for pair in pairs:
            # Strip whitespace from the pair string
            stripped_pair = pair.strip()
            if not stripped_pair:
                continue # Skip empty segments that might result from extra semicolons

            # Split each segment into key and value
            parts = stripped_pair.split(':', 1) # Use 1 to split only on the first colon

            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                if key: # Ensure key is not empty
                    self.criteria[key] = value
                else:
                    print(f"Warning: Skipping malformed pair with empty key: '{stripped_pair}'")
            else:
                print(f"Warning: Skipping malformed pair (missing colon or value): '{stripped_pair}'")


    
    def get_matches(self):
        matched_vulns = {}

        numVulns = len(self.json_data['open']['vulnerabilities'])
        for n in range(numVulns):
            include_vuln = True
            for crit_key,crit_val in self.criteria.items():
                # if criteria specifies a known vuln attrib, make sure the values match
                # if they don't, then don't include the vuln
                if crit_key in self.json_data['open']['vulnerabilities'][n]:
                    # TBD special handling for path
                    vulnVal = self.json_data['open']['vulnerabilities'][n][crit_key]
                    if crit_val != vulnVal:
                        include_vuln = False
                else:
                    # criteria key not known in vuln; don't include it
                    include_vuln = False


            if include_vuln:
                id = self.json_data['open']['vulnerabilities'][n]['id']
                snyk = self.json_data['open']['vulnerabilities'][n]['snyk']
                sev = self.json_data['open']['vulnerabilities'][n]['severity']
                title = self.json_data['open']['vulnerabilities'][n]['title']
                score = self.json_data['open']['vulnerabilities'][n]['score']
                cwe = self.json_data['open']['vulnerabilities'][n]['cwe']
                cve = self.json_data['open']['vulnerabilities'][n]['cve']
                name = self.json_data['open']['vulnerabilities'][n]['name']
                fixed = self.json_data['open']['vulnerabilities'][n]['fixed']

                matched_vulns[id] = Vulnerability(snyk, sev, title, score, cwe, cve, name, fixed)

                num_paths = len(self.json_data['open']['vulnerabilities'][n]['paths'])
                for p in range(num_paths):
                    path = self.json_data['open']['vulnerabilities'][n]['paths'][p]
                    matched_vulns[id].add_path(path)
        
        return matched_vulns

        


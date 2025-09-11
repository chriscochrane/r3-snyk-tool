import json
from Vulnerability import Vulnerability

#
# represent a scanned snyk project
#
class Project:
    def __init__(self, project_name, json_data):
        self.project_name = project_name
        self.json_data = json_data
        self.vuln_index = {}
        
        self._build_vulnerability_index()    # safe to do this here?


    # build an index of the vulnerabilities found in this project
    def _build_vulnerability_index(self):
        numVulns = len(self.json_data['vulnerabilities'])
        for n in range(numVulns):
            id = self.json_data['vulnerabilities'][n]['id']
            sev = self.json_data['vulnerabilities'][n]['severity']
            title = self.json_data['vulnerabilities'][n]['title']
            score = self.json_data['vulnerabilities'][n]['cvssScore']
            cwe = self.json_data['vulnerabilities'][n]['identifiers']['CWE']
            cve = self.json_data['vulnerabilities'][n]['identifiers']['CVE']
            name = self.json_data['vulnerabilities'][n]['name']
            fixed = self.json_data['vulnerabilities'][n]['fixedIn']
            path = self.json_data['vulnerabilities'][n]['from']

            if id in self.vuln_index:
                self.vuln_index[id].add_path(path)
            else:
                self.vuln_index[id] = Vulnerability(id, sev, title, score, cwe, cve, name, fixed, path)

    # decide if a vuln should be added to the report, based on what paths where specified at the command line.
    def _should_add_vuln(self,match_path,vuln):
        add_vuln = False
        if not match_path:
            add_vuln=True
        else:
            for p in vuln.paths:    # paths
                for pe in p:        # path-elements
                    if match_path in pe:
                        add_vuln=True
                        break

        return add_vuln


    # get the open i.e. unresolved vulnerabilities in this project
    def get_open_vulnerabilities(self,match_path=None) -> set:
        vulnsSet = set()

        # vulns that can be fixed by upgrading
        if "remediation" in self.json_data:
            moduleNames = self.json_data['remediation']['upgrade'].keys()
            for n in moduleNames:
                if "upgrade" in self.json_data['remediation']:
                    vulnsSize = len(self.json_data['remediation']['upgrade'][n]['vulns'])
                    for m in range(vulnsSize):
                        id = self.json_data['remediation']['upgrade'][n]['vulns'][m]
                        sev = 'unknown'
                        if id in self.vuln_index:
                            sev = self.vuln_index[id].severity

                        if self._should_add_vuln(match_path,self.vuln_index[id]):
                            vulnsSet.add(
                                self.vuln_index[id]
                            )
        
        # vulns that apparently have no resolution yet
        if "remediation" in self.json_data:
            if "unresolved" in self.json_data["remediation"]:
                vulnsSize = len(self.json_data['remediation']['unresolved'])
                for n in range(vulnsSize):
                    id = self.json_data['remediation']['unresolved'][n]['id']
                    if self._should_add_vuln(match_path,self.vuln_index[id]):
                        vulnsSet.add(
                            self.vuln_index[id]
                        )
        return vulnsSet

    # get the vulnerabilities that have been waivered in this project
    def get_waivered_vulnerabilities(self) -> set:
        vulnsSet = set()

        if "filtered" in self.json_data:
            if "ignore" in self.json_data["filtered"]:
                vulnsSize = len(self.json_data['filtered']['ignore'])
                for n in range(vulnsSize):
                    vulnsSet.add(
                        Vulnerability(self.json_data['filtered']['ignore'][n]['id'],
                                      self.json_data['filtered']['ignore'][n]['severity'],
                                      self.json_data['filtered']['ignore'][n]['title'],
                                      self.json_data['filtered']['ignore'][n]['cvssScore'],
                                      self.json_data['filtered']['ignore'][n]['identifiers']['CWE'],
                                      self.json_data['filtered']['ignore'][n]['identifiers']['CVE'],
                                      self.json_data['filtered']['ignore'][n]['name'],
                                      self.json_data['filtered']['ignore'][n]['fixedIn']
                        )
                    )
        return vulnsSet

    def get_snyk_json_report(self):
        return self.json_data


    
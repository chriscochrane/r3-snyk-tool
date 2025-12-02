import subprocess
import json
import os
import sys
import logging
from JsonLogWriter import JsonLogWriter
from Project import Project
from ScanConfiguration import ScanConfiguration
from datetime import datetime


# Represent a snyk scan

class Snyk:
    def __init__(self, project_dir=None, user_projects=None, scan_type=None, scan_name=None):

        self.buildfile = "build.gradle"
        self.scan_timestamp = f"{datetime.now().strftime('%Y%m%d-%H%M%S%f')[:-4]}"
        self.project_dir = "."
        self.scan_type = "dev"
        self.user_projects = []
        self.project_mapping = {}
        self.scan_error = None

        # read stuff out of the scan configuration, if one was specified
        # (and it is a recognised name)
        if scan_name:
            scan_config = ScanConfiguration()
            self.dump_snyk = scan_config.dump_snyk_is_active()

            if scan_config.has_scan(scan_name):
                self.project_dir = scan_config.get_scan_property(scan_name,"root")
                self.scan_type = scan_config.get_scan_property(scan_name,"type")
                self.user_projects = scan_config.get_scan_property(scan_name,"sub-projects")
                self.project_mapping = scan_config.get_scan_property(scan_name,"project-mapping")

                if scan_config.has_scan_property(scan_name,"buildfile"):
                    self.buildfile = scan_config.get_scan_property(scan_name,"buildfile")
                    if not self.buildfile:
                        self.buildfile = "build.gradle"
            else:
                logging.error(f"Scan [{scan_name}] not found")
                raise ValueError(f"Unknown scan [{scan_name}]")

        # args specified on the command line override anything from the named scan configuration
        if project_dir:
            self.project_dir = project_dir
        
        if user_projects:
            self.user_projects = user_projects

        if scan_type:
            self.scan_type = scan_type

        # if all else has failed, assume we're actually in the project to be scanned
        if self.project_dir is None:
            self.project_dir = os.getcwd()

        # other (internal) stuff
        self.all_gradle_projects = set()    # list of discovered gradle projects
        self.is_tested = False              # has a test been run?
        self.scanned_projects = {}          # project data that has been scanned, indexed by project name


    # Discover all the gradle projects within the project dir
    #
    # This is done by looking for build.gradle files, and taking the project name to be the path to that build file.
    #
    # Note that there are instances where the Gradle project name does not match the pathname of the build file.
    # In those cases, typically the project name is configured actually in the build file, or in a settings file, but seeing as
    # this app is not actually 'properly processing' the gradle project, it can't see that.
    # To that end, self.project_mapping provides a mapping between a project directory and it's actual name. The actual name is
    # needed to pass on to Snyk, since Snyk is much cleverer and properly understands Gradle projects.
    #
    # This would better is there was a way to examine gradle project properly in Python...
    #
    def _discover_gradle_projects(self):
        logging.info(f"Discovering Gradle projects in [{self.project_dir}]")
        try:
            # find all build.gradles, get their dir path
            command = ["find", self.project_dir, "-type", "f", "-name", self.buildfile, "-exec", "dirname", "{}", ";"]
            logging.info(f"Running [{" ".join(command)}]")
            process = subprocess.run(command, capture_output=True, text=True, check=True)
            output = process.stdout.strip()
            if output:
                output_list = output.split('\n')
                # trim out the root-dir portion of the dir name
                output_list = [s.replace(f"{self.project_dir}/","") for s in output_list]
                output_list = [s.replace(f"{self.project_dir}","") for s in output_list]
                # map dir names to project names, as described in project_mapping
                for project_path, project_name in self.project_mapping.items():
                    output_list = [s.replace(project_path,project_name) for s in output_list]
                self.all_gradle_projects = set(output_list)

                logging.info(f"Found: {self.all_gradle_projects}")

        except subprocess.CalledProcessError as e:
            logging.error(f"Error running find command: {e}")
            logging.error(f"stderr: {e.stderr}")
        except FileNotFoundError:
            logging.error("Error: The 'find' command was not found. Please ensure it's in your system's PATH.")      


    # run a snyk test
    def _run_test(self):
        if self.is_tested:
            return

        self._discover_gradle_projects()
        projects_to_scan = set()

        # if some projects were specified at the commnd line, try to use them.
        # otherwise just scan everything.
        if not self.user_projects:
            projects_to_scan = self.all_gradle_projects
        else:
            for p in self.user_projects:
                if p in self.all_gradle_projects:
                    projects_to_scan.add(p)
                else:
                    logging.warn(f"The project '{p}' was not found; ignoring.")
        
        if not projects_to_scan:
            logging.info("No projects to scan.")
            return

        jsonLogger = None
        if self.dump_snyk:
            jsonLogger = JsonLogWriter(self.scan_timestamp)
        
        for p in projects_to_scan:
            # Run actual Snyk test with specified options
            logging.info(f"scanning project [{p}]")
            params = ['snyk', 'test', self.project_dir, 
                    '--show-vulnerable-paths=all', 
                    '--json'
                    ]
            
            # if there's a specific sub-project to scan, add it to the args
            if p != "":
                params.append(f'--sub-project={p}')
            
            # if scanning a dev project, we're only interested in the runtime vulnerabilities.
            # vulnerabilities with test configurations, metadata, etc. - don't care about those
            if self.scan_type == 'dev':
                params.append(f'--configuration-matching=^runtimeClasspath$')

            logging.info(f"Running [{" ".join(params)}]")

            # actually run Snyk and capture its output
            result = subprocess.run(
                params,
                capture_output=True, 
                text=True,
                check=False
            )
            # parse the result for errors
            json_data = json.loads(result.stdout)
            if "error" in json_data:
                json_err = json_data["error"]
                if json_err.startswith("Specified sub-project not found:"):
                    # this specific error - just log something and carry on
                    logging.info(f"Snyk failed to find sub-project [{p}]; ignoring")
                    continue
                else:
                    logging.error(f"Snyk failed for project [{p}]")
                    # consider this sort of error as fatal - there is something fundamenetally wrong
                    self.scan_error = json_err
                    break

            else:
                # Create a project object to hold/parse the scan result data, and provide access
                # to the vulnerabilities within.
                new_project = Project(p, json_data)
                self.scanned_projects[p] = new_project

                if jsonLogger:
                    jsonLogger.write_to_file(p,json_data)

        # finally compress the log dir
        if jsonLogger:
            jsonLogger.compress()
        
        self.is_tested = True


    # collect the open (i.e. unresolved) vulnerabilities
    def get_open_vulnerabilities(self,match_path) -> set:
        self._run_test()
        vulnsSet = set()
        vulnsLookup = {}

        # collect the open vulns for all scanned projects
        for p in self.scanned_projects.values():
            project_vulns = p.get_open_vulnerabilities(match_path)
            for pv in project_vulns:
                # a single vuln can be reported from multiple projects, so
                # be sure to collapse paths for the same vuln/different projects
                # into the same vuln item
                if pv.id in vulnsLookup:
                    # a known vuln; merge together
                    existingVuln = vulnsLookup[pv.id]
                    existingVuln.merge_with(pv)
                else:
                    # new vuln; just add it
                    vulnsSet.add(pv)
                    vulnsLookup[pv.id] = pv

        return vulnsSet

    # collect the waivered vulnerabilities
    def get_waivered_vulnerabilities(self) -> set:
        self._run_test()
        vulnsSet = set()
        # collect the waivered vulns for all scanned projects
        # don't really care about same waiver in multiple projects, the waiver is the waiver
        for p in self.scanned_projects.values():
            project_vulns = p.get_waivered_vulnerabilities()
            vulnsSet.update(project_vulns)           
        
        return vulnsSet







    

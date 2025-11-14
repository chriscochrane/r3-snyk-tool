from jira import JIRA
from ScanConfiguration import ScanConfiguration
import logging
import subprocess


class JiraQuery:
    """
    A class to manage the connection and execution of JQL queries 
    against a Jira instance.
    """
    def __init__(self, server: str, email: str, api_token: str, scan_name : str):
        self.server = server
        self.email = email
        self.api_token = api_token
        self.jira = None
        self.scan_name = scan_name
        
        try:
            # Establish the connection using basic authentication (email + API token)
            logging.info(f"Connecting to Jira at [{self.server}]")
            self.jira = JIRA(server=self.server, basic_auth=(self.email, self.api_token))
        except Exception as e:
            logging.error(f"Failed to connect to Jira at {self.server}. Error: {e}")
            # Ensure jira is None if connection fails
            self.jira = None


    def _get_current_git_branch(self, path: str = ".") -> str | None:
        """
        Retrieves the name of the current Git branch for the repository at the given path.

        Args:
            path (str): The path to the Git repository (defaults to the current directory).

        Returns:
            str | None: The name of the current branch, or None if an error occurs 
                        (e.g., not a Git repository or Git is not installed).
        """
        try:
            # The command 'git rev-parse --abbrev-ref HEAD' is the standard way 
            # to get the current branch name.
            # - check=True raises a CalledProcessError if the command returns a non-zero exit code.
            # - capture_output=True captures stdout and stderr.
            # - text=True decodes stdout and stderr as strings (using the default system encoding).
            result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=path,
                check=True,
                capture_output=True,
                text=True
            )

            # The output is often followed by a newline, so we strip whitespace.
            branch_name = result.stdout.strip()
            
            if branch_name == 'HEAD':
                # This happens in a detached HEAD state (e.g., after checking out a commit hash).
                print(f"Warning: Repository at '{path}' is in a detached HEAD state.")
                return None
                
            return branch_name

        except subprocess.CalledProcessError as e:
            # Handle errors, such as the path not being a Git repository.
            print(f"Error executing Git command in '{path}':")
            print(f"    Return Code: {e.returncode}")
            print(f"    Stderr: {e.stderr.strip()}")
            print("This usually means the directory is not a Git repository.")
            return None
        except FileNotFoundError:
            # Handle the case where the 'git' executable itself is not found (Git not installed or not in PATH).
            print("Error: The 'git' command was not found. Please ensure Git is installed and accessible in your system's PATH.")
            return None




    def _query(self) -> list:
        if not self.jira:
            logging.warn("Cannot execute query. Jira connection is not active.")
            return []
        
        # comment-in when you want to find out more fields to query
        # fields_list = self.jira.fields()
        # print("Available Jira Fields:")
        # for field in fields_list:
        #     # Print the technical ID (key) and the human-readable name
        #     logging.info(f"ID: {field['id']} \t Name: {field['name']}")

        jira_filter = None
        project_dir = "."

        if self.scan_name != None:
            scan_config = ScanConfiguration()
            if scan_config.has_scan(self.scan_name):
                # get the filter to use - require this so as not to issue stupid queries
                if scan_config.has_scan_property(self.scan_name, "jira_filter_id"):
                    jira_filter = scan_config.get_scan_property(self.scan_name, "jira_filter_id")
                # get the project root dir, so the git branch can be found
                if scan_config.has_scan_property(self.scan_name, "root"):
                    project_dir = scan_config.get_scan_property(self.scan_name, "root")
            else:
                logging.error(f"Scan [{self.scan_name}] not known")

        if jira_filter == None:
            logging.warning("No filter specified and so not going to query Jira.")
            return []

         # figure out the current project/version from the current git branch
        curr_branch = self._get_current_git_branch(project_dir)
        query_text = f"filter = {jira_filter} AND status != Done AND summary ~ '{curr_branch}'"

        logging.info(f"Executing JQL: {query_text}")

        try:
            # Execute the search. maxResults=False fetches all results.
            issues = self.jira.search_issues(query_text, maxResults=False, fields=["summary", "created"])
            return issues

        except Exception as e:
            logging.error(f"Error executing JQL '{query_text}'. Error: {e}")
            return []

    # get the ticket IDs for the current project
    def get_vuln_jira_ids(self) -> list[str]:
        jira_issues = self._query()
        ticket_ids = [issue.key for issue in jira_issues] 
        return ticket_ids


    # given a list of vulnerabilities, find out and attach the jira ID for each one
    def attach_jira_ids(self, vulns : set):
        # query the jira issue
        jira_issues = self._query()
        jira_index = {}

        # index them by their CVE (taken from the summary)
        for ji in jira_issues:
            summary = ji.fields.summary
            start_pos = summary.find("CVE")
            if start_pos == -1:
                start_pos = summary.find("CWE")
            if start_pos == -1:
                continue

            cve_id = summary[start_pos:]
            jira_index[cve_id] = ji.key

        # iterate through vulns - get their CVE
        for v in vulns:
            # can be multiple CVEs; just get the jira for one
            for vuln_cve in v.cve:
                if vuln_cve in jira_index:
                    v.jira_id = jira_index[vuln_cve]
                    break



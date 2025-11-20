from jira import JIRA, JIRAError
from jira.resources import Issue
from ScanConfiguration import ScanConfiguration
import logging
import subprocess
from enum import StrEnum


# Jira fields we care about
class JiraFieldId(StrEnum):
    SUMMARY = "summary",
    CREATED = "created",
    STATUS = "status",
    FIX_VERSION = "fixVersions",
    REQUIRES_REL_NOTE = "customfield_12324",
    REQUIRES_DOC_CHANGES = "customfield_12214",
    REL_NOTE = "customfield_11802"


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
        self.git_branch = None
        
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
        self.git_branch = self._get_current_git_branch(project_dir)
        query_text = f"filter = {jira_filter} AND {JiraFieldId.STATUS} != Done AND {JiraFieldId.STATUS} != 'Waiver Provided' AND {JiraFieldId.STATUS} != 'Descope' AND {JiraFieldId.SUMMARY} ~ '{self.git_branch}'"
        logging.info(f"Executing JQL: {query_text}")
        try:
            # Execute the search. maxResults=False fetches all results/disables pagination
            issues = self.jira.search_issues(query_text, maxResults=False, fields=[JiraFieldId.SUMMARY, JiraFieldId.CREATED])
            return issues
        except Exception as e:
            logging.error(f"Error executing JQL '{query_text}'. Error: {e}")
            return []

    # get the Jira fields
    def get_fields(self) -> list:
        if not self.jira:
            logging.warn("Cannot execute query. Jira connection is not active.")
            return []
        return self.jira.fields()


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

    def _prepare_for_status_change(self, issue: Issue) :
        issue_key = issue.key
        logging.info(f"Attempting to update mandatory fields for {issue_key}")
        
        # 1. Define fields for update
        # Yes/No fields are typically updated by passing the value as a dictionary 
        # with the 'value' key, or sometimes just the string value depending on the field type config.
        # We will use the format: {'value': 'No'} which is common for Select List (single choice).
        scan_config = ScanConfiguration()
        project_dir = "."
        if scan_config.has_scan(self.scan_name):
            # get the project root dir, so the git branch can be found
            if scan_config.has_scan_property(self.scan_name, "root"):
                project_dir = scan_config.get_scan_property(self.scan_name, "root")
        git_branch = self._get_current_git_branch(project_dir)
        fix_version = scan_config.get_fix_version_for_git_branch(git_branch)
        
        fields_to_update = {
            JiraFieldId.REQUIRES_DOC_CHANGES: {'value': 'No'},
            JiraFieldId.REQUIRES_REL_NOTE: {'value': 'No'},
            # fixVersions field takes a list of dictionary objects
            JiraFieldId.FIX_VERSION: [{'name': fix_version}]
        }

        # 2. Perform the update
        try:
            issue.update(fields=fields_to_update)
            logging.info(f"Successfully updated fields for {issue_key}: {JiraFieldId.REQUIRES_DOC_CHANGES}, {JiraFieldId.REQUIRES_REL_NOTE}, and {JiraFieldId.FIX_VERSION} to '{fix_version}'.")
            return True
        
        except JIRAError as e:
            # A common JIRAError for invalid versions is 400 (Bad Request)
            if e.status_code == 400:
                logging.warning(
                    f"{issue_key} - failed to update [{FIELD_ID_FIX_VERSION}] "
                    f"with value [{fix_version}]. The value may not exist in Jira: {e.text}"
                )
                return False
            else:
                logging.error(f"Error updating fields for {issue_key}: {e.status_code} - {e.text}")
                return False
        except Exception as e:
            logging.error(f"An unexpected error occurred during field update for {issue_key}: {e}")
            return False
        pass

    def _transition_status(self, issue_key: str, new_status: str):
        logging.info(f"Attempting to apply [{new_status}] transition {issue_key}...")
        try:
            # Get all valid transitions for the issue
            transitions = self.jira.transitions(issue_key)
            
            # Find the ID for the desired transition
            transition_id = next(
                (t['id'] for t in transitions if t['name'].lower() == new_status.lower()), 
                None
            )

            if transition_id:
                # Perform the transition
                self.jira.transition_issue(issue_key, transition_id)
                logging.info(f"Successfully applied [{new_status}] to {issue_key}")
                return True
            else:
                # This happens if the target status is not a valid transition path
                logging.warning(
                    f"Could not find a valid transition path from the current status "
                    f"to apply transition [{new_status}] for {issue_key}. Skipping transition."
                )
                return False

        except JIRAError as e:
            logging.error(f"Error transitioning {issue_key}: {e.status_code} - {e.text}")
            return False


    # mark jira tickets as done
    def mark_as_done(self, ids_list: list) :
        if not self.jira:
            logging.warn("Cannot execute query. Jira connection is not active.")
            return []

        for ticket_id in ids_list:
            try:
                jira_issue = self.jira.issue(ticket_id, fields=[JiraFieldId.STATUS,JiraFieldId.SUMMARY])
                current_status = jira_issue.fields.status.name
                # Done tickets don't need to be touched
                if current_status.lower() == "done":
                    logging.info(f"ticket_id is already 'Done' - nothing to do")
                    continue
                # Backlog tickets need to go to "in progress", then "Done"
                # fields need to be updated in order to move to "In progress"
                if current_status.lower() == "backlog":
                    self._prepare_for_status_change(jira_issue) # update the relnotes/docs checkboxes
                    if (self._transition_status(ticket_id, "In Progress")):
                        self._transition_status(ticket_id, "testing not required")
                elif current_status.lower() == "in progress":
                    self._transition_status(ticket_id, "testing not required")
                else:
                    logging.warning(f"{ticket_id} has status '{current_status}'. "
                                    "Cannot/will not mark this as Done")
            except JIRAError as e:
                if e.status_code == 404:
                    # Issue not found
                    logging.warning(f"{ticket_id} does not exist or you do not have permission to view it.")
                else:
                    # Other Jira API error
                    logging.error(f"Failed to fetch or process {ticket_id}: {e.status_code} - {e.text}")
            except Exception as e:
                logging.error(f"An unexpected error occurred while processing {ticket_id}: {e}")












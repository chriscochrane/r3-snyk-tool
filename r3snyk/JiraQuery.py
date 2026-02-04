from jira import JIRA, JIRAError
from jira.resources import Issue
from .ScanConfiguration import ScanConfiguration
import logging
import subprocess
from enum import StrEnum


# Jira fields we care about
class JiraFieldId(StrEnum):
    SUMMARY = "summary"
    CREATED = "created"
    STATUS = "status"
    FIX_VERSION = "fixVersions"
    REQUIRES_REL_NOTE = "customfield_12324"
    REQUIRES_DOC_CHANGES = "customfield_12214"
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
        """
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=path,
                check=True,
                capture_output=True,
                text=True
            )

            branch_name = result.stdout.strip()
            
            if branch_name == 'HEAD':
                print(f"Warning: Repository at '{path}' is in a detached HEAD state.")
                return None
                
            return branch_name

        except subprocess.CalledProcessError as e:
            print(f"Error executing Git command in '{path}':")
            print(f"    Return Code: {e.returncode}")
            print(f"    Stderr: {e.stderr.strip()}")
            return None
        except FileNotFoundError:
            print("Error: The 'git' command was not found.")
            return None

    def _query(self) -> list:
        if not self.jira:
            logging.warning("Cannot execute query. Jira connection is not active.")
            return []

        jira_filter = None
        project_dir = "."

        if self.scan_name != None:
            scan_config = ScanConfiguration()
            if scan_config.has_scan(self.scan_name):
                if scan_config.has_scan_property(self.scan_name, "jira_filter_id"):
                    jira_filter = scan_config.get_scan_property(self.scan_name, "jira_filter_id")
                if scan_config.has_scan_property(self.scan_name, "root"):
                    project_dir = scan_config.get_scan_property(self.scan_name, "root")
            else:
                logging.error(f"Scan [{self.scan_name}] not known")

        if jira_filter == None:
            logging.warning("No filter specified and so not going to query Jira.")
            return []

        self.git_branch = self._get_current_git_branch(project_dir)
        query_text = f"filter = {jira_filter} AND {JiraFieldId.STATUS} != Done AND {JiraFieldId.STATUS} != 'Waiver Provided' AND {JiraFieldId.STATUS} != 'Descope' AND {JiraFieldId.SUMMARY} ~ '{self.git_branch}'"
        logging.info(f"Executing JQL: {query_text}")
        try:
            issues = self.jira.search_issues(query_text, maxResults=False, fields=[JiraFieldId.SUMMARY, JiraFieldId.CREATED])
            return issues
        except Exception as e:
            logging.error(f"Error executing JQL '{query_text}'. Error: {e}")
            return []

    def get_fields(self) -> list:
        if not self.jira:
            logging.warning("Cannot execute query. Jira connection is not active.")
            return []
        return self.jira.fields()

    def get_vuln_jira_ids(self) -> list[str]:
        jira_issues = self._query()
        ticket_ids = [issue.key for issue in jira_issues] 
        return ticket_ids

    def attach_jira_ids(self, vulns : set):
        jira_issues = self._query()
        jira_index = {}

        for ji in jira_issues:
            summary = ji.fields.summary
            start_pos = summary.find("CVE")
            if start_pos == -1:
                start_pos = summary.find("CWE")
            if start_pos == -1:
                continue

            cve_id = summary[start_pos:]
            jira_index[cve_id] = ji.key

        for v in vulns:
            for vuln_cve in v.cve:
                if vuln_cve in jira_index:
                    v.jira_id = jira_index[vuln_cve]
                    break

    def _prepare_for_status_change(self, issue: Issue) :
        issue_key = issue.key
        logging.info(f"Attempting to update mandatory fields for {issue_key}")
        
        scan_config = ScanConfiguration()
        project_dir = "."
        if scan_config.has_scan(self.scan_name):
            if scan_config.has_scan_property(self.scan_name, "root"):
                project_dir = scan_config.get_scan_property(self.scan_name, "root")
        
        git_branch = self._get_current_git_branch(project_dir)
        fix_version = scan_config.get_fix_version_for_git_branch(git_branch)
        
        fields_to_update = {
            JiraFieldId.REQUIRES_DOC_CHANGES: {'value': 'No'},
            JiraFieldId.REQUIRES_REL_NOTE: {'value': 'No'},
            JiraFieldId.FIX_VERSION: [{'name': fix_version}]
        }

        try:
            issue.update(fields=fields_to_update)
            logging.info(f"Successfully updated fields for {issue_key}.")
            return True
        except JIRAError as e:
            logging.error(f"Error updating fields for {issue_key}: {e.status_code} - {e.text}")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred during field update for {issue_key}: {e}")
            return False

    def _transition_status(self, issue_key: str, new_status: str) -> bool:
        logging.info(f"Attempting to apply [{new_status}] transition {issue_key}...")
        try:
            transitions = self.jira.transitions(issue_key)
            transition_id = next(
                (t['id'] for t in transitions if t['name'].lower() == new_status.lower()), 
                None
            )

            if transition_id:
                self.jira.transition_issue(issue_key, transition_id)
                logging.info(f"Successfully applied [{new_status}] to {issue_key}")
                return True
            else:
                logging.warning(f"Could not find valid transition path to [{new_status}] for {issue_key}.")
                return False
        except JIRAError as e:
            logging.error(f"Error transitioning {issue_key}: {e.status_code} - {e.text}")
            return False

    def mark_as_done(self, ids_list: list, comment: str = None):
        """
        Marks Jira tickets as done and optionally adds a comment if the status changes.
        """
        if not self.jira:
            logging.warning("Cannot execute query. Jira connection is not active.")
            return

        for ticket_id in ids_list:
            try:
                jira_issue = self.jira.issue(ticket_id, fields=[JiraFieldId.STATUS, JiraFieldId.SUMMARY])
                current_status = jira_issue.fields.status.name
                
                if current_status.lower() == "done":
                    logging.info(f"{ticket_id} is already 'Done' - nothing to do")
                    continue

                transitioned = False

                if current_status.lower() == "backlog" or current_status.lower() == "to do" :
                    # Update fields and attempt multi-step transition
                    if self._prepare_for_status_change(jira_issue):
                        if self._transition_status(ticket_id, "In Progress"):
                            if self._transition_status(ticket_id, "testing not required"):
                                transitioned = True
                
                elif current_status.lower() == "in progress":
                    if self._transition_status(ticket_id, "testing not required"):
                        transitioned = True
                
                else:
                    logging.warning(f"{ticket_id} has status '{current_status}'. Cannot mark as Done")

                # If the ticket state was changed successfully, add the comment if provided
                if transitioned and comment:
                    try:
                        self.jira.add_comment(ticket_id, comment)
                        logging.info(f"Successfully added comment to {ticket_id}")
                    except Exception as e:
                        logging.warning(f"Status for {ticket_id} was updated, but the comment could not be applied. Error: {e}")

            except JIRAError as e:
                if e.status_code == 404:
                    logging.warning(f"{ticket_id} does not exist or permissions are missing.")
                else:
                    logging.error(f"Failed to process {ticket_id}: {e.status_code} - {e.text}")
            except Exception as e:
                logging.error(f"An unexpected error occurred while processing {ticket_id}: {e}")
from jira import JIRA
import logging


class JiraQuery:
    """
    A class to manage the connection and execution of JQL queries 
    against a Jira instance.
    """
    def __init__(self, server: str, email: str, api_token: str):
        self.server = server
        self.email = email
        self.api_token = api_token
        self.jira = None
        
        try:
            # Establish the connection using basic authentication (email + API token)
            logging.info(f"Connecting to Jira at [{self.server}]")
            self.jira = JIRA(server=self.server, basic_auth=(self.email, self.api_token))
        except Exception as e:
            logging.error(f"Failed to connect to Jira at {self.server}. Error: {e}")
            # Ensure jira is None if connection fails
            self.jira = None

    def query(self, jql_query: str) -> list[str]:
        if not self.jira:
            logging.warn("Cannot execute query. Jira connection is not active.")
            return []
        
        # comment-in when you want to find out more fields to query
        # fields_list = self.jira.fields()
        # print("Available Jira Fields:")
        # for field in fields_list:
        #     # Print the technical ID (key) and the human-readable name
        #     logging.info(f"ID: {field['id']} \t Name: {field['name']}")


        logging.info(f"Executing JQL: {jql_query}")

        try:
            # Execute the search. maxResults=False fetches all results.
            issues = self.jira.search_issues(jql_query, maxResults=False, fields=["summary", "created"])
            # Extract just the ticket keys
            ticket_ids = [issue.key for issue in issues]            
            return ticket_ids

        except Exception as e:
            logging.error(f"Error executing JQL '{jql_query}'. Error: {e}")
            return []


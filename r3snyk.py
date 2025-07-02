#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
import logging
import secrets
import string
from datetime import datetime

from enum import StrEnum
from Waivers import Waivers
from Snyk import Snyk
from Vulnerability import Vulnerability
from ScanReport import ScanReport


# the supported commands
class Command(StrEnum):
    COUNT = "count",
    LIST = "list",
    REMOVE = "rm",
    REDUNDANT = "red",
    REMOVE_REDUNDANT = "rmred",
    SUMMARISE = "sum",
    TEST = "test",
    REPORT = "rep"
    
def _configure_logging(args :argparse.Namespace):
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    else:
        null_handler = logging.NullHandler()
        logging.getLogger().addHandler(null_handler)
        logging.getLogger().setLevel(logging.NOTSET)

def generate_unique_random_string(length: int = 24) -> str:
    """
    Generates a random and cryptographically secure unique string of a specified length.

    The string is composed of uppercase letters, lowercase letters, digits,
    and a selection of common punctuation characters.

    Args:
        length (int): The desired length of the string. Defaults to 24.

    Returns:
        str: A random, unique, and cryptographically secure string.
    """
    if not isinstance(length, int) or length <= 0:
        raise ValueError("Length must be a positive integer.")

    # Define the pool of characters to choose from
    # This includes uppercase letters, lowercase letters, digits, and some common punctuation
    characters = string.ascii_letters + string.digits

    # Generate the string by repeatedly choosing a random character from the pool
    # secrets.choice is used for cryptographic strength
    random_string = ''.join(secrets.choice(characters) for _ in range(length))

    return random_string
    
def countWaivers(args : argparse.Namespace):
    waiver_manager = Waivers(filename=args.waivers)
    print(waiver_manager.size())

def listWaivers(args : argparse.Namespace):
    waiver_manager = Waivers(filename=args.waivers)
    print("{")
    print('\n'.join(waiver_manager.list_ids()))
    print("}")

def listRedundantWaivers(args : argparse.Namespace):
    waiver_manager = Waivers(filename=args.waivers)
    snyk_manager = Snyk(project_dir=args.project)
    redundant = _getRedundantIDs(waiver_manager,snyk_manager)
    print("{")
    print('\n'.join(redundant))
    print("}")


def removeWaivers(args : argparse.Namespace):
    waiver_manager = Waivers(filename=args.waivers)
    waiver_manager.remove(args.ids.split(","))
    waiver_manager.write_waivers(args.waivers)


def removeRedundantWaivers(args : argparse.Namespace):
    waiver_manager = Waivers(filename=args.waivers)
    snyk_manager = Snyk(project_dir=args.project)
    redundant = _getRedundantIDs(waiver_manager,snyk_manager)
    waiver_manager.remove(redundant)
    waiver_manager.write_waivers(args.waivers)


def summariseProject(args : argparse.Namespace):    
    # the 'include' arg is a delimited list of projects to be specifically included in the summary
    projects_list = None
    if args.include != "":
        projects_list = set(args.include.split(","))

    snyk_manager = Snyk(project_dir=args.project,user_projects=projects_list,scan_type=args.type,scan_name=args.name)

    # get the open and waivered vulns
    openVulns = snyk_manager.get_open_vulnerabilities(match_path=args.match)
    waiveredVulns = snyk_manager.get_waivered_vulnerabilities()
    allVulns = openVulns.union(waiveredVulns)

    # split the vulns into critical,high,medium,low
    (allCrit,allHigh,allMed,allLow) = _categoriseVulnerabilities(allVulns)
    (openCrit,openHigh,openMed,openLow) = _categoriseVulnerabilities(openVulns)
    (waiveredCrit,waiveredHigh,waiveredMed,waiveredLow) = _categoriseVulnerabilities(waiveredVulns)

    # output the counts as delimited data
    # TBD make it look nicer/human-readable?
    print(f"All,{len(allCrit)},{len(allHigh)},{len(allMed)},{len(allLow)}")
    print(f"Waiv,{len(waiveredCrit)},{len(waiveredHigh)},{len(waiveredMed)},{len(waiveredLow)}")
    print(f"Open,{len(openCrit)},{len(openHigh)},{len(openMed)},{len(openLow)}")


def testProject(args : argparse.Namespace):

    # the 'include' arg is a delimited list of projects to be specifically included in the summary
    projects_list = None
    if args.include:
        projects_list = set(args.include.split(","))

    snyk_manager = Snyk(project_dir=args.project,user_projects=projects_list,scan_type=args.type,scan_name=args.name)
    
    # get the open and waivered vulns
    openVulns = snyk_manager.get_open_vulnerabilities(match_path=args.match)
    waiveredVulns = snyk_manager.get_waivered_vulnerabilities()

    print("{")
    print(f" \"id\": \"{generate_unique_random_string()}\",")
    print(f" \"timestamp\": \"{datetime.now().astimezone().strftime('%Y%m%d-%H:%M:%S.%f')[:-3]}{datetime.now().astimezone().strftime('%z')}\",")
    print("  \"num\":", len(openVulns) + len(waiveredVulns), ",", sep='')
    print("  \"open\": {")
    print("    \"num\": ", len(openVulns), ",", sep='')
    print("    \"vulnerabilities\": [")
    last = len(openVulns) - 1
    for i, v in enumerate(openVulns):
        print("      {")
        print(f"        \"id\": \"{generate_unique_random_string()}\",")
        print(f"        \"snyk\": \"{v.id}\",")
        print(f"        \"title\": \"{v.title}\",")
        print(f"        \"severity\": \"{v.severity}\",")
        print(f"        \"score\": \"{v.score}\",")
        print(f"        \"name\": \"{v.name}\",")
        print(f"        \"url\": \"https://security.snyk.io/vuln/{v.id}\",")
        # fixed-in is a list
        print(f"        \"fixed\": [")
        last_fix = len(v.fixed) - 1
        for a, fx in enumerate(v.fixed):
            if a == last_fix:
                print(f"          \"{fx}\"")
            else:
                print(f"          \"{fx}\",")
        print("        ],")
        # cwe is actually a list
        print(f"        \"cwe\": [")
        last_cwe = len(v.cwe) - 1
        for k, cwe in enumerate(v.cwe):
            if k == last_cwe:
                print(f"          \"{cwe}\"")
            else:
                print(f"          \"{cwe}\",")
        print("        ],")
        # cwe is actually a list as well
        print(f"        \"cve\": [")
        last_cve = len(v.cve) - 1
        for m, cve in enumerate(v.cve):
            if m == last_cve:
                print(f"          \"{cve}\"")
            else:
                print(f"          \"{cve}\",")
        print("        ],")
        # paths is a list of lists (paths, and path-elements)
        print(f"        \"paths\": [")
        last_path = len(v.paths) - 1
        for j, path in enumerate(v.paths):
            path_to_print = " > ".join(path)
            if j == last_path:
                print(f"          \"{path_to_print}\"")
            else:
                print(f"          \"{path_to_print}\",")
        print("        ]")  # last vuln element so no trailing comma here
        
        if i == last:
            print("      }")
        else:
            print("      },")
        
    print("    ]")  
    print("  },")
    print("  \"waivered\": {")
    print("    \"num\": ", len(waiveredVulns), ",", sep='')
    print("    \"vulnerabilities\": [")
    last = len(waiveredVulns) - 1
    for i, v in enumerate(waiveredVulns):
        print("      {")
        print(f"        \"id\": \"{generate_unique_random_string()}\",")
        print(f"        \"snyk\": \"{v.id}\",")
        print(f"        \"title\": \"{v.title}\",")
        print(f"        \"severity\": \"{v.severity}\"")
        # don't bother with paths here
        if i == last:
            print("      }")
        else:
            print("      },")
        
    print("    ]")  
    print("  }")
    print("}")


def processReport(args : argparse.Namespace):
    if args.report is None:
        raise Error("Report file not specified")
    
    # open and parse the report file
    scan_report = ScanReport(args.report)

    # set the match criteria
    scan_report.set_criteria(args.match)

    # get the matching vulns
    matches = scan_report.get_matches()

    # print the info
    last_vuln = len(matches) - 1

    print("{")
    print(f"  \"num\": \"{len(matches)}\",")
    print("  \"matches\": [")

    for index, (id, vuln) in enumerate(matches.items()):
        print("    {")
        # TBD - let the user dictate the output fields
        print(f"      \"id\": \"{id}\",")
        print(f"      \"snyk\": \"{vuln.id}\",")
        print(f"      \"cve\": \"{vuln.cve}\"")

        if index == last_vuln:
            print("    }")
        else:
            print("    },")

    print("  ]")
    print("}")
        







def _getRedundantIDs(waiver_manager: Waivers,snyk_manager: Snyk) -> list:
    # IDs in the waivers file
    waivers = waiver_manager.list_ids()
    # IDs snyk tells us have been waivered
    def extractID(vuln : Vulnerability):
        return vuln.id
    waivered = list(map(extractID, snyk_manager.get_waivered_vulnerabilities()))
    # redundant IDs are those that are in the waivers file, but not waivered in the snyk report
    return list(set(waivers) - set(waivered))


# given a list of vulns, split them into Critical, High, Medium, Low
# returns a tuple of the IDs in each severity (Cr,Hi,Me,Lo)
def _categoriseVulnerabilities(vulns : set):
    critical = set()
    high = set()
    medium = set()
    low = set()

    for v in vulns:
        if v.severity == "critical":
            critical.add(v.id)
        elif v.severity == "high":
            high.add(v.id)
        elif v.severity == "medium":
            medium.add(v.id)
        elif v.severity == "low":
            low.add(v.id)
        else:
            print(f"Found vulnerability [{v.id}] with an unrecognised severity of [{v.severity}] - can't categorise it")
    
    return (critical,high,medium,low)


def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description='Snyk Waiver Management Tool')
    
    # Subcommands first
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    #
    # Count waivers subcommand with optional arguments
    #
    count_parser = subparsers.add_parser(Command.COUNT, help='Count number of waivers')
    count_parser.add_argument('-w', '--waivers', 
                               default='.snyk', 
                               help='Path to waivers file (default: .snyk)')
    count_parser.add_argument('-v', '--verbose', 
                                action='store_true', 
                                help='Output informational messages during processing.')

    #
    # List waivers subcommand with optional arguments
    #
    list_parser = subparsers.add_parser(Command.LIST, help='List waiver identifiers')
    list_parser.add_argument('-w', '--waivers', 
                              default='.snyk', 
                              help='Path to waivers file (default: .snyk)')
    list_parser.add_argument('-v', '--verbose', 
                                action='store_true', 
                                help='Output informational messages during processing.')
    
    #
    # List-redundant subcommand with optional arguments
    #
    redundant_parser = subparsers.add_parser(Command.REDUNDANT, help='List redundant waivers')
    redundant_parser.add_argument('-p', '--project', 
                                    default=os.getcwd(), 
                                    help='Project root directory (default: current directory)')
    redundant_parser.add_argument('-w', '--waivers', 
                                    default='.snyk', 
                                    help='Path to waivers file (default: .snyk)')
    redundant_parser.add_argument('-v', '--verbose', 
                                action='store_true', 
                                help='Output informational messages during processing.')


    #
    # Remove subcommand with optional arguments
    #
    remove_parser = subparsers.add_parser(Command.REMOVE, help='Remove waivers')
    remove_parser.add_argument('-i', '--ids', 
                                required=True,
                                help='Comma-delimited list of Snyk IDs to be removed.')
    remove_parser.add_argument('-w', '--waivers', 
                                default='.snyk', 
                                help='Path to waivers file (default: .snyk)')
    remove_parser.add_argument('-v', '--verbose', 
                                action='store_true', 
                                help='Output informational messages during processing.')

    #
    # Remove-redundant subcommand with optional arguments
    #
    remove_redundant_parser = subparsers.add_parser(Command.REMOVE_REDUNDANT, help='Remove redundant waivers')
    remove_redundant_parser.add_argument('-p', '--project', 
                                    default=os.getcwd(), 
                                    help='Project root directory (default: current directory)')
    remove_redundant_parser.add_argument('-w', '--waivers', 
                                default='.snyk', 
                                help='Path to waivers file (default: .snyk)')
    remove_redundant_parser.add_argument('-v', '--verbose', 
                                action='store_true', 
                                help='Output informational messages during processing.')

    #
    # Test subcommand with optional arguments
    #
    #   args
    #   -p = project dir
    #
    test_parser = subparsers.add_parser(Command.TEST, help='Test a project and list the open vulnerability IDs')
    test_parser.add_argument('-p', '--project', 
                                default=None, 
                                help='Project root directory (default: current directory)')
    test_parser.add_argument('-w', '--waivers', 
                                default=None, 
                                help='Path to waivers file (default: .snyk)')
    test_parser.add_argument('-i', '--include', 
                                default=None, 
                                help='Project names to be included in the test report')
    test_parser.add_argument('-t', '--type', 
                                default=None, 
                                help='The type of project being scanned (dev or relpack)')
    test_parser.add_argument('-n', '--name', 
                                default=None, 
                                help='The scan name to use for executing the snyk test.')
    test_parser.add_argument('-v', '--verbose', 
                                action='store_true', 
                                help='Output informational messages during processing.')
    test_parser.add_argument('-m', '--match', 
                                default=None, 
                                help='Vulnerability paths to include vulnerabilities for.')

    #
    # Summary subcommand with optional arguments
    # Runs a snyk test on a project and gives a more comprehensive summary:
    #                                   Overall    
    #   Total number of issues found    C   H   M   L 
    #   Number of issues waivered       C   H   M   L 
    #   Number of issues remaining      C   H   M   L 
    #
    #   args
    #   -p = project dir
    #
    run_parser = subparsers.add_parser(Command.SUMMARISE, help='Summarise the vulnerabilities affecting a project')
    run_parser.add_argument('-p', '--project', 
                                default=None, 
                                help='Project root directory (default: current directory)')
    run_parser.add_argument('-w', '--waivers', 
                                default='.snyk', 
                                help='Path to waivers file (default: .snyk)')
    run_parser.add_argument('-i', '--include', 
                                    default="", 
                                    help='Project names to be included in the summary')
    run_parser.add_argument('-t', '--type', 
                                default="", 
                                help='The type of project being scanned (dev or relpack)')
    run_parser.add_argument('-n', '--name', 
                                default=None, 
                                help='The scan name to use for executing the snyk test.')
    run_parser.add_argument('-v', '--verbose', 
                                action='store_true', 
                                help='Output informational messages during processing.')
    run_parser.add_argument('-m', '--match', 
                                default=None, 
                                help='Vulnerability paths to include vulnerabilities for.')

    # report processing
    rep_parser = subparsers.add_parser(Command.REPORT, help='Filter/process a vulnerability report')
    rep_parser.add_argument('-v', '--verbose', 
                                action='store_true', 
                                help='Output informational messages during processing.')
    rep_parser.add_argument('-r', '--report', 
                                default=None, 
                                help='Path to report file')
    rep_parser.add_argument('-m', '--match', 
                                default=None, 
                                help='Criteria to match')



    # Parse arguments
    args = parser.parse_args()

    _configure_logging(args)
    
    # Execute command
    if args.command == Command.COUNT:
        countWaivers(args)

    elif args.command == Command.LIST:
        listWaivers(args)

    elif args.command == Command.REDUNDANT:
        listRedundantWaivers(args)

    elif args.command == Command.REMOVE:
        removeWaivers(args)

    elif args.command == Command.REMOVE_REDUNDANT:
        removeRedundantWaivers(args)

    elif args.command == Command.SUMMARISE:
        summariseProject(args)

    elif args.command == Command.TEST:
        testProject(args)

    elif args.command == Command.REPORT:
        processReport(args)

if __name__ == '__main__':
    main()
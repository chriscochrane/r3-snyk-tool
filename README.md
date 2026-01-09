# r3-snyk-tool
This is a helper tool written in Python, that was developed to help manage vulnerbilities in R3 projects, which use Snyk for vulnerability scanning. It initially started as a waiver-management tool, but later expanded to include general Snyk-scanning helper utilities.

The [first part](#how-to-use-r3-snyk-tool) of this document describes how to use the tool.

The [second part](#under-the-bonnet) provides some information about the source code, project structure, and so forth.

# How to use r3-snyk-tool

## Environment
The application was developed using Python 3.
The following Python packages need to be available in the environment where the application is running.
jira
json

The following environment variables need to be set where the application is running.
|env var|description|notes|
|----|----|----|
|JIRA_SERVER|The server address for Jira i.e. https://r3-cev.atlassian.net/|Only needed for Jira-related features|
|JIRA_USER|Jira username, typically your email address.|Only needed for Jira-related features|
|JIRA_API_TOKEN|Jira API token. You can create this in Jira yourself.|Only needed for Jira-related features|

## Installation
From the root directory of this project, run:

`pip install .`

This installs the r3snyk application as Python application `sk` (saves typing)

To uninstall:

`pip uninstall r3snyk`

## Running the tool
It can be run from the command-line thus:

`python r3snyk.py <command> <arguments...>`

## Commands

|command|description|
|----|----|
|`count`|Count the number of waivers in the waivers file|
|`jlist`|List the Jira tickets that are currently open for the project|
|`list`|List the IDs in the waivers file|
|`red`|List the IDs of waivers that are redundant|
|`rm`|Remove waivers from the waivers file|
|`rmred`|Find redundant waivers and remove them from the waivers file|
|`sum`|Perform a Snyk scan and summarise the total vulnerabilitie found.|
|`test`|Perform a Snyk scan and output a JSON report|

### Command arguments
Many commands share the same arguments - each command sub-section indicates which arguments are applicable.
To save repeated definitions, the arguments are described here.

|argument|description|
|----|----|
|--ids,-i|Comma-separated list of Snyk vulnerability IDs to be processed by the command.|
|--include,-i|Delimited list of sub-projects to processed by the command.|
|--match,-m|Vulnerability paths to include vulnerabilities for.|
|--name,-n|The name of a preset set of arguments - see [Scan Configurations](#scan-configurations)|
|--project,-p|The root directory of the project to be scanned. Defaults to the current working directory.|
|--type,-t|The type of project being scanned - either 'dev' or 'relpack'|
|--verbose,-v|Enable informational logging to stdout.|
|--waivers,-w|The path and filename of the waivers file to be used.|


### count
Count the number of waivers in the waivers file.

### jlist
List the Jira tickets that are currently open for the project.

### jmad
Given a list of Jira tickets, mark them all as "Done".

### list
List the Snyk IDs of the waivered vulnerabilities found in the waivers file.

### red
List the Snyk IDs of the waivered vulnerabilities that are redundant. That is, the waivered vulnerabilities that, if removed from the waivers file, would not alter the result of a security scan.

### rm
Remove the supplied list of Snyk IDs from the waivers file. The waivrers file is updated in-place.

### rmred
A combination of `rm` nd `red` commands - identify the redundant waivers and remove them from the waivers file. The waivrers file is updated in-place.

### sum
Perform a Snyk scan on the project and output a summary of the critical, high, medium, and low-severity vulnerabilities that were found. An example of the output from this command is:

`All,9,100,85,17 (211)`

`Waiv,3,21,31,12 (67)`

`Open,6,79,54,5 (144)`

The `All` line indicates how many critical, high, medium, and low severity issues were found in total.
The `Waiv` line indicates how many critical, high, medium, and low severity issues were waivered.
The `Open` line indicates how many critical, high, medium, and low severity issues remain open, and need to be addressed (either by updating the project, or adding more waivers).

### test
Perform a Snyk test on the project/sub-projects and generate a report describing the vulnerabilities found. By default a JSON report is generated, but the `--csv` option forces a CSV report to be generated instead.


## Scan Configurations
Scan configurations are preset collections of options for running the the tool with. It was introduced at a point in the application's development where it seemed like the number of command line arguments would explode, and remembering them (and typing them in) would become boring.

Scan configurations are stored in a configuraion file that the user sets up. The location of the file must be specified in the environment variable `SNYK_R3_SCAN_CONFIG`. An example configuration file can be found in the examples directory of this repository.

The scan configuration is a JSON-formatted file consisting of the following top-level sections:
* `configuration` - a set of general configuration options for the application
* `scans` - a list of named scan configurations that can be used for running Snyk scans.

### configuration
Configuration options for the application:

|Option|Description|
|------|------|
|dump_snyk|true/false, indicating whether the capture of the original Snyk report is activated.|
|fix_version_mapping|A mapping of git branch name to the Fix Version found on Jira tickets.|

#### `dump_snyk`
When the Snyk tool is run with the `sum` or `test` commands, it executes the Snyk CLI application to run the actual scan. The Snyk CLI produces a detailed JSON report that is interpreted by the R3 tool, and the relevant information is extracted. The report by the R3 tool is essentially a simplified version of the original report produced by the Snyk CLI.
With `dump_snyk` enabled, the original Snyk report is captured in `~/.r3cache/snyk`. This can be useful when developing new features in the R3 tool, or just to verify the R3 report is correct (if there is any doubt). The original report is captured into a compressed ZIP file whose name is the timestamp of the report, as indicated by the `timestamp` attribute at the top of the report.

#### `fix_version_mapping`
This setting is used by the Jira-related commands `jmad` to map a Git branch to the text that needs to be set in the "Fix Versions" field in a Jira ticket. 

### scans
A collection of named scans. Each scan can contain the following sub-elements:
|Element|Description|
|-----|-----|
|description|A brief description of the scan|
|root|The root directory of the project to be scanned.|
|waivers|The full path and filename of the waivers file to be used.|
|type|The type of scsn to run: 'dev' for a development project such as Corda; 'relpack' for a release pack.|
|buildfile|The name used for the build configuration files in the main project and sub-projects. By default this is 'build.gradle'.|
|sub-projects|A list of sub-projects to be included in the scan.|
|project-mapping|A mapping of sub-project names to sub-project directories.|


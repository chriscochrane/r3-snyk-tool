# r3-snyk-tool
This is a helper tool written in Python, that was developed to help manage vulnerbilities in R3 projects, which use Snyk for vulnerability scanning. It initially started as a waiver-management tool, but later expanded to include general Snyk-scanning helpers.

The [first part](#how-to-use-r3-snyk-tool) of this document describes how to use the tool.

The [second part](#under-the-bonnet) provides some information about the source code, project structure, and so forth.

# How to use r3-snyk-tool

## Running the tool
It can be run from the command-line thus:

`python r3snyk.py <command> <arguments...>`

## Commands

|command|description|
|----|----|
|`count`|Count the number of waivers in the waivers file|
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

`All,9,100,85,17`

`Waiv,3,21,31,12`

`Open,6,79,54,5`

The `All` line indicates how many critical, high, medium, and low severity issues were found in total.
The `Waiv` line indicates how many critical, high, medium, and low severity issues were waivered.
The `Open` line indicates how many critical, high, medium, and low severity issues remain open, and need to be addressed (either by updating the project, or adding more waivers).

### test
TBD


## Scan Configurations
TBD


# Under the bonnet
TBD

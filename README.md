# r3-snyk-tool
This is a helper tool written in Python, that was developed to help manage vulnerbilities in R3 projects, which use Snyk for vulnerability scanning. It initially started as a waiver-management tool, but later expanded to include general Snyk-scanning helpers.

The [first part](#how-to-use-r3-snyk-tool) of this document describes how to use the tool.

The [second part](#under-the-bonnet) provides some information about the source code, project structure, and so forth.

# How to use r3-snyk-tool

## Running the tool
It can be run from the command-line thus:

`python r3snyk.py <command> <arguments...>`

## Commands

|command|blah|
|----|----|
|`count`|Count the number of waivers in the waivers file|
|`list`|List the IDs in the waivers file|
|`red`|List the IDs of waivers that are redundant|
|`rm`|Remove waivers from the waivers file|
|`rmred`|Find redundant waivers and remove them from the waivers file|
|`sum`|Perform a Snyk scan and summarise the total vulnerabilitie found.|
|`test`|Perform a Snyk scan and output a JSON report|

### count
TBD

### list
TBD

### red
TBD

### rm
TBD

### rmred
TBD

### sum
TBD

### test
TBD


## Scan Configurations
TBD


# Under the bonnet
TBD

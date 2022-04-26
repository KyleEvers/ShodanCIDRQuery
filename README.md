# ShodanCIDRQuery :satellite: #

NOTE: This script assumes you have an Shodan enterprise license and api key :money_with_wings:

Query Shodan for a given CIDR range(s) saving the raw output or explicitly get Open Ports, Hostnames, and CVEs/Vulns

## Getting Started ##

`ShodanCIDRQuery` requires **3.7+**. Python 2 is not supported.

To run the tool locally from the repository, first
install the requirements:
```bash
pip install -r requirements.txt
```

### Usage and examples ###

```bash
python ShodanCIDRQuery.py --cidr 127.0.0.1/32 -a api.txt
python ShodanCIDRQuery.py --cidr 127.0.0.1/30 -a api.txt -o localhost
python ShodanCIDRQuery.py --cidr 127.0.0.1/29 --api api.txt -o localhost -f csv --log-level info
python ShodanCIDRQuery.py --cidr 127.0.0.1/28 --api api.txt --output localhost -f json --log-level info critical


python ShodanCIDRQuery.py -s cidrs.txt -a api.txt --log-level critical
python ShodanCIDRQuery.py --scope cidrs.txt -a api.txt -o sample_output -f csv --log-level info
python ShodanCIDRQuery.py -s cidrs.txt -a api.txt -o sample_output -f json --log-level critical
```

#### Options ####

```bash
  -h --help                                 show this help message and exit
  -s SCOPE_FILE --scope=SCOPE_FILE          File containing CIDR ranges
  -a API_FILE --api=API_FILE                File containing Shodan API Key
  -o OUTPUT --output=OUTPUT                 Output file prefix
  -f OUTPUT_FILE_TYPE                       File type for output. Valid output values "csv" and "json".
  --cidr CIDR_RANGE                          Single CIDR range you would like to query ie 127.0.0.0/28
  --log-level=LEVEL                         If specified, then the log level will be set to
                                            the specified value.  Valid values are "debug", "info",
                                            "warning", "error", and "critical". [default: error]
```

## Public domain ##

This project is in the worldwide [public domain](LICENSE.md).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.

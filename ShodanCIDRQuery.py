
#!/usr/bin/env python3
"""
Query Shodan for a given CIDR range(s) saving the raw output or explicitly get Open Ports, Hostnames, and CVEs/Vulns

EXIT STATUS
    This utility exits with one of the following values:
    0   Recon completed successfully.
    >0  An error occurred.

Usage:
  ShodanCIDRQuery (-s SCOPE_FILE | --scope SCOPE_FILE)(-a API_FILE | --api API_FILE) [-o OUTPUT | --output OUTPUT][--log-level=LEVEL][-f OUTPUT_FILE_TYPE]
  ShodanCIDRQuery (--cidr CIDR_RANGE)(-a API_FILE | --api API_FILE) [-o OUTPUT | --output OUTPUT][--log-level=LEVEL][-f OUTPUT_FILE_TYPE]
  ShodanCIDRQuery (-h | --help)

Options:
  -h --help                                 show this help message and exit
  -s SCOPE_FILE --scope=SCOPE_FILE          File containing CIDR ranges
  -a API_FILE --api=API_FILE                File containing Shodan API Key
  -o OUTPUT --output=OUTPUT                 Output file prefix
  -f OUTPUT_FILE_TYPE                       File type for output. Valid output values "csv" and "json".
  --cidr CIDR_RANGE                         Single CIDR range you would like to query ie 127.0.0.0/28
  --log-level=LEVEL                         If specified, then the log level will be set to
                                            the specified value.  Valid values are "debug", "info",
                                            "warning", "error", and "critical". [default: error]
"""

# Standard Python Libraries
from datetime import datetime
import ipaddress
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Set

# Third-Party Libraries
from docopt import docopt
from schema import And, Or, Schema, SchemaError, Use
import shodan
from tqdm import tqdm

PORTS_HEADING: str = "IP,Port"
HOSTNAME_HEADING: str = "IP,Hostname"
VULNS_HEADING: str = "IP,CVE"
CSV_OUTPUTS: Dict = {
    'ports': PORTS_HEADING,
    'hostnames': HOSTNAME_HEADING,
    'vulns': VULNS_HEADING}


# Read in Shodan API
def read_api(api_file: str) -> shodan.client.Shodan:
    f = open(api_file, "r")
    apikey = (f.read())
    f.close()
    return shodan.Shodan(str(apikey.strip()))


# Writes line of results to CSV
def write_results(ip: str, results: str, out_file: str) -> None:
    with open(out_file, "a") as file:
        # value can be port, hostname, or cve
        for value in results:
            file.write("%s,%s\n" % (ip, value))


# Creates the placeholder CSV files that will be appended to
def create_csvs(output_file: str, timestamp: str) -> None:
    output_filenames = {}
    for out in CSV_OUTPUTS:
        filename = '%s_shodan_%s_%s.csv' % (output_file, out, timestamp)
        output_filenames[out] = filename
        with open(filename, 'w') as f:
            f.write(CSV_OUTPUTS[out] + '\n')
    return output_filenames


# Expands provided CIDR range(s) to list of IP addresses
def expand_cidr(ip_list: List[str]) -> Set:
    ip_array = set()
    for ip in ip_list:
        try:
            for host in ipaddress.ip_network(ip.strip(), False):
                ip_array.add(host.compressed)
        except ValueError as e:
            logging.error("%s" % (e))

    return ip_array


# Write results to JSON
def write_output_to_json(results: List[Dict], output: str) -> None:
    with open(f"{output}.json", "w") as f:
        json.dump(results, f, indent=4, sort_keys=True)


def main() -> None:
    arguments: Dict[str, str] = docopt(__doc__)
    print(arguments)
    # Validate and convert arguments as needed
    schema: Schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning",
                                "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            "-f": Or(None,
                     And(
                         str,
                         Use(str.lower),
                         lambda n: n in ("csv", "json"),
                         error="Possible values for output file type are csv and json",
                     )
                     ),
            "--scope": Or(None,
                          And(
                              str,
                              lambda file: os.path.isfile(file),
                              error="Input file doesn't exist!",
                          )
                          ),
            "--api": And(
                str,
                lambda file: os.path.isfile(file),
                error="API file doesn't exist!",
            ),
            "--cidr": Or(None,
                         And(
                             str,
                             lambda cidr: ipaddress.ip_network(cidr),
                             error="Invalid CIDR provided"
                         )
                         ),
            "--output": Or(None, str),
            str: object,  # Don't care about other keys, if any
        }
    )

    try:
        validated_args: Dict[str, Any] = schema.validate(arguments)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        sys.exit(1)

    # Assign validated arguments to variables
    api_file: str = validated_args["--api"]
    output_file: str = validated_args["--output"]
    output_file_type: str = validated_args["-f"]
    input_file: str = validated_args["--scope"]
    log_level: str = validated_args["--log-level"]
    single_cidr: str = validated_args["--cidr"]

    # Set up logging
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s",
        level=log_level.upper())

    api = read_api(api_file)

    if input_file:
        with open(input_file, 'r') as f:
            cidr_list = f.readlines()
    elif single_cidr:
        cidr_list = [single_cidr]

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    ip_array = expand_cidr(cidr_list)

    if output_file_type == "csv":
        csv_filenames = create_csvs(output_file, timestamp)

    print(f"Requesting info on {len(ip_array)} IPs...")
    results = []
    for ip in tqdm(ip_array):
        try:
            # Query Shodan with minify result
            response = api.host(ip, minify=True)
            try:
                if output_file_type == "csv":
                    for out in CSV_OUTPUTS:
                        write_results(ip, response[out], csv_filenames[out])
                else:
                    results.append(response)
            except KeyError as e:
                logging.error('[-] No %s entry in response' % e)
            # Shodan has query limit of one request per sec
            time.sleep(1)
        except shodan.exception.APIError as e:
            logging.error("[-] shodan.exception.APIError (%s): %s" % (ip, e))
            # Shodan has query limit of one request per sec
            time.sleep(1)

    if not output_file_type:
        print(results)
    elif output_file_type == "json":
        write_output_to_json(results, output_file)


if __name__ == "__main__":
    main()

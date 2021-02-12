# this file reads large zone fields and extract its set of NS records

import argparse
import logging
import re


def get_ns_set(zonefile=None, extension=None):
    nsset = set()
    if extension[-1] != ".":
        extension = extension + "."
    if extension[0] != ".":
        extension = "." + extension

    with open(zonefile) as f:
        for line in f.readlines():
            sp = re.split('[\s]+', line.lower())
            ns_entry = ''

            if len(sp) > 3:
                if sp[2] == 'ns' or sp[3] == 'ns':
                    ns_entry = sp[-2].rstrip()

                if ns_entry != '':
                    ns_entry = ns_entry.lower()

                    if ns_entry[-1] != ".":
                        ns_entry = ns_entry + extension
                    nsset.add(ns_entry)
    return nsset


def zone_parser(zonefile=None, zonename=None, output_file=None):
    nsset = get_ns_set(zonefile=zonefile, extension=zonename)
    with open(output_file, 'w') as aus:
        for k in nsset:
            aus.write(f"{k}\n")


if __name__ == '__main__':
    # Setup logging if called from command line
    logging.basicConfig(filename='zone-parser.log',
                        level=logging.INFO, format="%(asctime)s zone_parser: %(levelname)s %(message)s")
    # Read the command line arguments
    argparser = argparse.ArgumentParser(description="Extract all NS records from a zone file")
    argparser.add_argument('zonefile', type=str, help="File with the list of nameservers")
    argparser.add_argument('zonename', type=str, help="The name of the zone to parse")
    argparser.add_argument('output', type=str, help="File to save the output")
    args = argparser.parse_args()

    zone_parser(zonefile=args.zonefile, zonename=args.zonename, output_file=args.output)

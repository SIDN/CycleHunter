# this file reads large zone fields and extract its set of NS records
import argparse
import logging
import sys
import re


def parseNS(s, extension=None):
    ns_entry = '0'
    if s[0] != ";":
        sp = re.split('[\s]+', s.lower())
        foundNS = False
        for item in sp:
            if item == 'ns' and foundNS is False and 'rrsig' not in s.lower() and 'nsec' not in s.lower():
                ns_entry = sp[-1].rstrip()
                if len(ns_entry) == 0:
                    # test if the one before the last has NS
                    tempNS = sp[-2].strip()
                    if "." in tempNS:
                        ns_entry = tempNS
                if ns_entry[-1] != ".":
                    ns_entry = ns_entry + extension
                    foundNS = True

    return ns_entry


def get_ns_set(zonefile=None, extension=None):
    nsset = set()
    if extension[-1] != ".":
        extension = extension + "."
    if extension[0] != ".":
        extension = "." + extension

    with open(zonefile) as f:
        for line in f:
            ns_entry = parseNS(line, extension)
            if ns_entry != '0':
                nsset.add(ns_entry)
    return nsset


def zone_parser(zonefile=None, zonename=None, output_file=None):
    nsset = get_ns_set(zonefile=zonefile, extension=zonename)

    if len(nsset) > 0:
        with open(output_file, 'w') as aus:
            logging.info('Info reading zonefile for domain: {}'.format(zonefile))
            for k in nsset:
                aus.write(f"{k}\n")
    else:
        logging.info('Error with largeZoneParser.py: could not extract NS records from zone file'.format(zonefile))
        logging.info('Please run CycleHunter step-by-step and changeZoneParser.py to your zone synthax')
        sys.exit(output_file + "  has no NS records; stop here. Plase check if largeZoneParser correctly parsers your zone file")


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

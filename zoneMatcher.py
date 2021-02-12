# this file reads large zone fiels and extract its set of NS records

import json
import argparse
import logging
import sys

from domutils import getparent


def evalNSSet(cyclic, nsset):
    ret = False

    for ns in nsset:
        parentNS = getparent(ns)
        if parentNS[-1] != ".":
            parentNS = parentNS + "."
        if parentNS in cyclic:
            ret = True

    return ret


def parseZone(cyclic, zonefile, extension):
    bugged = dict()
    if extension[-1] != ".":
        extension = extension + "."
    if extension[0] != ".":
        extension = "." + extension

    counter = 0
    with open(zonefile) as f:
        nsset = set()
        foundZone = False

        tempDomain = ''
        for line in f:
            line = line.lower()
            sp = line.split('\t')
            counter = counter + 1

            if float(counter) % 100_000 == 0:
                print(f"reading line {counter} of zone file")

            if 'ns\t' in line:
                # if 'ns' in line and 'rrsig' not in line and 'dnskey' not in line and 'nsec3' not in line :
                if sp[0] != '':
                    if not foundZone:
                        tempDomain = sp[0]
                        if len(tempDomain.split(".")) == 1:
                            tempDomain = tempDomain + extension
                            foundZone = True
                            tempNS = sp[-1].rstrip()
                            if tempNS[-1] != ".":
                                tempNS = tempNS + extension
                            nsset.add(tempNS)

                    else:
                        '''
                        thne it is a new zone, need to do two things:
                        1. calc if it is bugged
                        2. create new zone
                        '''

                        result = evalNSSet(cyclic, nsset)

                        if result:
                            bugged[tempDomain] = list(nsset)

                        # reset
                        foundZone = False
                        nsset = set()
                        tempDomain = sp[0]
                        if len(tempDomain.split(".")) == 1:
                            tempDomain = tempDomain + extension

                        foundZone = True
                        tempNS = sp[-1].rstrip()
                        if tempNS[-1] != ".":
                            tempNS = tempNS + extension
                        nsset.add(tempNS)
                else:
                    if foundZone:
                        tempNS = sp[-1].rstrip()
                        if tempNS[-1] != ".":
                            tempNS = tempNS + extension
                        nsset.add(tempNS)
                    else:
                        # new zone
                        tempDomain = sp[0]
                        if len(tempDomain.split(".")) == 1:
                            tempDomain = tempDomain + extension

                        foundZone = True
                        nsset.add(sp[-1].rstrip())

    return bugged


def getCyclic(infile):
    ret = set()
    deps = dict()
    try:
        with open(infile, 'r') as f:
            deps = json.load(f)
    except:
        # if it's multiple dics in one json file
        with open(infile, 'r') as f:
            for line in f:
                tempD = json.loads(line)
                for k, v in tempD.items():
                    deps[k] = v


    for key, value in deps.items():
        if 'fullDep' in key:
            for ns1, ns2 in value.items():
                ret.add(ns1)
                ret.add(ns2)


    return ret


def zone_matcher(cyclic_domain_file=None, zonefile=None, zoneorigin=None, output_file=None):
    print("step 8: read cyclic domains")
    cyclic=''
    try:
        cyclic = getCyclic(cyclic_domain_file)
    except FileNotFoundError:
        logging.info("ERROR: no cyclic domain file")

    if cyclic=='':
        logging.info('ERROR: no cyclic domain file  ')
        sys.exit(cyclic_domain_file + "    does not exist; exiting ")

    else:
        print("step 8a: read zone file and find them")
        troubledDomains = parseZone(cyclic, zonefile, zoneorigin)
        print("step 8b: writing it to json")


        if len(troubledDomains)>0:
            with open(output_file, 'w') as fp:
                json.dump(troubledDomains, fp)
            print(f"\nThere are {len(troubledDomains)} domains that have at least one cyclic dependent NS")
            print('done')
        else:
            logging.info("ERROR: could not match domain names to NS records; please check zoneMatcher.py")
            sys.exit('ERROR:  could not match domain names to NS records; please check zoneMatcher.py')

if __name__ == '__main__':
    # Setup logging if called from command line
    logging.basicConfig(filename='zone-matcher.log',
                        level=logging.INFO, format="%(asctime)s zone_matcher: %(levelname)s %(message)s")
    # Read the command line arguments
    argparser = argparse.ArgumentParser(description="Determines how many domains are affected by cyclic dependency")
    argparser.add_argument('full_cycle_file', type=str, help="File with the list of full cycles")
    argparser.add_argument('zonefile', type=str, help="Zone file to analyze")
    argparser.add_argument('zonename', type=str, help="Zone origin")
    argparser.add_argument('output', type=str, help="File to save the output")
    args = argparser.parse_args()

    zone_matcher(cyclic_domain_file=args.full_cycle_file, zonefile=args.zonefile,
                 zoneorigin=args.zonename, output_file=args.output)

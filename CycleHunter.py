# This script encapsulates all the steps detailed in README.mkd
# You can use this to run all the necessary steps

from largeZoneParser import zone_parser
from CyclicDetector import map_nsset
from findCyclicDep import find_cycles
from fullDepParser import full_cycle_detection
from zoneMatcher import zone_matcher

import os
import argparse
import logging
from datetime import datetime

if __name__ == '__main__':
    CORES = os.cpu_count()

    # Setup logging for all future steps
    logging.basicConfig(filename='CycleHunter.log',
                        level=logging.INFO, format="%(asctime)s fireloop: %(levelname)s %(message)s")

    # Read the command line arguments
    argparser = argparse.ArgumentParser(description="Executes the fire loop detection")
    argparser.add_argument('--zonefile', type=str, help="Zone file to detect loops on")
    argparser.add_argument('--origin', type=str, help="Origin of the zonefile, eg, .COM")
    argparser.add_argument('--save-file', type=str, help="File to save the list of domains affected by a fire loop")
    argparser.add_argument('--workers', type=int, default=CORES, help="Number of parallel workers to query for DNS data")
    args = argparser.parse_args()

    now = datetime.now().strftime("%F")
    file_prefix = f"{args.origin.strip('.')}.{now}"
    output1 = f"{file_prefix}.step1.txt"
    output2 = f"{file_prefix}.step2.txt"
    output3 = f"{file_prefix}.step3.json"
    output4 = f"{file_prefix}.step4.json"

    # Step 1, extract all NS records
    zone_parser(zonefile=args.zonefile, zonename=args.origin, output_file=output1)

    # Step 2, query the list of NS records and record the timeouts
    map_nsset(output1, output2, workers=args.workers)

    # Step 3, Review the timed out NS records, and look for cyclic dependencies
    find_cycles(output2, output3)

    # Step 4, select the full cyclic dependencies from step 3
    full_cycle_detection(output3, output4)

    # Step 5, determine how many zones are affected
    zone_matcher(cyclic_domain_file=output4, zonefile=args.zonefile, zoneorigin=args.origin, output_file=args.save_file)

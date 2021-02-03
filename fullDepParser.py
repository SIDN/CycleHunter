import json
import argparse
import logging


def full_cycle_detection(dep_file=None, output_file=None):
    with open(dep_file) as f:
        deps = json.load(f)

    fullDep = dict()

    for k, v in deps.items():
        if k == 'fullDep':
            for zone, dep in v.items():
                if len(v) > 0:
                    fullDep[zone] = dep

    if len(fullDep) > 0:
        with open(output_file, 'a') as fp:
            json.dump(fullDep, fp)


if __name__ == '__main__':
    # Setup logging if called from command line
    logging.basicConfig(filename='full-cycle-dependency.log',
                        level=logging.INFO, format="%(asctime)s full_cycle: %(levelname)s %(message)s")
    # Read the command line arguments
    argparser = argparse.ArgumentParser(
        description="Reviews the dependency detection and filter outs only full cyclic dependencies")
    argparser.add_argument('cycle-file', type=str, help="File with the output from findCyclicDep")
    argparser.add_argument('output_file', type=str, help="File to save the full cycle cases")
    args = argparser.parse_args()

    full_cycle_detection(dep_file=args.cycle_file, output_file=args.output_file)

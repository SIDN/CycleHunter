# new detector
import dns.rcode
import dns.rdatatype
import dns.resolver
import datetime
import json
import random
import multiprocessing
import argparse
import logging
import tqdm
from collections import defaultdict

from domutils import getparent

'''
1. read the zone file, for each entry with an NS record

#find TIMEOUT domains
2. for each domain d, loops from its NSSet
3. For each NS in NSSet, try to:
    * get A
    * get AAAA
4a. If any A/AAAA resolves, domain is OK
4b. If all NSSet is NXDOMAIN, domain cannot be resolved (other type of error)
4c. IF A/AAAA resolves, but NSSet is noth auth , then it is out of scope of this cod
4d. If ALL A/AAAA, timeout, then we may be up to something.

#domains timeout to cyclic dependency.

1. Loop trhough the domains  above
2. For each NS on NSSet, get its parent auth server
3. Ask the parent for the auth servers of these domains
4. compare 3 to 2 , and see if they are in cyclic dependency


#todo first

1. write a class for NS
2. write a class for NSSet
3. wirte a class for domain

'''


class NS:
    def __init__(self, servername):
        self.serverName = servername
        self.A = set()
        self.AAAA = set()
        self.NXDOMAIN = False
        self.timeoutv4 = False
        self.timeoutv6 = False
        self.NOANSWERv4 = False
        self.NOANSWERv6 = False
        self.reachable = False
        self.reachablev4 = False

        self.reachablev6 = False

    def IsReachable(self):
        if not self.NXDOMAIN:
            if len(self.A) > 0 or len(self.AAAA) > 0:
                return True
            else:
                return False


def fetch_glue(ns):
    temp_ns = NS(ns)

    try:
        answer = dns.resolver.resolve(ns, 'A')
        response = answer.response
        # print(type(response))
        rcode = response.rcode()
        if rcode == dns.rcode.Rcode.NOERROR:
            temp_ns.reachable = True
            temp_ns.reachablev4 = True

            temp_ns.A = set(str(addr) for addr in response.answer)
        elif rcode == dns.rcode.Rcode.NXDOMAIN:
            temp_ns.NXDOMAIN = True

    except dns.resolver.Timeout:
        temp_ns.timeoutv4 = True
    except dns.resolver.NoAnswer:
        temp_ns.NOANSWERv4 = True
    except dns.resolver.NXDOMAIN:
        temp_ns.NXDOMAIN = True

    # now, check v6 only if v4 does not work
    if not temp_ns.reachable and (temp_ns.NOANSWERv4 or temp_ns.timeoutv4):
        try:
            answer = dns.resolver.resolve(ns, 'AAAA')
            response = answer.response
            # print(type(response))
            rcode = response.rcode()
            if rcode == 0:
                temp_ns.reachable = True
                temp_ns.reachablev6 = True

                temp_ns.AAAA = set(str(addr) for addr in response.answer)
            elif rcode == 3:
                temp_ns.NXDOMAIN = True
        except dns.resolver.Timeout:
            temp_ns.timeoutv6 = True
        except dns.resolver.NoAnswer:
            temp_ns.NOANSWERv6 = True
        except dns.resolver.NXDOMAIN:
            temp_ns.NXDOMAIN = True

    return temp_ns


def getParentNSes(k):
    # get the parent
    parent = getparent(k)
    toBeRet = []

    try:
        try:
            answer = dns.resolver.resolve(parent, 'NS')
            response = answer.response
            # print(type(response))
            rcode = response.rcode()

            # parent is valid

            if rcode == dns.rcode.NOERROR:
                try:
                    localA = response.answer
                    for k in localA:
                        for addr in k.items:
                            try:
                                tempNS = addr.target
                                toBeRet.append(str(tempNS))
                            except Exception as e:
                                logging.error(f"{k}: NS from parent has No A - {e}")
                except Exception as e:
                    logging.error(f'{k}: auth server has no NS, reason {e}')
                    pass
            elif rcode == dns.rcode.NXDOMAIN:
                logging.info(f"{parent} NXDOMAIN")
                toBeRet.append(-1)
            elif rcode == dns.rcode.SERVFAIL:
                logging.info(f"{parent} SERVFAIL")
        except Exception as e:
            logging.error(f"{k}: NS from parent has failed - {e}")
            # print(type(e))
            return 'ERROR'
    except Exception as e:
        logging.error(f"{k}: failed to retrieve NS answers - {e}")
    return toBeRet


def getNS(parent):
    # get the parent

    toBeRet = []

    try:
        answer = dns.resolver.resolve(parent, 'NS')
        response = answer.response
        # print(type(response))
        rcode = response.rcode()

        # parent is valid

        if rcode == dns.rcode.NOERROR:
            try:
                localA = response.answer
                for k in localA:
                    for addr in k.items:
                        try:
                            tempNS = addr.target
                            toBeRet.append(str(tempNS))
                        except Exception as e:
                            logging.error(f"{k}: failed getting ns getNS() for {parent} - {e}")
            except Exception as e:
                logging.error(f"{parent}: no NS - {e}")
                pass
        elif rcode == dns.rcode.NXDOMAIN:
            logging.error(f"Parent {parent} does not exist")
            toBeRet.append(-1)
    except Exception as e:
        return 'TIMEOUT'

    return toBeRet


def getA(ns):
    address = []
    try:
        answer = dns.resolver.resolve(ns, 'A')
        response = answer.response
        # print(type(response))
        rcode = response.rcode()
        if rcode == dns.rcode.NOERROR:
            try:
                localA = response.answer
                for k in localA:
                    for addr in k.items:
                        address.append(str(addr))
            except Exception as e:
                logging.error(f"{ns}: no A, reason {e}")
                pass
        elif rcode == dns.rcode.NXDOMAIN:
            address.append(-1)
    except Exception as e:
        logging.error(f"Querying A for {ns} produced exception {e}")

    return address


def getSOA(ns):
    # try to get a SOA, if it fails return ERROR
    try:
        answer = dns.resolver.resolve(ns, 'SOA')
        response = answer.response
        # print(type(response))
        rcode = response.rcode()
        if rcode == dns.rcode.NOERROR:
            return 0
        elif rcode == dns.rcode.NXDOMAIN:
            return -1
        elif rcode == dns.rcode.SERVFAIL:
            return "ERROR"
    except Exception as e:
        logging.error(f"Querying SOA for {ns} generated an exception {e}")
        return 'ERROR'


def retrieveNSFromParent(fqdn, ip_from_auth_server):
    queryType = dns.rdatatype.NS

    try:
        ip_from_auth_server = ip_from_auth_server[0]
    except Exception as e:
        logging.error(f"Using {ip_from_auth_server} triggered an exception {e}")
    query = dns.message.make_query(fqdn, queryType)

    ret = defaultdict(list)
    try:
        response = dns.query.udp(query, ip_from_auth_server, timeout=5)
    except Exception as e:
        logging.error(f"Failed {fqdn} query to {ip_from_auth_server} - {e}")
        response = "NA"

    if response != "NA":
        if len(response.answer) > 0:
            logging.error(f"shoot, {fqdn} has answer at parent")
        elif len(response.answer) == 0 and len(response.authority) > 0:
            rcode = response.rcode()

            if rcode == dns.rcode.NOERROR:
                for item in response.authority:
                    if item.rdtype == dns.rdatatype.SOA:
                        # print("has soa, all GOOD")
                        return 'SOA'
                    elif item.rdtype == dns.rdatatype.NS:
                        for addr in item.items:
                            namez = str(item.name)

                            ret[namez].append(str(addr))

                        return ret
            elif rcode == dns.rcode.NXDOMAIN:
                return 'NXDOMAIN'


def probe_ns(nsname):
    localSoa = getSOA(nsname)
    res = None
    # only analyze nses that have no soa

    if localSoa == 'ERROR':
        logging.error(f"{nsname} has error with SOA query")
        isOK = False
        timeOUtButNotFromParent = False
        bailiStatus = False

        tempTest = getparent(nsname)

        if tempTest != "" and len(tempTest.split(".")) < 2:
            # print(str(tempTest))
            logging.info(f"{nsname} is already at the top (tld), skip it")
        else:
            parentNS = getParentNSes(nsname)

            logging.info(f"the parent domain of {nsname} is {parentNS}")
            if isinstance(parentNS, list):
                # check if in bailwikc at least one
                sp2 = nsname.split(".")
                baili = ''
                for ww in range(1, len(sp2) - 1):
                    baili = baili + "." + sp2[ww]
                if baili[0] == ".":
                    baili = baili[1:]

                for e in parentNS:
                    logging.info(f"{nsname} has bailiwick {baili} and nameserver {e}")
                    if baili in e:
                        logging.info(f"Result: {nsname} is fine has NS in bailiwick {e}")
                        bailiStatus = True
                        break
            elif parentNS == "ERROR":
                tempP = getparent(nsname)

                tempP = getparent(tempP)
                if len(tempP) > 0:
                    if tempP[-1] != '.':
                        tempP = tempP + "."
                else:
                    print(f"tempP is {tempP}")
                parentNS = getNS(tempP)
                timeOUtButNotFromParent = True
                logging.info(f"{nsname} has timed out via normal resolution")

            if not bailiStatus:
                for singleNS in parentNS:
                    if not isOK:
                        tempA = getA(singleNS)
                        if tempA != -1:
                            tempNSParent = retrieveNSFromParent(nsname, tempA)
                            # we only add domains here if they timeout
                            if timeOUtButNotFromParent and isinstance(tempNSParent, dict):
                                res = tempNSParent
                                logging.info(f"Result: {nsname} has been added")
                                isOK = True
                            elif tempNSParent == 'SOA':
                                isOK = True
                                logging.info(f"Result: {nsname} has SOA (is fine)")
                                # do nothing domain is ok
                            elif tempNSParent == 'NXDOMAIN':
                                isOK = True
                                logging.info(f"Result: {nsname} IS NXDOMAIN")

    return nsname, res


def probeNSes(setOfNSes, workers=5):
    results = dict()

    ns_total = len(setOfNSes)
    counter = 0
    with multiprocessing.Pool(processes=workers) as pool:
        for nsname, probe_res in tqdm.tqdm(pool.imap_unordered(probe_ns, setOfNSes, chunksize=15), total=ns_total):
            counter += 1
            if probe_res is not None:
                results[nsname] = probe_res

    return results


def readFAST(filename):
    with open(filename, 'r') as f:
        nsset = set(line.strip() for line in f.readlines())

    return nsset


'''
   Definition of cyclic domain is the following: 
    * at least one it's NS point to another NS/CNAME '''


def map_nsset(nsset_file, output_file, limit=None, workers=5):
    logging.info('start reading zone file')
    before = datetime.datetime.now()

    nsRecords = readFAST(nsset_file)
    logging.info('end reading zone file')
    after = datetime.datetime.now()
    diff = (after - before).seconds
    logging.info(f"It took {diff} seconds to read the file")
    logging.info("start detect cycles")
    logging.info(f"the number of nsRecords  is {len(nsRecords)}")

    if limit is None:
        # now shuffle the set
        lRecords = list(nsRecords)
        random.shuffle(lRecords)
    else:
        lRecords = random.sample(nsRecords, limit)
    timeOutNSes = probeNSes(lRecords, workers=workers)
    with open(output_file, 'w') as fp:
        json.dump(timeOutNSes, fp)

    print("und jetz? ")


if __name__ == '__main__':
    # Setup logging if called from command line
    logging.basicConfig(filename='nameserver-mapper.log',
                        level=logging.INFO, format="%(asctime)s ns_mapper: %(levelname)s %(message)s")
    # Read the command line arguments
    argparser = argparse.ArgumentParser(
        description="Fetches the glue records for the list of nameservers in the input file")
    argparser.add_argument('nsset_file', type=str, help="File with the list of nameservers")
    argparser.add_argument('output_file', type=str, help="File to save the mapping")
    argparser.add_argument('--limit', type=int, required=False, default=None,
                           help="Restrict the list of nameserver, use for testing")
    argparser.add_argument('--workers', type=int, default=5,
                           help="Number of parallel workers to query for DNS data")
    args = argparser.parse_args()

    asyncio.run(map_nsset(args.nsset_file, args.output_file, limit=args.limit,
                          workers=args.workers))

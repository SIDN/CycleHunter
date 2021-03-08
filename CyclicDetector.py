# new detector
import dns.asyncresolver
import dns.asyncquery
import dns.rcode
import dns.rdatatype
import dns.resolver
import async_lru
import asyncio
import datetime
import json
import random
import multiprocessing
import argparse
import logging
import tqdm.asyncio
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
3. write a class for domain

'''



@async_lru.alru_cache(maxsize=None)
async def getParentNSes(k):
    # get the parent
    parent = getparent(k)
    toBeRet = []

    try:
        try:
            answer = await dns.asyncresolver.resolve(parent, 'NS')
            response = answer.response
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
            return 'ERROR'
    except Exception as e:
        logging.error(f"{k}: failed to retrieve NS answers - {e}")
    return toBeRet


@async_lru.alru_cache(maxsize=None)
async def getNS(parent):
    # get the parent
    toBeRet = []

    try:
        answer = await dns.asyncresolver.resolve(parent, 'NS')
        response = answer.response
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


@async_lru.alru_cache(maxsize=None)
async def getA(ns):
    address = []
    try:
        answer = await dns.asyncresolver.resolve(ns, 'A')
        response = answer.response
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


@async_lru.alru_cache(maxsize=None)
async def getSOA(ns):
    # try to get a SOA, if it fails return ERROR
    try:
        answer = await dns.asyncresolver.resolve(ns, 'SOA')
        response = answer.response
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


@async_lru.alru_cache(maxsize=None)
async def retrieveNSFromParent(fqdn, ip_from_auth_server):
    queryType = dns.rdatatype.NS

    try:
        ip_from_auth_server = ip_from_auth_server[0]
    except Exception as e:
        logging.error(f"Using {ip_from_auth_server} triggered an exception {e}")
    query = dns.message.make_query(fqdn, queryType)

    ret = defaultdict(list)
    try:
        response = await dns.asyncquery.udp(query, ip_from_auth_server, timeout=5)
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


@async_lru.alru_cache(maxsize=None)
async def probe_ns(nsname):
    localSoa = await getSOA(nsname)
    res = None
    # only analyze nses that have no soa

    if localSoa == 'ERROR':
        logging.error(f"{nsname} has error with SOA query")
        isOK = False
        timeOUtButNotFromParent = False
        bailiStatus = False

        tempTest = getparent(nsname)

        if tempTest != "" and len(tempTest.split(".")) < 2:
            logging.info(f"{nsname} is already at the top (tld), skip it")
        else:
            parentNS = await getParentNSes(nsname)

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
                parentNS = await getNS(tempP)
                timeOUtButNotFromParent = True
                logging.info(f"{nsname} has timed out via normal resolution")

            if not bailiStatus:
                for singleNS in parentNS:
                    if not isOK:
                        tempA = await getA(singleNS)
                        if tempA != -1:
                            tempNSParent = await retrieveNSFromParent(nsname, tuple(sorted(tempA)))
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


async def probe_ns_limited_concurrency(nsname, sem):
    async with sem:
        return await probe_ns(nsname)


async def probeNSes(setOfNSes, workers=5):
    results = dict()

    ns_total = len(setOfNSes)

    sem = asyncio.Semaphore(value=workers)

    aws = [probe_ns_limited_concurrency(nsname, sem) for nsname in setOfNSes]
    for coro in tqdm.asyncio.tqdm.as_completed(aws):
        nsname, res = await coro
        results[nsname] = res

    return results


def readFAST(filename):
    with open(filename, 'r') as f:
        nsset = set(line.strip() for line in f.readlines())

    return nsset


'''
   Definition of cyclic domain is the following: 
    * at least one it's NS point to another NS/CNAME '''


async def map_nsset(nsset_file, output_file, limit=None, workers=5):
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
    timeOutNSes = await probeNSes(lRecords, workers=workers)
    with open(output_file, 'w') as fp:
        json.dump(timeOutNSes, fp)

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

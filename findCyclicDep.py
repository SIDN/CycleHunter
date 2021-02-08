import dns.resolver
from dns import resolver
import json
import sys
import argparse
import logging

from domutils import getparent


class Authority(object):
    def __init__(self, zone):
        self.zone = zone.lower()

        self.NSrecords = set()
        self.zoneItDepends = set()
        self.extZonesItDepends = set()
        self.zoneHasAtLeastOneNSinBailiwick = False
        self.allNSinBailiwick = False
        self.resolvable = None

    def addNS(self, ns):
        if ns[-1] != ".":
            ns = ns + "."
        self.NSrecords.add(ns)

    def calcParentZones(self):
        inZoneCounter = 0
        for i in self.NSrecords:
            # if 'bio-bak' in i:
            #    print('wait')
            parent = getparent(i)
            parentLenght = len(parent.split("."))
            if parentLenght> 0:
                if parent[-1] != ".":
                    parent = parent + "."
            else:
                print("CHECK: parent has zero length")
            isParentTLD = False
            # if len==2 , then is a TLD
            if parentLenght == 2:
                isParentTLD = True
                self.zoneHasAtLeastOneNSinBailiwick = True
                inZoneCounter = inZoneCounter + 1
                self.zoneItDepends.add(i)
            elif parentLenght > 2 and parent != self.zone:
                self.zoneItDepends.add(parent)
            else:
                self.zoneHasAtLeastOneNSinBailiwick = True
                self.zoneItDepends.add(parent)
                inZoneCounter = inZoneCounter + 1

        if inZoneCounter == len(self.NSrecords):
            self.allNSinBailiwick = True

        self.extZonesItDepends = self.zoneItDepends
        if self.zone in self.extZonesItDepends:
            self.extZonesItDepends.remove(self.zone)

        return self.extZonesItDepends


def makeAuth(bugged):
    timeOutZones = dict()

    for ns, authoritySection in bugged.items():
        for zone, nsset in authoritySection.items():
            # If the zone is in the timeOutZones, get it, if not, generate an Authority object
            temp_zone = timeOutZones.get(zone, Authority(zone))

            # add NSes
            for i in nsset:
                temp_zone.addNS(i.lower())

            timeOutZones[zone.lower()] = temp_zone

    return timeOutZones


def getZonesWithoutInBailiwickServer(timeOutZones):
    timeOutWOBailick = dict()
    for k, v in timeOutZones.items():

        tempV = v.calcParentZones()
        timeOutZones[k] = v
        # print("only add zones with ALL NSes all of bailiwkc")

        # print(str(v.zoneHasAtLeastOneNSinBailiwick)+ "," + str(v.allNSinBailiwick))

        if not v.allNSinBailiwick:
            timeOutWOBailick[k] = v

        # if v.zoneHasAtLeastOneNSinBailiwick!=v.allNSinBailiwick:
        #    print('wait here')
    return timeOutWOBailick


def figureParentRecords(domain):
    parentZone = getparent(domain)

    toBeRet = []

    localRes = resolver.Resolver()
    localRes.timeout = 5
    localRes.lifetime = 5
    answer = ''
    try:
        answer = localRes.resolve(parentZone, 'NS')
    except Exception as e:
        logging.error(f"Getting NS for {domain} triggered exception {e}")
        return 'NXDOMAIN'

    if answer != '':
        response = answer.response
        # print(type(response))
        rcode = response.rcode()

        # parent is valid

        if rcode == 0:
            try:
                localA = response.answer
                for k in localA:
                    for addr in k.items:
                        tempNS = ''
                        try:
                            tempNS = addr.target
                            toBeRet.append(str(tempNS))
                        except Exception as e:
                            print(e)
                            # print(type(e))
            except:
                print('no NS')
                pass;
        elif rcode == 3:
            print('does not exist')
            toBeRet.append(-1)

    return toBeRet


def getDeps(timeOutWOBailick):
    codep = dict()
    for zone, localAuth in timeOutWOBailick.items():
        tempDepzone = localAuth.zoneItDepends
        codep[zone] = tempDepzone

    return codep


def getAAAA(ns):
    localRes = resolver.Resolver()
    localRes.timeout = 5
    localRes.lifetime = 5
    address = []
    try:

        answer = localRes.resolve(ns, 'AAAA')
        response = answer.response
        # print(type(response))
        rcode = response.rcode()
        if rcode == 0:
            try:
                localA = response.answer
                for k in localA:
                    for addr in k.items:
                        address.append(str(addr))
            except:
                print('no A')
                pass;

        elif rcode == 3:
            address.append(-1)
    except Exception as e:
        print(e)

    return address


def getA(ns):
    localRes = resolver.Resolver()
    localRes.timeout = 5
    localRes.lifetime = 5
    address = []
    try:

        answer = localRes.resolve(ns, 'A')
        response = answer.response
        # print(type(response))
        rcode = response.rcode()
        if rcode == 0:
            try:
                localA = response.answer
                for k in localA:
                    for addr in k.items:
                        address.append(str(addr))
            except:
                print('no A')
                pass;

        elif rcode == 3:
            address.append(-1)
    except Exception as e:
        print(e)

    return address


def retrieveNSFromParent(fqdn, ipFromAuthServer):
    queryType = dns.rdatatype.NS

    try:
        ipFromAuthServer = ipFromAuthServer[0]
    except:
        print("the error is " + str(ipFromAuthServer))
    query = dns.message.make_query(fqdn, queryType)

    # initialize var
    response = -1

    ret = dict()
    try:
        response = dns.query.udp(query, ipFromAuthServer, timeout=5)
    except Exception as e:
        print('stope here')
        response = "NA"

    if response != "NA":
        if len(response.answer) > 0:

            isCNAME = False
            cnameValue = ""

            for item in response.answer:
                namez = str(item.name).lower()
                if item.rdtype == 5:
                    # cnameValue = str(item.name).lower()
                    for singleI in item.items:
                        tempV = str(singleI.target).lower()
                        cnameValue = tempV

                    if namez not in ret:
                        tempL = []
                        tempL.append(cnameValue)
                        ret[namez] = tempL
                    else:
                        tempL = ret[namez]
                        tempL.append(cnameValue)
                        ret[namez] = tempL

                else:
                    print('aint cname')

            return ret
        elif len(response.answer) == 0 and len(response.authority) > 0:
            rcode = response.rcode()

            if rcode == 0:

                for item in response.authority:
                    if item.rdtype == 6:
                        # print("has soa, all GOOD")
                        return 'SOA'
                    elif item.rdtype == 2:

                        for addr in item.items:

                            namez = item.name
                            namez = str(namez)

                            if namez not in ret:
                                tempL = []
                                tempL.append(str(addr))
                                ret[namez] = tempL
                            else:
                                tempL = ret[namez]
                                tempL.append(str(addr))
                                ret[namez] = tempL

                        return ret
            elif rcode == 3:
                return 'NXDOMAIN'


def getNS2(parent):
    # get the parent

    toBeRet = []

    localRes = resolver.Resolver()
    localRes.timeout = 5
    localRes.lifetime = 5
    answer = ''
    try:

        answer = localRes.resolve(parent, 'NS')
    except Exception as e:
        if 'timed out' in str(e):
            toBeRet.append('TIMEOUT')
            return toBeRet
    if answer != '':

        response = answer.response
        # print(type(response))
        rcode = response.rcode()

        # parent is valid

        if rcode == 0:

            try:
                localA = response.answer
                for k in localA:
                    for addr in k.items:
                        tempNS = ''
                        try:
                            tempNS = addr.target
                            toBeRet.append(str(tempNS))
                        except Exception as e:
                            print(e)

                            # print(type(e))
            except:
                print('no NS')
                pass;

        elif rcode == 3:
            print('does not exist')
            toBeRet.append('NXDOMAIN')

    return toBeRet


def findParents(x):
    results = dict()

    '''
    1. get soa - see if it resolves 
        1a. if it works, proceed to 2
        1b. if soa does not work, then have to find the real parent recursively utnil get an answer
    2. for the nmname is soa list, then ask this mname for all NS records of the parent zone
    '''
    soaRec = getSOA(x)

    # has soa
    if len(soaRec) == 0:
        logging.warning(f"Domain {x} has no soa")
        parentX = getparent(x)
        if parentX[-1] != ".":
            localParent = parentX + "."
        else:
            localParent = parentX

        nsLocalParent = ''
        try:
            nsLocalParent = getNS(localParent)
        except Exception as e:
            print("failed to get NS from zone at findParents" + str(x))
            print(e)
            print(type(e))
            return -1

        if nsLocalParent != '':
            # print("analyze here")
            for k in nsLocalParent:
                tempA = getA(k)
                tempAAAA = getAAAA(k)

                gotAnswer = False

                if gotAnswer == False:
                    if len(tempA) > 0:
                        # query it

                        resParent = retrieveNSFromParent(x, tempA)

                        if isinstance(resParent, dict):
                            # then got results
                            gotAnswer = True
                            tempAuth = Authority(x)
                            for k, v in resParent.items():
                                for singleNS in v:
                                    tempAuth.addNS(singleNS)
                            tempAuth.calcParentZones()
                            results[x] = tempAuth.zoneItDepends
                            return results

                        elif isinstance(resParent, str):
                            if resParent == 'NXDOMAIN':
                                return "NXDOMAIN"
                        else:
                            print("FAILED hon here too")
                            print(resParent)
                            return resParent



        else:

            return nsLocalParent
    else:
        # the domain resolves, the soa record shows the first avail auth server.
        for k, v in soaRec.items():
            parentsK = ''
            try:
                parentsK = getNS2(k)
            except  Exception as e:
                print("failed to get NS from zone that has soa on findParents " + str(k))
                print(e)
                print(type(e))

            if parentsK != '':

                tempAuth = Authority(x)
                for singleNS in parentsK:
                    tempAuth.addNS(singleNS)
                tempAuth.calcParentZones()
                results[x] = tempAuth.zoneItDepends
                return results

            else:
                print('FOUND SOA< but not NS, could not happen')
                return -2


def getDepZonesRecursive(x):
    '''
    this method gets the zones each NS depends on, and put them in a set or something
    the idea is to determine on what zones domain x depends on

    steps
    1. try to get the NSes of the X. If it works, fine! add them and return a dict
    2. If it fails, then  recursively get the parent until someone responds with NS.
    And from that, get is NS records
    '''

    isOK = False
    NSworks = False
    results = dict()
    parentNS = ''
    try:
        parentNS = getNS2(x)
        if isinstance(parentNS, list):
            if len(parentNS) > 0:
                if parentNS[0] != 'TIMEOUT':
                    isOK = True
                    NSworks = True
    except Exception as e:
        print("failed to get NS from zone" + str(x))
        print(e)
        print(type(e))

    # in case there wer errors, need to fix this
    if isOK == False:
        try:
            parentNSX = findParents(x)
            '''
            results from the method above
            *  dict - it worked
            * -1: no soa
            * -2 : soa, but no ns (should never happen I guess)
            
            '''
            if isinstance(parentNSX, dict):
                isOK = True
                # then, convert it to list
                tempP = []
                for k, v in parentNSX.items():
                    for singleNS in v:
                        parentNS.append(singleNS)

            elif parentNSX == -1 or parentNSX == -2:
                isOK = False
            elif parentNS == 'NXDOMAIN':
                results[x] = 'NXDOMAIN'
                return results

        except Exception as e:
            print("failed to find parent NS from zone" + str(x))
            print(e)
            print(type(e))

    # this is when you can retrive the NS of the parent; no biggie here, when the NS is reachable
    if isOK == True:
        tempAuth = Authority(x)
        for k in parentNS:
            tempAuth.addNS(k)
        tempAuth.calcParentZones()
        if NSworks == True:
            tempAuth.resolvable = True
            'TODO: fix here, add support to cnnam and disregard '

        whatZones = tempAuth.zoneItDepends
        if len(whatZones) == 0:
            whatZones = ''
        results[x] = tempAuth
        return results
    else:

        return 'NXDOMAIN'


def getDepZones(x):
    # this code gets all the zones a certain zone depends
    # example, giovane-moura.nl depends on webreus.nl
    isOK = False
    results = dict()

    localNSes = getNS(x)
    timeOUtButNotFromParent = False

    if localNSes == "TIMEOUT" or localNSes == "NXDOMAIN":
        logging.info(f"Domain {x}: NX or bailiwick?")
        tempP = getparent(x)

        if tempP[-1] != '.':
            tempP = tempP + "."
        parentNS = getNS(tempP)

        # print(parentNS)
        timeOUtButNotFromParent = True
        if parentNS != 'TIMEOUT':
            for singleNS in parentNS:
                if isOK == False and singleNS not in results:
                    tempA = getA(singleNS)
                    if tempA != -1:
                        tempNSParent = retrieveNSFromParent(x, tempA)
                        # we only add domains here if they timeout
                        if timeOUtButNotFromParent == True and isinstance(tempNSParent, dict):

                            results[x] = tempNSParent
                            # for key, v in tempNSParent.items():
                            #    if key not in results:

                            # results[key]=v
                            # else:
                            #    print('been tghere done that')

                            isOK = True
                        elif tempNSParent == 'SOA':
                            isOK = True
                            # do nothing domain is ok
                        elif tempNSParent == 'NXDOMAIN':
                            isOK = True
                            return 'NXDOMAIN'
        else:
            print("Parent does no work,try to get soa")
            # try get soa

            parentNS = getSOA(tempP)

            return 'BROKEN NS'
        return results
    elif len(localNSes) > 0:
        results[x] = localNSes
        return results


def getNS(parent):
    # get the parent

    toBeRet = []

    localRes = resolver.Resolver()
    localRes.timeout = 5
    localRes.lifetime = 5
    answer = ''
    try:

        answer = localRes.resolve(parent, 'NS')
    except Exception as e:
        print(e)

        print(type(e))
        return 'NXDOMAIN'

    if answer != '':

        response = answer.response
        # print(type(response))
        rcode = response.rcode()

        # parent is valid

        if rcode == 0:

            try:
                localA = response.answer
                for k in localA:
                    for addr in k.items:
                        tempNS = ''
                        try:
                            tempNS = addr.target
                            toBeRet.append(str(tempNS))
                        except Exception as e:
                            print(e)

                            # print(type(e))
            except:
                print('no NS')
                pass;

        elif rcode == 3:
            print('does not exist')
            toBeRet.append(-1)

    return toBeRet


def getSOA(ns):
    localRes = resolver.Resolver()
    localRes.timeout = 5
    localRes.lifetime = 5
    answer = ''
    soa = dict()
    # try to get a SOA, if it fails return ERROR
    try:
        answer = localRes.resolve(ns, 'SOA')
    except Exception as e:
        print(e)
        if 'does not contain an answer' in str(e):
            tempDict = e.kwargs
            response = tempDict['response']
            tempSOA = []
            authZone = ''
            for k in response.authority:
                authZone = str(k.name)
                for singleItem in k.items:
                    tempV = str(singleItem.mname)
                    tempSOA.append(tempV)
            soa[authZone] = tempSOA
            return soa

        else:
            logging.info(f"BROKEN SOA for {ns}")
            return soa

    if answer != '':
        response = answer.response
        # print(type(response))
        rcode = response.rcode()
        if rcode == 0:
            return 0
        elif rcode == 3:
            return -1
        elif rcode == 2:
            return "ERROR"


def sortDeps(codependency, timeOutWOBailick):
    cyclicDependentZones = dict()
    cyclicDependentZones['notResolvable'] = dict()

    cyclicDependentZones['Resolvable'] = dict()

    clearedForNX = set()
    clearedZonesForOK = set()

    bailiwickZonesOK = set()
    domainsThatFailedBUtNotCyclicDependency = set()
    total = str(len(codependency))
    counter = 0
    for zone, extDepentZones in codependency.items():
        reverseDep = set()
        counter = counter + 1
        logging.info(f"Analyzying {zone}. Domain {counter}/{total}")

        # to be cyclic dependent, all zones here must from tempDepZone must point to zone

        for singleZone in extDepentZones:

            externalAgain = ''
            localDepZones = ''
            if singleZone in timeOutWOBailick:
                localDepZones = timeOutWOBailick[singleZone].zoneItDepends

            else:
                # externalAgain = getDepZones(singleZone)
                externalAgain = getDepZonesRecursive(singleZone)

                # if we get a dict
                if isinstance(externalAgain, dict):
                    localDepZones = set()
                    for ext2zone, dep2zone in externalAgain.items():
                        if isinstance(dep2zone, str) == False:
                            for singelDep2Zone in dep2zone.zoneItDepends:
                                if dep2zone != '':
                                    localDepZones.add(singelDep2Zone.lower())

                elif externalAgain == "NXDOMAIN":
                    clearedForNX.add(zone)
                elif externalAgain == "OK":
                    clearedZonesForOK.add(zone)

                elif externalAgain == "BROKEN":
                    print("broken NS")

            # now, process localDepZone
            hasDiffZone = False
            for k in localDepZones:
                if k.lower() == zone.lower() and hasDiffZone == False:
                    # domain is cyclic depednet
                    if zone.lower() not in cyclicDependentZones:

                        resolvable = timeOutWOBailick[zone.lower()].resolvable
                        if resolvable == True:
                            tempL = cyclicDependentZones['Resolvable']
                            tempL[zone.lower()] = singleZone
                            cyclicDependentZones['Resolvable'] = tempL
                        else:
                            tempL = cyclicDependentZones['notResolvable']
                            tempL[zone.lower()] = singleZone
                            cyclicDependentZones['notResolvable'] = tempL

                    else:
                        print('it shoudl not get here I guess')

                elif not hasDiffZone:
                    # print(zone.lower() + ' is not cyclic dependent')
                    domainsThatFailedBUtNotCyclicDependency.add(zone.lower())
                    hasDiffZone = True
                elif hasDiffZone:
                    pass

    return cyclicDependentZones


def sortDepsNew(timeOutWOBailick):
    """
    codependency= list of all zones that the timeout NSes depend
    timeOutWOBailick =dictionary with Authority  objects

    goal : iterate over codependency and return a dict like timeOutWithoutBailick

    """

    # dict with the new crated Auth
    newAuth = dict()

    # to be returned
    cyclicDependentZones = dict()
    cyclicDependentZones['partialDep'] = dict()
    cyclicDependentZones['fullDep'] = dict()
    cyclicDependentZones['fullDepWithInzone'] = dict()

    # unique zones from all timeout domais
    zoneAndDeps = getDeps(timeOutWOBailick)

    # dict clear with zones with NX
    clearedForNX = []

    # OK zones now
    clearedZonesForOK = []

    # clear with multiple zones
    clearedZonesForMultipleZones = []

    # other failed domains
    domainsThatFailedBUtNotCyclicDependency = []

    total = str(len(zoneAndDeps))
    counter = 0

    for zone, extDepentZones in zoneAndDeps.items():
        reverseDep = set()
        counter = counter + 1
        print('analyzying ' + zone + ". Domain " + str(counter) + " from " + total)

        # to be cyclic dependent, all zones here must from tempDepZone must point to zone
        if True:
            # evaluate every single zone they depend on
            for singleZone in extDepentZones:

                localDepZones = ''
                tempAuthDict = dict()
                if singleZone in timeOutWOBailick:

                    tempAuthDict[singleZone] = timeOutWOBailick[singleZone]
                    localDepZones = set()
                    for ext2zone, dep2zone in tempAuthDict.items():
                        if isinstance(dep2zone, str) == False:
                            for singelDep2Zone in dep2zone.zoneItDepends:
                                if dep2zone != '':
                                    localDepZones.add(singelDep2Zone.lower())

                else:

                    tempAuthDict = getDepZonesRecursive(singleZone)

                    # if we get a dict
                    if isinstance(tempAuthDict, dict):
                        localDepZones = set()
                        for ext2zone, dep2zone in tempAuthDict.items():
                            if isinstance(dep2zone, str) == False:
                                for singelDep2Zone in dep2zone.zoneItDepends:
                                    if dep2zone != '':
                                        localDepZones.add(singelDep2Zone.lower())

                    elif tempAuthDict == "NXDOMAIN":
                        clearedForNX.append(zone)
                    elif tempAuthDict == "OK":
                        clearedZonesForOK.append(zone)

                    elif tempAuthDict == "BROKEN":
                        print("broken NS")

                # add tempAuthDict to the new domains
                hasDiffZone = False
                if isinstance(tempAuthDict, dict):
                    for k, v in tempAuthDict.items():
                        v.calcParentZones()
                        newAuth[k] = v

                        if v.extZonesItDepends != None:
                            hasDiffZone = True

                    # now, process localDepZone
                    if len(localDepZones) > 0:

                        # there are two cateogries of codep: one fullY (1to1, then there's one only localDepzone)
                        # full DEP
                        if len(localDepZones) == 1:

                            for k in localDepZones:

                                # the error is here: must be not ONLY zone, but ALL

                                if k.lower() == zone.lower() and hasDiffZone == True:
                                    # domain is cyclic depednet

                                    if timeOutWOBailick[zone].zoneHasAtLeastOneNSinBailiwick == False:

                                        if zone.lower() not in cyclicDependentZones['fullDep']:

                                            fp = cyclicDependentZones['fullDep']
                                            fp[zone] = singleZone
                                            cyclicDependentZones['fullDep'] = fp

                                        else:
                                            print('it shoudl not get here I guess')

                                    else:

                                        if zone.lower() not in cyclicDependentZones['fullDepWithInzone']:
                                            fp = cyclicDependentZones['fullDepWithInzone']
                                            fp[zone] = singleZone
                                            cyclicDependentZones['fullDepWithInzone'] = fp


                                elif hasDiffZone == False:
                                    # print(zone.lower() + ' is not cyclic dependent')
                                    domainsThatFailedBUtNotCyclicDependency.append(zone.lower())
                                    # hasDiffZone=True
                                else:
                                    # print('waht now')
                                    pass
                            else:
                                clearedZonesForMultipleZones.append(zone.lower())


                        elif len(localDepZones) > 1:
                            for k in localDepZones:

                                # the error is here: must be not ONLY zone, but ALL

                                if k.lower() == zone.lower() and hasDiffZone == True:
                                    # domain is cyclic depednet
                                    if zone.lower() not in cyclicDependentZones['partialDep']:
                                        print("object has no resolvable, damn it ")
                                        pd = cyclicDependentZones['partialDep']
                                        pd[zone.lower()] = singleZone
                                        cyclicDependentZones['partialDep'] = pd


                                    else:
                                        print('it shoudl not get here I guess')

                                elif hasDiffZone == False:
                                    # print(zone.lower() + ' is not cyclic dependent')
                                    domainsThatFailedBUtNotCyclicDependency.append(zone.lower())
                                    # hasDiffZone=True
                                else:
                                    # print('waht now')
                                    pass
                            else:
                                clearedZonesForMultipleZones.append(zone.lower())
                        else:
                            print('zone has been eval')
                            pass
    return cyclicDependentZones


def classZones(domains):
    ret = dict()
    ret['FullyCyclic'] = []
    ret['CyclicBUtResolvableGivenInZone'] = []
    for k, v in domains.items():

        parentsK = ''
        try:
            parentsK = getNS2(k)
        except  Exception as e:
            print("failed to get NS from zone that has soa on findParents " + str(k))
            print(e)
            print(type(e))

        if parentsK != '':
            tempL = ret['FullyCyclic']
            tempDict = dict()
            tempDict[k] = v
            tempL.append(tempDict)
            ret['FullyCyclic'] = tempL
        else:
            tempL = ret['CyclicBUtResolvableGivenInZone']
            tempDict = dict()
            tempDict[k] = v
            tempL.append(tempDict)
            ret['CyclicBUtResolvableGivenInZone'] = tempL

    return ret


def find_cycles(timeout_file=None, output_file=None):
    print("Step 1:  read timed out zones")
    with open(timeout_file) as f:
        bugged = json.load(f)

    # create Authority objects from timed out zones
    print("Step 2: create Authority objects")
    timeOutZones = makeAuth(bugged)

    print("Step 3: get only zones without in-bailiwick/in-zone authoritative servers")
    zonesWoBailiwick = getZonesWithoutInBailiwickServer(timeOutZones)

    print("Step 4: sort which ones are cyclic")
    cyclic = sortDepsNew(zonesWoBailiwick)

    # print it

    # print("step 6: classifying domains as resolvanble and not resolvable")
    # classified=classZones(cyclic)

    print("step 7: writing down results")
    if len(cyclic)>0:
        with open(output_file, 'w') as fp:
            json.dump(cyclic, fp)
    else:
        logging.info('Warning: no cylic dependent NS records found. Stopping here   ')
        sys.exit(output_file + "   cylic dependent NS records found. Stopping here ")


if __name__ == '__main__':
    # Setup logging if called from command line
    logging.basicConfig(filename='cycle-finder.log',
                        level=logging.INFO, format="%(asctime)s cycle_finder: %(levelname)s %(message)s")
    # Read the command line arguments
    argparser = argparse.ArgumentParser(
        description="Verifies timed out NS, either parent or child, and checks the ones with cyclic dependency")
    argparser.add_argument('timeout_file', type=str, help="File with the timeout output from CyclicDetector.py")
    argparser.add_argument('cycle_output', type=str, help="File to save the cycles detected")
    args = argparser.parse_args()

    find_cycles(timeout_file=args.timeout_file, output_file=args.cycle_output)

#this file reads large zone fiels and extract its set of NS records

import sys
import json



def getParent(y):
    z=y
    if y[-1]!=".":
        z=y+"."
    sp=z.split(".")
    parentDomain=''

    if len(sp)>3:
        max=len(sp)-1
        #print(max)
        for k in range(1, max):
            #print(k)
            parentDomain=parentDomain+"."+sp[k]


    elif len(sp)==3:
        parentDomain=sp[-2]
        return parentDomain
    elif len(sp)==2:
        parentDomain= y+"."
        return parentDomain
    try:
        if parentDomain[0]==".":
            parentDomain=parentDomain[1:]
        #print(parentDomain)
    except:
        pass;
        #not sure what to do here
    return parentDomain



def evalNSSet(cyclic,nsset):

    ret= False

    for ns in nsset:
        parentNS=getParent(ns)
        if parentNS[-1]!=".":
            parentNS=parentNS+"."
        if parentNS in cyclic:
            ret = True
        '''
        else:
            #eval substrings
            for k in cyclic:
                for j in nsset:
                    if k in j:
                        ret =True
        '''

    return ret


def parseZone(cyclic):
    bugged=dict()
    extension=sys.argv[3]
    if extension[-1]!=".":
        extension=extension+"."
    if extension[0]!=".":
        extension= "." +extension

    counter=0
    with open(sys.argv[2], 'r') as f:
        nsset=set()
        foundZone = False

        previousDomain = ''
        for line in f:
            line=line.lower()
            sp = line.split('\t')
            counter=counter+1

            if float(counter)%1000000==0:
                m=counter/1000000
                print('reading line '+ str(m) + ' million  of zone file')

            if '\tns\t' in line:
                tempDomain=sp[0]

                if previousDomain=='':
                    previousDomain=tempDomain
                    nsset.add(sp[-1].rstrip())

                elif previousDomain==tempDomain:
                    nsset.add(sp[-1].rstrip())


                elif previousDomain!=tempDomain:

                    result = evalNSSet(cyclic, nsset)
                    if result == True:
                        bugged[previousDomain] = list(nsset)

                    #reset
                    previousDomain=tempDomain
                    nsset=set()
                    nsset.add(sp[-1].rstrip())


    return bugged




def getCyclic(infile):
    ret =set()
    deps=dict()
    try:
        with open(infile, 'r') as f:
            deps = json.load(f)
    except:
        #if it's multiple dics in one json file
        with open (infile,'r') as f:
            for line in f:
                tempD=json.loads(line)
                for k,v in tempD.items():
                    deps[k]=v

    for key, value in deps.items():
        ret.add(key)
        ret.add(value)
    return ret

def main():
    print("step 1: read cyclic domains")
    cyclic=getCyclic(sys.argv[1])
    print("step 2: read zone file and find them")
    troubledDomains=parseZone(cyclic)
    print("step 3: writing it to json")

    with open(sys.argv[4], 'w') as fp:
        json.dump(troubledDomains,fp)
    print("\nThere are " + str(len(troubledDomains))+ " domains that have at least one cyclic dependent NS")
    print('done')
    '''
    aus=open(sys.argv[2], 'w')
    for k in nsset:
        aus.write(k.strip()+"\n")
    aus.close()

    '''

if len(sys.argv) != 5:

    print("ERROR: usage\npython zoneMatcher.py <CyclicDepFiles>   <zoneFile> zoneEnd <outFile>")

else:

    main()

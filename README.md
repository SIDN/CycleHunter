## CycleHunter

* This code detects [cyclic dependecies](http://conferences.sigcomm.org/sigcomm/2004/papers/p595-pappas111.pdf) in DNS zones
* It has a series of steps
* It takes as input DNS zone files
* First developed by [@gmmoura](https://github.com/gmmoura) and [@seb-at-nzrs](https://github.com//seb-at-nzrs), from [SIDN Labs](https://sidnlabs.nl) and [InternetNZ](http://internet.net.nz/).



### TL;DR

To analyze a full zone, you can use `CycleHunter.py` as below

```
python CycleHunter.py --zonefile <ZONEFILE> --origin <ORIGIN> --save-file <FILE_TO_SAVE_AFFECTED_DOMAINS> --workers <WORKERS>
```

Where
- `ZONEFILE` is the file with the zone you want to analyze
- `ORIGIN` is the zone represented by the `ZONEFILE`, for example, *.COM* or *.NL*
- `FILE_TO_SAVE_AFFECTED_DOMAINS` is a JSON file that in the end will have the list of domains affected by full cycles
- `WORKERS` is the number of parallel works that will use to send queries
### If you like to do this by hand

`CycleHunter.py` wraps all the steps below, but if you still want to run them by hand, the process is:

1. Extract all NS records from the zone file

  * `python largeZoneParser.py $zonefile $TLD $output1`
    * e.g: `python3 largeZoneParser.py  /var/cache/bind/com.zone .com com-nses.csv`

2. Query these NSes, and output those that timeout into `$output2`

  * `python CyclicDetector.py $output1 $output2`

3. Scrutinize each timed out NS, either parent or child, and see if which ones are really cyclic dependent into `output3`

  * `python  findCyclicDep.py $output2 $output3`

  * Note: $output3 is a json file with 3 categories of dependency. `fullDep` is the one very bad, but the other two can quickily become `fullDep`

4. Get only the fully cyclic dependent ones from `output3`

  * `python fullDepParser.py $output3 $output4`

`output4` has the zones that are cyclic dependent. These are likely parent zones of NSes

5. Determine how many zones are affected by cyclic dependency

    * `python zoneMacher.py $ouput4 $zoneFile $TLD $output5`
    * **Alternative version for com** : `zoneMatcher-com.py`

`output5` has all domains affected by cyclic dependency

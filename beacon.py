#!/usr/bin/env python
# WARNING: Only target this script against computer systems you own, or have permission to probe.

import requests
import argparse
import sys
from time import gmtime, strftime, sleep

def perform_beacon(target_uri, beacon_interval, verify_cert): 
    while True: 
	try:
    	    r = requests.get(target_uri, verify=verify_cert, timeout=10)
	    if len(r.content) > 0:
	        print str(strftime("%Y-%m-%d %H:%M:%S", gmtime()))+": "+str(r.url)
	    else:
	        print "Error: Response content 0 bytes!"
	    sleep(beacon_interval)
        except KeyboardInterrupt:
	    sys.exit()
	except:
	    print "Error: Could not perform GET request!"
	    sleep(beacon_interval)            

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument('-u','--uri',required=True,help='Full URI you wish to target (including protocol)')
    parser.add_argument('-t','--interval',required=False,help='Beacon sleep interval in seconds (default 60)')
    parser.add_argument('-v','--verifycert',required=False,help='Use -v flag to overide certificate validation (useful if you self-signed)', action='store_false')
    args = vars(parser.parse_args())
    target_uri = args['uri']
    if args["interval"]:
        beacon_interval = int(args['interval'])
    else:
	beacon_interval = 60
    verify_cert = args["verifycert"]    
    print """
************************************************
Running beacon.py!
************************************************
* Target URI: %s
* Beacon Interval (seconds): %s
* Verify TLS Certificates: %s
************************************************"""%(target_uri,beacon_interval,verify_cert)
    
    # Good idea to warn against DoS-ing the target site...
    if beacon_interval < 5:
	print """Warning: Using short beacon interval; don't go DoS-ing!
************************************************
Will resume in 10 seconds..."""
	sleep(10)
    perform_beacon(target_uri, beacon_interval, verify_cert)

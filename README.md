# scripts

## beacon.py
Simulates HTTP/S malware beacons; useful for testing new detection methods based on statistical analysis.
(https://killthemalware.com/blog/2016/09/05/beaconpy-simulate-malware-beacons)



## findPtH.py
Identifies evidence of pass-the-hash logins within Windows Security.evtx logs.
Windows only (due to reliance on LogParser.exe), lines 14 + 20 should be edited accordingly. 
(https://killthemalware.com/blog/2017/1/31/detecting-pass-the-hash-without-a-siem)

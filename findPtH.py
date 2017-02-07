#!/usr/bin/env python
# Use at your own risk
# Tested on Windows 7/10 x64

import csv
import os
import time
import uuid
import subprocess
import argparse
import binascii

# Path to LogParser.exe (available here: https://technet.microsoft.com/en-gb/scriptcenter/dd919274.aspx)
logparserexe = "C:\\temp\\LogParser.exe"

# Event ID's of interest (LogParser syntax)
eventids = "EventID=4624 OR EventID=4625"

# List of Windows Domains to ignore (we're interested in LOCAL accounts)
ignore = ['DOMAIN1', 'DOMAIN2', 'WORKGROUP']

# Headers for the CSV results file
csvheaders = ['EventLog', 'RecordNumber', 'TimeGenerated', 'TimeWritten', 'EventID', 'EventType', 'EventTypeName',
              'EventCategory', 'EventCategoryName', 'SourceName', 'Strings', 'ComputerName', 'SID', 'Message',
              'SID', 'AccountName', 'Domain', 'LogonID', 'LogonType', 'LogonProcess', 'AuthenticationPackage',
              'WorkstationName', 'LogonGUID', '', 'PackageName', 'KeyLength', 'ProcessID', 'ProcessName',
              'SourceNetworkAddress', 'SourcePort', 'Computer']


def filehandler():
    targetfiles = []
    for path, dirs, files in os.walk(startdir, topdown=False):
        for name in files:
            target = os.path.join(path, name)
            # See if the file is an EVTX (ElfFile)
            if binascii.hexlify(open(target, 'rb').read(8)) == "456c6646696c6500":
                targetfiles.append(target)
    return (targetfiles)


def logparser():
    print "\nParsing " + str(len(targetfiles)) + " EVTX files..."
    results.writerow(csvheaders)
    parsecount = 0
    for evtx in targetfiles:
        parsecount += 1
        log_parser_parse_percent_pre = int(parsecount) * 100
        log_parser_parse_percent = int(log_parser_parse_percent_pre) / int(len(targetfiles))
        print "Running LogParser.exe against: " + str(evtx) + ": " + str(parsecount) + "/" + str(
            len(targetfiles)) + " (" + str(log_parser_parse_percent) + "%)..."
        # Use a UID to prevent any file overwrites
        outputcsv = str(tempdir) + str(uuid.uuid4()) + ".csv"
        command = str(logparserexe) + " -i:EVT -o:CSV \"SELECT * INTO \'" + str(outputcsv) + "\' FROM \'" + str(
            evtx) + "\' WHERE " + str(eventids)
        subprocess.call(command)
        if os.path.isfile(outputcsv):
            replace_pipe(outputcsv)
            detect_passthehash(outputcsv)
            # Add more calls to detect_ functions here
            os.remove(outputcsv)
    try:
        os.rmdir(tempdir)
    except OSError:
        print "Could not remove temp dir: " + str(tempdir)
    print "Results saved to: " + str(args["outputfile"]) + "\n"
    if hits:
        print "Complete! Evidence of pass-the-hash identified! See results CSV!"
    else:
        print "Complete! No evidence of pass-the-hash identified!"


def detect_passthehash(outputcsv):
    print "Looking for pass-the-hash: " + str(outputcsv)
    csvFile = open(outputcsv)
    csvReader = csv.reader(csvFile, delimiter=',')
    try:
        for event in csvReader:
            if event[4] == "4624" or event[4] == "4625":
                if event[18] == "3":
                    if event[19] == "NtLmSsp ":
                        if event[25] == "0":
                            # If source host language is non-English, modify / add the relevant string here
                            if event[15] != "ANONYMOUS LOGON":
                                if event[16] not in ignore:
                                    results.writerow(event)
                                    global hits
                                    hits = True
    except:
        print "Failed to process: " + outputcsv


# Template function for additional query
def detect_template(outputcsv):
    print "Looking for TEMPLATE: " + str(outputcsv)
    csvFile = open(outputcsv)
    csvReader = csv.reader(csvFile, delimiter=',')
    try:
        for event in csvReader:
            if event[4] == "1234":
                results.writerow(event)
                hits = True
    except:
        print "Failed to process: " + outputcsv


def replace_pipe(outputcsv):
    # LogParser.exe outputs both ',' and '|' delimiters; we standardise this to ','
    # This needs to be memory efficient, otherwise you can end up with HUGE strings.
    pipeIn = open(str(outputcsv), 'r')
    pipeOut = open(str(outputcsv) + "_", 'w')
    for line in pipeIn:
        newline = line.replace('|', ',')
        pipeOut.write(newline)
    pipeIn.close()
    pipeOut.close()
    os.remove(str(outputcsv))
    try:
        os.rename(str(outputcsv) + "_", str(outputcsv))
    except:
        # File deletion can sometimes take a while, which causes the os.rename to fail...
        time.sleep(3)
        os.rename(str(outputcsv) + "_", str(outputcsv))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="Find evidence of pass-the-hash within Security.evtx logs!")
    parser.add_argument('-i', '--inputpath', required=True,
                        help='Specify the input path (dir containing EVTX files), enclosed in double quotes')
    parser.add_argument('-o', '--outputfile', required=True,
                        help='Specify the output file (CSV results), enclosed in double quotes')
    args = vars(parser.parse_args())
    # Check LogParser.exe exists
    if not os.path.isfile(logparserexe):
        print str(logparserexe) + " could not be found!"
        raise SystemExit
    startdir = args["inputpath"]
    tempdir = str(startdir) + "\\temp\\"
    os.mkdir(tempdir)
    results = csv.writer(open(str(args["outputfile"]), "ab"), delimiter=',')
    print """
************************************************
Running findPtH.py!
************************************************
* Input dir: %s
* Temp dir: %s
* Saving results to: %s
************************************************"""%(startdir,tempdir,str(args["outputfile"]))

    hits = False
    targetfiles = filehandler()
    logparser()

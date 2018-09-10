#!/usr/bin/python
# -*- coding: ascii -*-

import broker
import broker.bro
import json, sys

#Setup Bro comms
endpoint = broker.Endpoint()
endpoint.peer("localhost",9999)

for line in sys.stdin:
#with ope('1.txt') as f:
  #for line in f:
    myJson = json.loads(line)
    event = myJson["event_data"]
    computerName =  myJson["computer_name"]
    proto = myJson["event_data"]["Protocol"]
    dstip = event["DestinationIp"]
    dstprt = event["DestinationPort"]
    srcip = event["SourceIp"]
    srcprt = event["SourcePort"]
    procImage = event["Image"]
    procId = event["ProcessId"]
    user = event["User"]
    myTime = event["UtcTime"]
    
    event = broker.bro.Event("sysmonProcNetConn",(str(computerName),str(proto),str(srcip),str(srcprt),str(dstip),str(dstprt),str(procId),str(procImage)))
    endpoint.publish("/sysmon", event)



#"event_data": {
#   "DestinationHostname": "pychen-wsl2.internal.salesforce.com",
#   "DestinationIp": "10.85.180.22",
#   "DestinationIsIpv6": "false",
#   "DestinationPort": "7680",
#   "DestinationPortName": "ms-do",
#   "Image": "C:\\Windows\\System32\\svchost.exe",
#   "Initiated": "true",
#   "ProcessGuid": "{15495CAA-22F1-5B93-0000-0010CEA30D00}",
#   "ProcessId": "5408",
#   "Protocol": "tcp",
#   "SourceHostname": "DESKTOP-DR25I43.internal.salesforce.com",
#   "SourceIp": "10.0.2.15",
#   "SourceIsIpv6": "false",
#   "SourcePort": "52846",
#   "User": "NT AUTHORITY\\NETWORK SERVICE",
#   "UtcTime": "2018-09-10 18:16:14.880"
# },

#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

import json
import subprocess
from tabulate import tabulate
import re

def check_output_json(cmd):
    return json.loads(subprocess.check_output(cmd, shell=True).decode("utf-8"))

def get_xdp_prog(interface):
    cmd_iplink = 'ip -j link show %s' % interface
    iplink = check_output_json(cmd_iplink)
    return iplink[0]['xdp']['prog']['id']

def get_map_ids():
    #prog_id = get_xdp_prog(interface)
    #cmd_progshow = 'bpftool prog show id %d -p' % prog_id
    #prog_info = check_output_json(cmd_progshow)

    maps = check_output_json('bpftool map -p')

    used_maps = ['ingress_map', 'egress_map']
    map_ids = []

    for m in maps:
        if m.get('name') in used_maps:
            map_ids.append({'id': m['id'], 'name': m['name']})
    return map_ids

def get_map_entries(map_id):
    cmd_mapshow = 'bpftool map show id %s -p' % map_id
    map_info = check_output_json(cmd_mapshow)
    return map_info['max_entries']

def get_map_dev(map_id):
    cmd_mapshow = 'bpftool map show id %s -p' % map_id
    map_info = check_output_json(cmd_mapshow)

    if "dev" in map_info:
        return "Offload"
    else:
        return "Driver"

def dump_map(map_id):
    cmd_map = 'bpftool map dump id %s -p' % map_id
    return check_output_json(cmd_map)

def hex_list_to_int(hex_list):
    hex_str = ''.join([byte.replace('0x', '') for byte in hex_list])
    return (int.from_bytes(bytes.fromhex(hex_str), byteorder='little'))

names = ["middleware", "database"]

# capture service proxies to simplify distributed system architecture
services = {}
serviceOutput = subprocess.check_output("kubectl get services", shell=True).decode("utf-8").split("\n")[1:]

ipRegex = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
portRegex = re.compile(r'[0-9]+[^ ]*/TCP')

for serviceEntry in serviceOutput:
    if(serviceEntry and serviceEntry.split(" ")[0] != "kubernetes"):
        serviceIP = re.findall(ipRegex, serviceEntry)
        servicePort = re.findall(portRegex, serviceEntry)
        services[serviceEntry.split(" ")[0]] = serviceIP[0]

# map service IPs to pod IPs and vice-versa for posterior mapping (service cluster address bypassing)
serviceEndpointsMap = {}
ipToService = {}

addressRegex = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+')

for serviceKey in services:

    preProcessedEndpoints = subprocess.check_output("kubectl get endpoints "+serviceKey, shell=True).decode("utf-8").split("\n")[1:]

    for preProcessedEndpoint in preProcessedEndpoints:
        processedEndpoint = re.findall(addressRegex, preProcessedEndpoint)
        if(processedEndpoint):
            endpointAttributes = processedEndpoint[0].split(":")
            serviceEndpointsMap[services[serviceKey]] = endpointAttributes[0]
            ipToService[processedEndpoint[0].split(":")[0]] = serviceKey
        
#print(ipToService)
#print(serviceEndpointsMap)
#exit()


# format entries from bpf map
formatted_maps = []
for bpf_map in get_map_ids():
    formatted_entries = []
    mapIdentifier = ""
    for entry in dump_map(bpf_map['id']):
        if(entry['formatted']['key'] == 'map_identifier'):
            mapIdentifier = entry['formatted']['value']
        else:
            formatted_entries.append(entry['formatted'])
    formatted_maps.append({'name': mapIdentifier + "-" + bpf_map['name'], 'entries': formatted_entries})

timestamps_hashmaps = {}

# setup service cluster addresses bypass
for map in formatted_maps:
    timestamps_hash = {}
    for entry in map['entries']:

        addressAndTimetag = entry["key"].split(";")
        ipsAndPorts = addressAndTimetag[0].split(",")
        originIp = ipsAndPorts[0]
        originPort = ipsAndPorts[2]
        destinyIp = ipsAndPorts[1]
        destinyPort = ipsAndPorts[3]


        bypassOriginService = serviceEndpointsMap.get(originIp)

        if(bypassOriginService):
            originIp = bypassOriginService.split(":")[0]

        bypassDestinyService = serviceEndpointsMap.get(destinyIp)
        if(bypassDestinyService):
            destinyIp = bypassDestinyService.split(":")[0]

        timestamps_hash[";".join([",".join([originIp,destinyIp,originPort,destinyPort]), addressAndTimetag[1]])] = entry['value']
    timestamps_hashmaps[map['name']] = timestamps_hash

#print(timestamps_hashmaps)
#exit()

delaysMap = {}

#print(timestamps_hashmaps)

# fix inverted entries
for mapKey in timestamps_hashmaps:

    trafficDirection = ""
    currService = mapKey.split("-")[0]
    if("ingress" in mapKey):
        trafficDirection = "ingress"
    else:
        trafficDirection = "egress"

    for entryKey in list(timestamps_hashmaps[mapKey].keys()): 

        keyAddressAndTimetag = entryKey.split(";")
        split_key = keyAddressAndTimetag[0].split(",")
        inverted_entry = split_key[1] + "," + split_key[0] + "," + split_key[3] + "," + split_key[2] + ";" + keyAddressAndTimetag[1]

        if(trafficDirection == "ingress"):
            if(ipToService.get(split_key[0]) == currService):
                timestamps_hashmaps[mapKey][inverted_entry] = timestamps_hashmaps[mapKey][entryKey]
                del timestamps_hashmaps[mapKey][entryKey]
        if(trafficDirection == "egress"):
            if(ipToService.get(split_key[1]) == currService):
                timestamps_hashmaps[mapKey][inverted_entry] = timestamps_hashmaps[mapKey][entryKey]
                del timestamps_hashmaps[mapKey][entryKey]


# request timeframe analysis
for mapKey in timestamps_hashmaps:    

    trafficDirection = ""
    currService = mapKey.split("-")[0]

    if("ingress" in mapKey):
        #mirrorMap = timestamps_hashmaps[currService+"-egress_map"]
        trafficDirection = "ingress"
    else:
        #mirrorMap = timestamps_hashmaps[currService+"-ingress_map"]
        trafficDirection = "egress"

    if(trafficDirection == "ingress"):
        continue

    

    for entryKey in timestamps_hashmaps[mapKey].keys():

        if(entryKey[-1] == "l" or not (ipToService.get(entryKey.split(",")[0]) == currService)):
            continue

        keyAddressAndTimetag = entryKey.split(";")
        split_key = keyAddressAndTimetag[0].split(",")

        contactedService = ipToService.get(split_key[1])

        if(not contactedService):
            continue
            
        inverted_entry = split_key[1] + "," + split_key[0] + "," + split_key[3] + "," + split_key[2] + ";" + keyAddressAndTimetag[1]

        currentKey = entryKey
        contactedKey = inverted_entry

        currServiceEgressMap = timestamps_hashmaps[currService+"-egress_map"]
        contactedServiceEgressMap = timestamps_hashmaps[contactedService+"-egress_map"]

        #print(timestamps_hashmaps)

        currServiceIngressMap = timestamps_hashmaps[currService+"-ingress_map"]
        contactedServiceIngressMap = timestamps_hashmaps[contactedService+"-ingress_map"]

        currServiceInitialTimestamp = currServiceEgressMap.get(entryKey)

        #print(timestamps_hashmaps)

        #print(currService)
        #print(currentKey)
        #print(contactedKey)
        #print(currServiceEgressMap)
        #print(contactedServiceEgressMap)

        
        oppositeInitalTimestamp = contactedServiceEgressMap.get(contactedKey)
        oppositeInitialTimestampKey = contactedKey

        if(oppositeInitalTimestamp == None):
            continue
        if(contactedServiceEgressMap.get(contactedKey.replace("f", "l")) == None):
            continue

        #print(oppositeInitalTimestamp)
        #print(currServiceInitialTimestamp)

    

        if(int(oppositeInitalTimestamp) - int(currServiceInitialTimestamp) > 0):

            #print(currServiceEgressMap.get(entryKey))
            #print(contactedServiceEgressMap.get(contactedKey))
            #print(currServiceIngressMap.get(contactedKey))
            #print(contactedServiceIngressMap.get(entryKey))

            #print(currServiceIngressMap.get(contactedKey.replace("f", "l")))
            #print(contactedServiceIngressMap.get(entryKey.replace("f", "l")))
            #print(currServiceEgressMap.get(entryKey.replace("f", "l")))
            #print(contactedServiceEgressMap.get(contactedKey.replace("f", "l")))
            #exit()
            #weird
            #print(contactedServiceIngressMap)
            delaysMap[contactedService+"_request_to_"+currService+"-"+contactedKey.replace("f", "").replace("l", "")] = [(int(contactedServiceEgressMap.get(contactedKey.replace("f", "l"))) - int(contactedServiceIngressMap.get(entryKey))) / 1000000000, int(contactedServiceIngressMap.get(entryKey))]
            
            #print(currServiceEgressMap)
            #print(currServiceIngressMap)
            #print(entryKey)
            #print()
            #print(int(currServiceEgressMap.get(entryKey).replace("f", "l")))#10.244.0.81,10.244.0.82,14357,13472;l': '33355000207347
            #print(int(currServiceEgressMap.get('10.244.0.81,10.244.0.82,14357,13472;l')))
            #print(int(currServiceIngressMap.get(contactedKey)))
            delaysMap[currService+"_time_to_process_response_to_"+contactedService+"-"+entryKey.replace("f", "").replace("l", "")] = [(int(currServiceIngressMap.get(contactedKey.replace("f", "l"))) - int(currServiceEgressMap.get(entryKey))) / 1000000000, int(contactedServiceIngressMap.get(entryKey))]
        
        #print(delaysMap)
        #exit()

        #if(mirrorMap.get(inverted_entry)):
         #   delta_time = int(timestamps_hashmaps[mapKey][entryKey]) - int(mirrorMap[inverted_entry])
          #  delta_time_seconds = delta_time / 1000000000
           # if(delta_time > 0):
            #    if(trafficDirection == "ingress"):
             #       delaysMap[mapKey.split("-")[0]+"_time_to_receive_response-"+inverted_entry] = delta_time_seconds
              #  else:
               #     delaysMap[mapKey.split("-")[0]+"_time_to_deliver_response-"+inverted_entry] = delta_time_seconds
            #else:
            #    delaysMap[mapKey+"-"minikube mount $HOME:/host+entryKey] = delta_time_seconds * -1
        #else:contactedServiceEgressMap.get(oppositeInitialTimestampKey.replace("f", "l"))
         #   if(trafficDirection == "ingress"):
          #      delaysMap[mapKey.split("-")[0]+"_no_returned_response-"+inverted_entry] = "DELAYED RESPONSE"
           # else:
            #    delaysMap[mapKey.split("-")[0]+"_no_received_response-"+inverted_entry] = "DELAYED RESPONSE"

entries = []

#print(delaysMap)

for entry in delaysMap:
    addressAndTimetag = entry.split(";")
    code = addressAndTimetag[0].split("-")[0]
    ipsAndPorts = addressAndTimetag[0].split("-")[1].split(",")
    originIp = ipsAndPorts[0]
    originPort = ipsAndPorts[2]
    destinyIp = ipsAndPorts[1]
    destinyPort = ipsAndPorts[3]
    entries.append([code, originIp, originPort, destinyIp, destinyPort, delaysMap[entry][0], delaysMap[entry][1]])

metricsOutput = open("serviceTimes.txt", "w")  # append mode

metricsOutput.write(tabulate(entries, headers=['Code', 'OriginIP', 'OriginPort', 'DestinyIP', 'DestinyPort', 'Timeframe', 'Instant']))
         
        
         
             




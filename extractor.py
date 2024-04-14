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

# capture service proxies to simplify distributed system architecture
services = {}
serviceOutput = subprocess.check_output("kubectl get services", shell=True).decode("utf-8").split("\n")[1:]

ipRegex = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
portRegex = re.compile(r'[0-9]+[^ ]*/TCP')

for serviceEntry in serviceOutput:
    if(serviceEntry and serviceEntry.split(" ")[0] != "kubernetes"):
        serviceIP = re.findall(ipRegex, serviceEntry)
        servicePort = re.findall(portRegex, serviceEntry)
        services[serviceEntry.split(" ")[0]] = serviceIP[0]+":204"+servicePort[0].replace(":", "/").split("/")[0]

#print(services)
#exit()

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
            serviceEndpointsMap[services[serviceKey]] = endpointAttributes[0]+":204"+endpointAttributes[1]
            ipToService[processedEndpoint[0].split(":")[0]] = serviceKey
        
#print(ipToService)
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

        bypassOriginService = serviceEndpointsMap.get(":".join([originIp, originPort]))
        if(bypassOriginService):
            originIp = bypassOriginService.split(":")[0]
            originPort = bypassOriginService.split(":")[1]

        bypassDestinyService = serviceEndpointsMap.get(":".join([destinyIp, destinyPort]))
        if(bypassDestinyService):
            destinyIp = bypassDestinyService.split(":")[0]
            destinyPort = bypassDestinyService.split(":")[1]

        timestamps_hash[";".join([",".join([originIp,destinyIp,originPort,destinyPort]), addressAndTimetag[1]])] = entry['value']
    timestamps_hashmaps[map['name']] = timestamps_hash

#print(timestamps_hashmaps)
#exit()

delaysMap = {}

#print(timestamps_hashmaps)

# request timeframe analysis
for mapKey in timestamps_hashmaps:    

    trafficDirection = ""

    if("ingress" in mapKey):
        mirrorMap = timestamps_hashmaps[mapKey.split("-")[0]+"-egress_map"]
        trafficDirection = "ingress"
    else:
        mirrorMap = timestamps_hashmaps[mapKey.split("-")[0]+"-ingress_map"]
        trafficDirection = "egress"

    for entryKey in timestamps_hashmaps[mapKey]:

        if(entryKey[-1] =="l"):
            continue

        keyAddressAndTimetag = entryKey.split(";")
        split_key = keyAddressAndTimetag[0].split(",")

        if(trafficDirection == "ingress"):
            print(ipToService)
            originService = ipToService[split_key[0]]
            print(entryKey)
            print(originService)
            exit()

        inverted_entry = split_key[1] + "," + split_key[0] + "," + split_key[3] + "," + split_key[2] + ";" + keyAddressAndTimetag[1]

        if(mirrorMap.get(inverted_entry)):
            delta_time = int(timestamps_hashmaps[mapKey][entryKey]) - int(mirrorMap[inverted_entry])
            delta_time_seconds = delta_time / 1000000000
            if(delta_time > 0):
                if(trafficDirection == "ingress"):
                    delaysMap[mapKey.split("-")[0]+"_time_to_receive_response-"+inverted_entry] = delta_time_seconds
                else:
                    delaysMap[mapKey.split("-")[0]+"_time_to_deliver_response-"+inverted_entry] = delta_time_seconds
            #else:
            #    delaysMap[mapKey+"-"minikube mount $HOME:/host+entryKey] = delta_time_seconds * -1
        else:
            if(trafficDirection == "ingress"):
                delaysMap[mapKey.split("-")[0]+"_no_returned_response-"+inverted_entry] = "DELAYED RESPONSE"
            else:
                delaysMap[mapKey.split("-")[0]+"_no_received_response-"+inverted_entry] = "DELAYED RESPONSE"

entries = []

for entry in delaysMap:
    addressAndTimetag = entry.split(";")
    code = addressAndTimetag[0].split("-")[0]
    ipsAndPorts = addressAndTimetag[0].split("-")[1].split(",")
    originIp = ipsAndPorts[0]
    originPort = ipsAndPorts[2]
    destinyIp = ipsAndPorts[1]
    destinyPort = ipsAndPorts[3]
    entries.append([code, originIp, originPort, destinyIp, destinyPort, delaysMap[entry]])


print(tabulate(entries, headers=['Code', 'Origin IP', 'Origin Port', 'Destiny IP', 'Destiny Port', 'Timeframe']))
         
        
         
             




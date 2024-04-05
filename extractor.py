#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

import json
import subprocess
import struct
import sys

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
            if m['name'] in used_maps:
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

formatted_maps = []
for bpf_map in get_map_ids():
    formatted_entries = []
    for entry in dump_map(bpf_map['id']):
        formatted_entries.append(entry['formatted'])
    formatted_maps.append({'name': bpf_map['name'], 'entries': formatted_entries})

timestamps_hash = {}

for map in formatted_maps:
    for entry in map['entries']:
        #print(entry)
        timestamps_hash[entry['key']] = entry['value']

delays_map = {}

#print(timestamps_hash)


for key in timestamps_hash:
    #print(key, int(timestamps_hash[key]))
    split_key = key.split(",")
    inverted_entry = split_key[1] + "," + split_key[0] + "," + split_key[3] + "," + split_key[2]
    if(timestamps_hash.get(inverted_entry)):
        delta_time = int(timestamps_hash[key]) - int(timestamps_hash[inverted_entry])
        delta_time_seconds = delta_time / 1000000000
        if(delta_time > 0):
            delays_map[inverted_entry] = delta_time_seconds
        else:
            delays_map[key] = delta_time_seconds * -1
    else:
        delays_map[key] = "DELAYED RESPONSE"

print(len(timestamps_hash))

for entry in delays_map:
    print(entry, delays_map[entry])
         
        
         
             




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

for entry in formatted_maps[0]['entries']:
    print(entry)
    timestamps_hash[entry['key']] = entry['value']

delays_map = {}

for entryB in formatted_maps[1]['entries']:
    split_entry = entryB['key'].split(",")
    inverted_entry = split_entry[1] + "," + split_entry[0] + "," + split_entry[3] + "," + split_entry[2]
    if(timestamps_hash.get(inverted_entry)):
        delays_map[inverted_entry] = int(entryB['value']) - int(timestamps_hash[inverted_entry])

for entry in delays_map:
    print(delays_map[entry])
         
        
         
             




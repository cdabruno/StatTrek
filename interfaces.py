import json
import subprocess
import struct
import sys

cmd = "docker ps | grep -i frontend"
output1 = subprocess.check_output(cmd, shell=True).decode("utf-8")
containerID = output1.split("\n")[1].split(" ")[0]

cmd = "docker inspect " + containerID + "| grep -i sandboxkey"
output2 = subprocess.check_output(cmd, shell=True).decode("utf-8")
output2Parse = output2.split("/")[-1].split("\"")[0]

cmd = "sudo nsenter --net=/var/run/docker/netns/" + output2Parse + " ethtool -S eth0 | grep -i peer"
output3 = subprocess.check_output(cmd, shell=True).decode("utf-8")
output3Parse = output3.split(": ")[1]
print(output3Parse)

cmd = "docker ps | grep -i backend"
output1 = subprocess.check_output(cmd, shell=True).decode("utf-8")
containerID = output1.split("\n")[1].split(" ")[0]

cmd = "docker inspect " + containerID + "| grep -i sandboxkey"
output2 = subprocess.check_output(cmd, shell=True).decode("utf-8")
output2Parse = output2.split("/")[-1].split("\"")[0]

cmd = "sudo nsenter --net=/var/run/docker/netns/" + output2Parse + " ethtool -S eth0 | grep -i peer"
output3 = subprocess.check_output(cmd, shell=True).decode("utf-8")
output3Parse = output3.split(": ")[1]
print(output3Parse)
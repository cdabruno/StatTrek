import subprocess
import time
import json

metricsOutput = open("nodeMetrics.txt", "a")  # append mode

#minikubeConsumption = subprocess.check_output("minikube ssh && top", shell=True).decode("utf-8")
#exit()

while(True):
    # data capture
    timestamp = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    #nodeConsumption = subprocess.check_output("kubectl top node", shell=True).decode("utf-8")
    podConsumption = subprocess.check_output("kubectl top pods", shell=True).decode("utf-8")

    # data persistence

    metricsOutput.write("["+str(timestamp)+"]\n")

    #metricsOutput.write("NodeConsumption\n")
    #metricsOutput.write(str(nodeConsumption)+"\n")

    metricsOutput.write(str(podConsumption) + "\n")
    time.sleep(1)

metricsOutput.close()
import matplotlib.pyplot as plt
import pandas as pd
import re
from io import StringIO

# Input data
f = open("nodeMetrics.txt", "r")
data = f.read()

# Split data into snapshots
snapshots = re.split(r'\n\n', data)
instants = re.findall(r'\[(\d+)\]', data)


# Initialize lists to store metrics
db_cpu = []
db_memory = []
middleware_cpu = []
middleware_memory = []


# Parse each snapshot
for snapshot in snapshots:
    # Read the snapshot into a DataFrame
    if(snapshot == ''):
        continue
    snapshot_data = pd.read_csv(StringIO(snapshot.split("]\n")[1]), delim_whitespace=True)

    
    # Extract database metrics
    db_row = snapshot_data[snapshot_data['NAME'].str.contains('database')]
    db_cpu_str = db_row['CPU(cores)'].values[0]
    db_mem_str = db_row['MEMORY(bytes)'].values[0]
    
    db_cpu_value = float(db_cpu_str[:-1]) / 1000 if 'm' in db_cpu_str else float(db_cpu_str)
    db_mem_value = float(db_mem_str[:-2]) if 'Mi' in db_mem_str else float(db_mem_str) * 1024
    
    db_cpu.append(db_cpu_value)
    db_memory.append(db_mem_value)
    
    # Extract middleware metrics
    mw_row = snapshot_data[snapshot_data['NAME'].str.contains('middleware')]
    mw_cpu_str = mw_row['CPU(cores)'].values[0]
    mw_mem_str = mw_row['MEMORY(bytes)'].values[0]
    
    mw_cpu_value = float(mw_cpu_str[:-1]) / 1000 if 'm' in mw_cpu_str else float(mw_cpu_str)
    mw_mem_value = float(mw_mem_str[:-2]) if 'Mi' in mw_mem_str else float(mw_mem_str) * 1024
    
    middleware_cpu.append(mw_cpu_value)
    middleware_memory.append(mw_mem_value)

# Convert instants to numeric values for plotting
instants = [int(instant) for instant in instants]

# Create the plot
plt.figure(figsize=(14, 10))

# Plot Database CPU usage
plt.subplot(2, 1, 1)
plt.plot(instants, db_cpu, marker='o', linestyle='-', color='b', label='Database CPU (cores)')
plt.plot(instants, middleware_cpu, marker='o', linestyle='-', color='g', label='Middleware CPU (cores)')
plt.xlabel('Instant')
plt.ylabel('CPU Consumption (cores)')
plt.title('CPU Consumption Over Time')
plt.grid(True)
plt.legend()

# Plot Database Memory usage
plt.subplot(2, 1, 2)
plt.plot(instants, db_memory, marker='o', linestyle='-', color='r', label='Database Memory (MiB)')
plt.plot(instants, middleware_memory, marker='o', linestyle='-', color='m', label='Middleware Memory (MiB)')
plt.xlabel('Instant')
plt.ylabel('Memory Consumption (MiB)')
plt.title('Memory Consumption Over Time')
plt.grid(True)
plt.legend()

# Adjust layout and show the plot
plt.tight_layout()
plt.show()

import matplotlib.pyplot as plt
import pandas as pd
from io import StringIO

# Input data
f = open("serviceTimes.txt", "r")
data = f.read()

# Create a DataFrame
df = pd.read_csv(StringIO(data), delim_whitespace=True)

df = df.sort_values("Instant")

# Filter out the request data
requests = df[df['Code'].str.contains('middleware_request_to_database')]

# Convert instants to numeric values for plotting
requests['Instant'] = pd.to_numeric(requests['Instant'])

print(requests['Instant'])

# Convert timeframes to numeric values for plotting
requests['Timeframe'] = pd.to_numeric(requests['Timeframe'])

# Create the plot
plt.plot(requests['Instant'], requests['Timeframe'])

# Labeling the plot
plt.xlabel('Instant')
plt.ylabel('Timeframe (s)')
plt.title('Request Timeframes vs. Instants')
plt.grid(True)

# Show the plot
plt.show()

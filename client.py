import requests

for i in range(0, 100000):
    x = requests.get('http://192.168.49.2:32212/')

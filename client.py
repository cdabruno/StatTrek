import requests

for i in (0, 100):
    x = requests.get('http://192.168.49.2:30517/')
    print(x.text)

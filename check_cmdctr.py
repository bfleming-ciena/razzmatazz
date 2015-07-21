#!/usr/bin/python
import requests
import sys

# Make call to REST api to run CCFG Admin Console UI test.
url = "http://172.23.43.29:7070/api/v1/cmdctr/ui/ccfg/status"
response = requests.get(url)
data = response.json()

print str(data['message'])
sys.exit(data['nagios_code'])

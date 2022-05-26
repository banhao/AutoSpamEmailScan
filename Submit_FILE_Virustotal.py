#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: hao.ban@ehealthsask.ca//banhao@gmail.com
# Version:
# Issue Date: May 26, 2022
# Release Note: 


import requests, sys, time

for line in open("./init.conf",'r'):
    if line.startswith('VIRUSTOTAL_API_KEY'):
        VIRUSTOTAL_API_KEY = line.split("=")[1].strip()
file = sys.argv[1]
url = "https://www.virustotal.com/api/v3/files"
files={ "file": open(file,'rb') }
headers = {"x-apikey": VIRUSTOTAL_API_KEY}
response = requests.request("POST", url, headers=headers, files=files)
time.sleep(15)
ID = response.json()['data']['id']
url = "https://www.virustotal.com/api/v3/analyses/"+ID
headers = { "Accept": "application/json","x-apikey": VIRUSTOTAL_API_KEY }
response = requests.request("GET", url, headers=headers)
url = "https://www.virustotal.com/api/v3/files/"+response.json()['meta']['file_info']['sha256']
response = requests.request("GET", url, headers=headers)
print("VirusTotal File Scan Report: ")
print("https://www.virustotal.com/gui/file/"+response.json()['data']['id']+"/detection")
print("VirusTotal File Scan Stats: ")
print(response.json()['data']['attributes']['last_analysis_stats'])


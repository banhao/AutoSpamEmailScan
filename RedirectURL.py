#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: hao.ban@ehealthsask.ca//banhao@gmail.com
# Version:
# Issue Date: May 25, 2022
# Release Note: 

import sys, time, datetime, urllib.request
from selenium import webdriver

url = sys.argv[1]
try:
    response_code = urllib.request.urlopen(url).getcode()
except Exception:
    sys.exc_info()
    print(url, "is not accessible.")
    response_code = 404

if response_code == 200:
    driver = webdriver.Edge(executable_path=r'.\msedgedriver.exe')
    time.sleep(2)
    driver.get(url)
    time.sleep(2)
    print(driver.current_url)
    driver.quit()
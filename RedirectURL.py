#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: hao.ban@ehealthsask.ca//banhao@gmail.com
# Version:
# Issue Date: June 02, 2022
# Release Note: 

import sys, time, datetime, urllib.request
from selenium import webdriver
from selenium.webdriver.edge.options import Options
#from msedge.selenium_tools import EdgeOptions
#from msedge.selenium_tools import Edge

url = sys.argv[1]
edge_options = Options()
edge_options.use_chromium = True
edge_options.add_experimental_option('w3c', False)
edge_options.binary_location = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
#driver = Edge(executable_path=r'.\msedgedriver.exe', options=edge_options)
driver = webdriver.Edge(options = edge_options)
time.sleep(1)
try:
    driver.get(url)
    time.sleep(10)
    print(driver.current_url)
except Exception:
    MSG = sys.exc_info()[1]
    if "ERR_NAME_NOT_RESOLVED" in MSG.msg:
        print(url, "is not accessible.")
driver.quit()
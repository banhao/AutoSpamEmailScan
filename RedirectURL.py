#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: hao.ban@ehealthsask.ca//banhao@gmail.com
# Version:
# Issue Date: May 25, 2022
# Release Note: 

import sys, time, datetime
from selenium import webdriver

url = sys.argv[1]
driver = webdriver.Edge(executable_path=r'.\msedgedriver.exe')
time.sleep(2)
driver.get(url)
time.sleep(5)
print(driver.current_url)
driver.quit()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: hao.ban@ehealthsask.ca//banhao@gmail.com
# Version:
# Issue Date: June 02, 2022
# Release Note: 

import sys, time, datetime
from selenium import webdriver

url = sys.argv[1]
log_file = sys.argv[2]
#driver = webdriver.Firefox()
#driver = webdriver.Chrome()
driver = webdriver.Edge()
#driver = webdriver.Edge(executable_path=r'.\msedgedriver.exe')
time.sleep(2)
driver.get(url)
time.sleep(10)
screenshot_file = r".\reports\screenshot_" + log_file.split("_")[1].split(".")[0] + ".jpg"
driver.get_screenshot_as_file(screenshot_file)
message = "This HTML file is trying to open as " + str(driver.title) + ". It's highly suspicious Phising or Spam email."
print(message)
driver.quit()

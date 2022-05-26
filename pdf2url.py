#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: hao.ban@ehealthsask.ca//banhao@gmail.com
# Version:
# Issue Date: May 25, 2022
# Release Note: 

import sys
from PyPDF2 import PdfReader

pdffile = sys.argv[1]

reader = PdfReader(pdffile)
for page in reader.pages:
    if "/Annots" in page:
        for annot in page["/Annots"]:
            if annot.get_object()["/Subtype"] == '/Link' :
                print(annot.get_object()["/A"]["/URI"])

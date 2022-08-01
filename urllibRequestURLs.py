
# To support both python 2 and python 3
from __future__ import division, print_function, unicode_literals
# Common imports
import pandas as pd
import numpy as np
import time
import os
import sklearn
#import seaborn as sns
import warnings
#import matplotlib as mpl
#import matplotlib.pyplot as plt
#from mpl_toolkits.mplot3d import Axes3D
from random import randrange
#Disabling Warnings
import urllib.request as urllib
import socket
#import pyodbc
from datetime import datetime
import ssl
import OpenSSL
import logging
from celery.app.log import Logging

# Load Datasets
def loadDataset(file_name):
    df = pd.read_csv(file_name)
    return df

df_URLs = loadDataset("data.csv")

List = df_URLs['url']

length = len(List)
for url in List:
    print(url)

    try:
        request = urllib.Request(url)
        request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36')
        response = urllib.urlopen(request)
        rdata = response.info()
        ipaddr = socket.gethostbyname(request.origin_req_host)
    except Exception as e:
        print(logging.traceback.format_exc()) 
    except urllib.error.HTTPError as e:
    # Return code error (e.g. 404, 501, ...)
    # ...
        print('HTTPError: {}'.format(e.code))
        time.sleep(1)
        continue
    except urllib.error.URLError as e:
    # Not an HTTP-specific error (e.g. connection refused)
    # ...
        print('URLError: {}'.format(e.reason))
        time.sleep(1)
        continue
    else:
    # 200
     #  if response.status_code == 200:
        print('good, everything is going well. ')
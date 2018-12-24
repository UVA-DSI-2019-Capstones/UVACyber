#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov  5 14:59:56 2018

@author: rakeshravi
"""

import pandas as pd

file = "/Users/rakeshravi/Documents/Capstone Project/Secondary Dataset - Host Dataset/wls_day-01.txt"

with open(file, "r") as ins:
    array = []
    for line in ins:
        array.append(line)
        
print(len(array))
sample = array[1:1000]

check = pd.DataFrame(data=array)
check.columns = ['raw']
import numpy as np
check['Time'] = np.nan
check['EventID'] = np.nan
check['LogHost'] = np.nan
check['LogonType'] = np.nan
check['LogonTypeDescription'] = np.nan
check['UserName'] = np.nan
check['DomainName'] = np.nan
check['LogonID'] = np.nan
check['SubjectUserName'] = np.nan
check['SubjectDomainName'] = np.nan
check['SubjectLogonID'] = np.nan
check['Status'] =np.nan
check['Source'] = np.nan
check['ServiceName'] = np.nan
check['Destination'] = np.nan
check['AuthenticationPackage'] = np.nan
check['FailureReason'] = np.nan
check['ProcessName'] = np.nan
check['ProcessID'] = np.nan
check['ParentProcessName'] = np.nan
check['ParentProcessID'] = np.nan
check.head()
columnlist = ['Time',
'EventID',
'LogHost',
'LogonType',
'LogonTypeDescription',
'UserName',
'DomainName',
'LogonID',
'SubjectUserName',
'SubjectDomainName',
'SubjectLogonID',
'Status',
'Source',
'ServiceName',
'Destination',
'AuthenticationPackage',
'FailureReason',
'ProcessName',
'ProcessID',
'ParentProcessName',
'ParentProcessID']
check['LogHost']= check['LogHost'].astype(str)
check['UserName']= check['UserName'].astype(str)
sample = check.head(1000)

for index,row in sample.iterrows():
    str1 = (''.join(str(e) for e in row['raw'])).strip("\n")
    d = json.loads(str1)
    lis = []
    for y in range(0,21):
        try:
            k = d[columnlist[y]]
            lis.append(k)
        except KeyError:
            lis.append(0)
    print(lis)
    sample.set_value(index,'Time',lis[0])
    sample.set_value(index,'EventID',lis[1])
    sample.set_value(index,'LogHost',lis[2])
    sample.set_value(index,'LogonType',lis[3])
    sample.set_value(index,'LogonTypeDescription',lis[4])
    sample.set_value(index,'UserName',lis[5])
    sample.set_value(index,'DomainName',lis[6])
    sample.set_value(index,'LogonID',lis[7])
    sample.set_value(index,'SubjectUserName',lis[8])
    sample.set_value(index,'SubjectDomainName',lis[9])
    sample.set_value(index,'SubjectLogonID',lis[10])
    sample.set_value(index,'Status',lis[11])
    sample.set_value(index,'Source',lis[12])
    sample.set_value(index,'ServiceName',lis[13])
    sample.set_value(index,'Destination',lis[14])
    sample.set_value(index,'AuthenticationPackage',lis[15])
    sample.set_value(index,'FailureReason',lis[16])
    sample.set_value(index,'ProcessName',lis[17])
    sample.set_value(index,'ProcessID',lis[18])
    sample.set_value(index,'ParentProcessName',lis[19])
    sample.set_value(index,'ParentProcessID',lis[20])
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Thu Sep 27 18:29:45 2018

@author: babraham
"""
import re
import time
import pandas as pd

#Parses a honeypot log and converts into a dataframe. Extracts:
    #srcIP, srcPt, destIP, destPt, session_id, and timestamp.
    #Ex. res = parse_honeypot_log(path-to-honeypot-log.log)
    
def parse_honeypot_log(honeypot_file):
    with open(honeypot_file, 'r') as f:
        ftext = f.read()
        conn_pat = '[0-9]{4}-[0-9]{2}-[0-9]{2}.* New connection: .* \\[session: .*\\]'
        conn_tup = '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.[0-9]+'
        conns = re.findall(conn_pat, ftext)
        recs = []
        date = ""
        for i,conn in enumerate(conns):
            rec = {}
            dt_str = re.findall('([0-9]{4}-[0-9]{2}-[0-9]{2}.*?)\+', conn)[0]
            if i == 0: date = dt_str.split('T')[0]
            time_obj = time.strptime(dt_str,'%Y-%m-%dT%H:%M:%S.%f')
            rec['ts_hp'] = time.mktime(time_obj)
            src_info = re.findall('New connection: ({})'.format(conn_tup), conn)[0]
            rec['src_ip'], rec['src_pt'] = src_info.split(':')
            dest_info =  re.findall('\(({})\)'.format(conn_tup), conn)[0]
            rec['dest_ip'], rec['dest_pt'] = dest_info.split(':')
            rec['session_id'] = re.findall('session: (.*?)\]', conn)[0]
            recs.append(rec)
    newdata = pd.DataFrame(recs)
    return newdata
    
  
    
    
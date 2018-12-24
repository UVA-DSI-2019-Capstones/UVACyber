#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 20 12:52:29 2018

@author: babraham
"""
import numpy as np
import pandas as pd
import re
import os
import time
from datetime import date as Date

#This class enables cross-referencing honeypot IPs with real network traffic. 

#This class can: 
        # 1) label one connection at a time using one of the following:
#               #label_ip_by_date() - provide IP address and date string
#               #label_conn_by_date() - for row of a connection dataframe - pass in row and optional date str
#               #label_conn_by_time() - for row of a connection dataframe - pass in row and optional time
        # 2) label an entire connection log file using:
#               #label_logfile() - labels raw connection logfile - just pass its filename
#               #label_df() - labels a connection dataframe. Requires you to the df into memory

#   The class reads in honeypot data on an as-needed basis (i.e. only uses traffic from the date of connection logs) to save memory. Simply point the labeler to the right honeypot directory (defaults to ./honeypot) and the class will take care of reading in the right log files.

#   NOTE: This class assumes that honeypot log files follow a date-based naming convention
        #i.e. 2018-08-19-honeypot1.log

class HoneypotLabeler():
    
    def __init__(self, hp_dir = None, log_dir = None, output_dir = None):
        self.data = None
        self.log_dir = log_dir if log_dir else "./conn_logs" #where the connection logs are stored
        self.hp_dir = hp_dir if hp_dir else "./honeypot"      #where honeypot logs are stored
        self.output_dir = output_dir if output_dir else "./honeypot" #where to export labeled data
        self.ips_by_date = {}
    
    #labels an IP address by date. Date format: YYYY-MM-DD
    def label_ip_by_date(self,ip_addr, date):
        if date not in self.ips_by_date:
            self.add_data_by_date(date)
        return int(ip_addr in self.ips_by_date[date])

   #label a row from conn_df by ip and date. Competitive with label_df
    def label_conn_by_date(self, conn_row, ip_col='id.orig_h', date=None):
        if not date:
            try: date = conn_row['ts'].date().strftime('%Y-%m-%d')
            except: date = conn_row['ts'].split('T')[0]
        try: return int(conn_row[ip_col] in self.ips_by_date[date])
        except: return 0
        
    #label a row from conn_df by ip and time_window. Very slow
    def label_conn_by_time(self, conn_row, ip_col='id.orig_h', time_col='ts_unix', time_window = 24):
        try: date = conn_row['ts'].date().strftime('%Y-%m-%d')
        except: date = conn_row['ts'].split('T')[0]
        if date not in self.dates:
            print('reading in honeypot data...')
            self.add_data_by_date(date)
        data_sub = self.data.loc[:,['src_ip','ts_hp']]
        data_sub['time_diffs'] = data_sub['ts_hp'].apply(lambda x: np.abs(x-conn_row[time_col])/3600)
        data_sub = data_sub[data_sub['time_diffs'] <= time_window]
        return (conn_row[ip_col] in set(data_sub['src_ip'].tolist()))
    
    #label a connection logfile, line by line. Memory efficient.
    def label_logfile(self,lf):
        f = open(lf, 'r')
        outname = re.sub('\.log', '_hp_label.log', lf)
        #outfile = '/'.join([self.output_dir,outname]) ##UNCOMMENT THIS
        outfile = outname
        out = open(outfile, 'w')
        line = f.readline().strip()
        #modify and export header
        while line.startswith('#'):
            if line.startswith('#fields'):
                line = re.sub('\\t', ',', line)
                line = line[8:]+','+'hp_label\n'
                out.write(line)
            line = f.readline().strip()
        #try to infer date from filename. If not, infer date from first row.
        try: date = re.findall('([0-9]{4}.[0-9]{2}.[0-9]{2})/', lf)[0]
        except: date = None
        if not date:
            ts = float(line.split('\t')[0])
            date_obj = date.from_timestamp(ts)
            date = date_obj.strftime('%Y-%m-%d')
        while line:
            lsplit = line.split('\t')
            sip, dip = lsplit[2],lsplit[4]
            local = int(lsplit[-1])
            target_ip = dip if local==1 else sip
            label = self.label_ip_by_date(target_ip,date)
            lsplit.append(str(label))
            line = ','.join(lsplit) + '\n'
            out.write(line)
            line = f.readline().strip()          
        out.close()
        f.close()
      
    #label an entire conn_log dataframe       
    def label_df(self, traff_df, ip_col='id.orig_h', time_col='ts_unix', date=None, time_window = 24):
        if not date:
            try: date = traff_df['ts'][0].date().strftime('%Y-%m-%d')
            except: date = traff_df['ts'][0].split('T')[0]
        
        if date not in self.ips_by_date:
            print('reading in honeypot data...')
            self.add_data_by_date(date)
            
        traff_df['row_id'] = traff_df.index #Creating a column for row_id         
        if time_col in traff_df.columns and time_col in self.data.columns:
            traff_df.rename(columns = {time_col:time_col+'_traff'})
            time_col += '_traff'
        #Joining all the datasets based on the IP address
        normal_honeypot_match = traff_df.merge(self.data,left_on=ip_col,right_on='src_ip',how='left')
        #Calculating the time difference of normal traffic IP and honeypot traffic IP
        time_diff = pd.to_numeric(normal_honeypot_match['ts_hp'])- normal_honeypot_match[time_col]
        normal_honeypot_match['Time_difference'] = np.abs(time_diff)/3600
        
        ### Filtering only the matches based on the time window condition
        normal_honeypot_match = normal_honeypot_match[normal_honeypot_match.Time_difference <= time_window]
        normal_honeypot_match['honeypot_flag'] = 1
        
        ### Now the final dataset should have all the IP addresses regular + honeypot
        ### Since we have filtered the honeypot IPs we select the non-honeypot ones from regular traffic 
        unique_honeypot_row_ids = set(normal_honeypot_match.row_id.unique())
        list_out = [each for each in traff_df['row_id'] if each not in unique_honeypot_row_ids]
        
        ## Selecting corresponding rows from normal_traffic    
        normal_traffic_subset = traff_df[traff_df['row_id'].isin(list_out)]    
        normal_traffic_subset['honeypot_flag'] = 0
        
        ##### COMBINING NORMAL DATA AND HONEYPOT DATA
        combined_data = pd.concat([normal_traffic_subset,normal_honeypot_match], axis = 0, ignore_index = True)
        combined_data_out = combined_data[normal_traffic_subset.columns].drop_duplicates()
        
        #combined_data_out would not contain all the rows as per normal traffic with an additional flag for honeypot traffic  
        return combined_data_out
    
    def add_data_by_date(self,datestr = "2018-08-19"):
        #change format from yyyy/mm/dd to yyyy-mm-dd
        datestr = datestr.replace('/','-')
        fnames = re.findall("("+datestr+'.*?.log)', '#'.join(os.listdir(self.hp_dir)))
        for f in fnames:
            fpath = '/'.join([self.hp_dir,f])
            self.parse_honeypot_log(fpath) 
            
    def extract_honeypot_data(self,conn_lf, output_dir = None):
        f = open(conn_lf, 'r')
        out_dir = output_dir if output_dir else self.output_dir
        outname = re.sub('\.log', '_hp_data.csv', conn_lf).split('/')[-1]
        outfile = '/'.join([out_dir,outname]) ##UNCOMMENT THIS
        out = open(outfile, 'w')
        line = f.readline().strip()
        #modify and export header
        while line.startswith('#'):
            if line.startswith('#fields'):
                line = re.sub('\\t', ',', line[:8])
                out.write(line+'\n')
            line = f.readline().strip()
        #try to infer date from filename. If not, infer date from first row.
        try: date = re.findall('([0-9]{4}.[0-9]{2}.[0-9]{2})/', conn_lf)[0]
        except: date = None
        if not date:
            ts = float(line.split('\t')[0])
            date_obj = date.from_timestamp(ts)
            date = date_obj.strftime('%Y-%m-%d')
        while line:
            lsplit = line.split('\t')
            sip, dip = lsplit[2],lsplit[4]
            local = int(lsplit[-1])
            target_ip = dip if local==1 else sip
            label = self.label_ip_by_date(target_ip,date)
            if label == 1:
                line = ','.join(lsplit) + '\n'
                out.write(line)
            line = f.readline().strip()          
        out.close()
        f.close()
        
    def parse_honeypot_log(self,honeypot_file, overwrite=False):
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
        
        if date not in self.ips_by_date: self.ips_by_date[date] = set()
        for ip in newdata['src_ip'].unique().tolist():
            self.ips_by_date[date].add(ip)
        
        if self.data is None or overwrite: self.data = newdata            
        else: self.data = pd.concat([self.data, newdata], axis=0)
        
    def clear(self):
        self.dates = {}
        self.data = None
        
        
ips = ['116.31.116.10',
       '122.228.10.50',
       '178.73.215.171',	
       '185.244.25.133',	
       '212.237.2.20',
       '94.102.56.252',
       '45.227.255.97',
       '78.128.112.62',
       '78.128.112.50',
       '80.82.64.116']



def ipFilter(x, ip_list):
    target_ip = x['id.orig_h'] if not x['local'] else x['id.resp_h']
    return (target_ip in set(ip_list))

def label_logfile(hpl,lf):
    f = open(lf, 'r')
    outname = re.sub('\.log', '_hp_label.log', lf)
    #outfile = '/'.join([self.output_dir,outname]) ##UNCOMMENT THIS
    outfile = outname
    out = open(outfile, 'w')
    line = f.readline().strip()
    #modify and export header
    while line.startswith('#'):
        if line.startswith('#fields'):
            line = re.sub('\\t', ',', line)
            line = line[8:]+','+'hp_label\n'
            out.write(line)
        line = f.readline().strip()
    #try to infer date from filename. If not, infer date from first row.
    try: date = re.findall('([0-9]{4}.[0-9]{2}.[0-9]{2})/', lf)[0]
    except: date = None
    if not date:
        ts = float(line.split('\t')[0])
        date_obj = date.from_timestamp(ts)
        date = date_obj.strftime('%Y-%m-%d')
    while line:
        lsplit = line.split('\t')
        sip, dip = lsplit[2],line[4]
        local = int(lsplit[-1])
        target_ip = sip if local==1 else dip
        label = hpl.label_ip_by_date(target_ip,date)
        lsplit.append(str(label))
        line = ','.join(lsplit) + '\n'
        out.write(line)
        line = f.readline().strip()          
    out.close()
    f.close()

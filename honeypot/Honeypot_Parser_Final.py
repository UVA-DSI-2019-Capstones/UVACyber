
# coding: utf-8

# In[5]:


import os
os.chdir('/Users/rakeshravi/Documents/honeypot_logs/Honeypot 1')


# In[6]:


import pandas as pd

with open('merged.log') as f:
    time = []
    protocol = []
    details = []
    for line in f:
        if line.startswith('2018'):
            #temp=line.split(' ', 2)
            time.append(line.split('[',1)[0])
            protocol.append(line.split('[',1)[1].split(']',1)[0])
            details.append(line.split('[', 1)[1].split(']', 1)[1])
    df=pd.DataFrame({'time':time,'protocol':protocol,'details':details})


# In[51]:


# import datetime
# df.head(20)
# # df['time'][1].strftime('%Y-%m-%dT%H:%M:%S')
# o = datetime.datetime.strptime(df['time'][1], '%Y-%m-%dT%H:%M:%S.%f+0000')
# from dateutil.parser import parse
# dt = parse(df['time'].values[1])
# print(dt)
# det = df['details'].values[17]
# src_ip = det[det.find('New connection: ')+len('New connection: '):det.find(":", det.find('New connection: ')+len('New connection: ')-1)]
# 
# src_port = det[det.find('New connection: ')+len('New connection: '):det.find("(", det.find('New connection: ')+len('New connection: ')-1)].split(":")[1]
# session_id = det[det.find('[session: ')+len('[session: '):det.find("]", det.find('[session: ')+len('[session: ')-1)]
# dest_port = det[det.find('('):det.find(")", det.find('('))].split(':')[1]  

# software =  df['protocol'].values[18].split(",")[0]
# src_port = df['protocol'].values[18].split(",")[1]
# src_ip = df['protocol'].values[18].split(",")[2]
# print(df['protocol'].values[18].count(",") + 1)


# In[16]:


from dateutil.parser import parse
import pandas as pd
columnlist = ['timestamp',
'software',
'src_port',
'src_ip',
'session_id',
'dest_port',
'dest_ip',
'details']
parsed_df = pd.DataFrame(columns=columnlist)
for index, row in df.iterrows():
    #timestamp
    timestamp = parse(row['time'])
    #parsing protocol to software, src_port, src_ip
    if row['protocol'].count(",") + 1 == 3:
        software =  row['protocol'].split(",")[0]
        src_port = row['protocol'].split(",")[1]
        src_ip = row['protocol'].split(",")[2]
        session_id = 0
        dest_port = 0                                          
    elif 'New connection:' in row['details']:
        software =  row['protocol']
        det = row['details']
        src_ip = det[det.find('New connection: ')+len('New connection: '):det.find(":", det.find('New connection: ')+len('New connection: ')-1)]
        src_port = det[det.find('New connection: ')+len('New connection: '):det.find("(", det.find('New connection: ')+len('New connection: ')-1)].split(":")[1]
        session_id = det[det.find('[session: ')+len('[session: '):det.find("]", det.find('[session: ')+len('[session: ')-1)]    
        dest_port = det[det.find('('):det.find(")", det.find('('))].split(':')[1]                                        
    else:
        software =  row['protocol']
        src_port = 0
        src_ip = 0
        session_id = 0      
        dest_port = 0
    #dest_ip
    dest_ip = '128.143.31.40:23'
    details = row['details'].strip('\n')
    lis = [timestamp, software, src_port, src_ip, session_id, dest_port, dest_ip, details]
    temp_df = pd.DataFrame([lis], columns = columnlist)
    print(index)
    parsed_df = parsed_df.append(temp_df)
   


# In[18]:


parsed_df.head(20)


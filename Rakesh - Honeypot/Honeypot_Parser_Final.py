
# coding: utf-8

# In[3]:


import os
os.chdir('/Users/rakeshravi/Documents/honeypot_logs/Honeypot 1')
with open('merged.log') as f:
    time = []
    protocol = []
    details = []
    for line in f:
        if line.startswith('2018'):
            time.append(line.split('[',1)[0])
            protocol.append(line.split('[',1)[1].split(']',1)[0])
            details.append(line.split('[', 1)[1].split(']', 1)[1])
    df=pd.DataFrame({'time':time,'protocol':protocol,'details':details})


# In[ ]:


from dateutil.parser import parse
import pandas as pd
timestamp= []
software = []
src_port = []
src_ip = []
session_id = []
dest_port = []
dest_ip = []
details = []
for index, row in df.iterrows():
    #timestamp
    timestamp.append(parse(row['time']))
    #parsing protocol to software, src_port, src_ip
    if row['protocol'].count(',') + 1 == 3:
        software.append(row['protocol'].split(',')[0])
        src_port.append(row['protocol'].split(',')[1])
        src_ip.append(row['protocol'].split(",")[2])
        session_id.append(0)
        dest_port.append(0)                                    
    elif 'New connection:' in row['details']:
        software .append(row['protocol'])
        det = row['details']
        src_ip.append(det.split(':')[1].split(':')[0])
        src_port.append(det.split(':')[2].split('(')[0])
        session_id.append(det.split('[')[1].split(']')[0].split(':')[1])     
        dest_port.append(det.split('(')[1].split(')')[0].split(':')[1])                              
    else:
        software.append(row['protocol'])
        src_port.append(0)
        src_ip.append(0)
        session_id.append(0)
        dest_port.append(0)
    #dest_ip
    dest_ip.append('128.143.31.40')
    details.append(row['details'].strip('\n'))


# In[5]:


import pandas as pd
parsed_df=pd.DataFrame({'timestamp':timestamp, 'software':software,'src_port':src_port, 'src_ip':src_ip,
    'session_id':session_id,'dest_port':dest_port, 'dest_ip':dest_ip, 'details':details})
parsed_df.to_csv('honeypot2_1.csv',sep = ',')


# In[ ]:


parsed_df.head()


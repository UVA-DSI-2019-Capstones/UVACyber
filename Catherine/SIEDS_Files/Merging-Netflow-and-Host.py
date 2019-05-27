
import Netflow_Functions as nf
import sqlite3
import pandas as pd
import netflowMethods as nm

# Merging Netflow and Host Data

# Converting pandas dataframe into SQLite Database
host = pd.read_csv('merged.csv', header = 0)


db_netflow = sqlite3.connect('netflow-subset.db')
db_host = sqlite3.connect('host-subset.db')

nm.df.to_sql('Netflow_Subset', db_netflow, index = False, if_exists = 'replace')
host.to_sql('Host_Subset', db_host, index = True, if_exists = 'replace')

# Need to have host dataframe and do above line



sql_line = "SELECT DISTINCT DstDevice FROM Netflow_Subset"
dsts = pd.read_sql(sql_line, db_netflow)
dsts.to_sql('DstDevices', db_netflow, index = True, index_label = 'dst', if_exists = 'replace')
dsts = pd.read_sql("SELECT * FROM DstDevices", db_netflow, index_col="dst")
print(dsts.head())


sql_line2 = "SELECT DISTINCT LogHost FROM Host_Subset"
hosts = pd.read_sql(sql_line2, db_host)
hosts.to_sql('LogHosts', db_host, index = True, index_label = 'host', if_exists = 'replace')
hosts = pd.read_sql("SELECT * FROM LogHosts", db_host, index_col="host")
print(hosts.head())

print(set(host["LogHost"]) & set(nm.df["DstDevice"]))
import Netflow_Functions as nf
import sklearn.cluster
import sklearn
import numpy as np
import pandas as pd


netflowData = open('netflow_day-02.txt', 'r')
header = ["Time", "Duration", "SrcDevice", "DstDevice", "Protocol", "SrcPort", "DstPort", "SrcPackets",
          "DstPackets", "SrcBytes", "DstBytes"]

# Creating Pandas Dataframe
df = nf.make_df(netflowData, header)

# Converting all columns to correct data type
nf.convert_type(df)

# Filtering by Five-Tuple
df = nf.remove_repeats(df)

# Removing outliers in SrcPackets and DstPackets
df = nf.remove_outliers(df, 'SrcPackets')
df = nf.remove_outliers(df, 'DstPackets')

# Finding 5 clusters
packets = df.loc[:,["SrcPackets","DstPackets"]]
kmeans = sklearn.cluster.KMeans(n_clusters=5, init='k-means++').fit(packets)
clusters = kmeans.labels_
# This does not do what you expected-- does not find the linear relationships

# Trying DBSCAN because this clustering method can find linear clusters
dbscan = sklearn.cluster.DBSCAN(eps = 800).fit(packets)
dbClusters = dbscan.labels_
print(dbClusters)
print(len(set(dbClusters)))
# Plots

# Plot a scatter plot of DstPackets vs SrcPackets
df.plot(x="SrcPackets", y="DstPackets", kind='scatter', title='Destination Packets vs Source Packets: No Outliers')

# Plot scatter plot of DstPackets vs SrcPackets, and color points by Duration
#df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
                     #c = df['Duration'], title='Destination Packets vs Source Packets (Duration): No Outliers',
                     #legend=True, colormap = 'Blues')

# Plot scatter plot of DstPackets vs SrcPackets, and color points by Protocol
df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
                     c = df['Protocol'], title='Destination Packets vs Source Packets (Protocol): No Outliers',
                     legend=True, colormap = 'Accent')

# Plot scatter plot of DstPackets vs SrcPackets, and color points by K-Means Cluster
#df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
                     #c = clusters, title='Destination Packets vs Source Packets (KMeans): No Outliers',
                     #legend=True, colormap = 'Blues')

# Plot scatter plot of DstPackets vs SrcPackets, and color points by DBSCAN Cluster
df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
                     c = dbClusters, title='Destination Packets vs Source Packets (DBSCAN): No Outliers',
                     legend=True, colormap = 'Set2')


# K Means on the scatterplot so try to seperate the 5 relationships and get 5 linear relations

# First need to make all the data numerical
#sklearn.LabelEncoder().fit(df[:,[]])


# ***********************Make protocol categoricacl not an int




#clusters = []
#for i in range(0,2982):
    #clusters[i] = kmeans.predict(df.iloc[i, :])
    
# What if I categorize the lines by making five ranges for y/x for each pt
slopes = df["DstPackets"]/df["SrcPackets"]
slopes[slopes<=0.25] = 0
slopes[(slopes>0.25) & (slopes<=0.75)] = 0.5
slopes[(slopes>0.75) & (slopes<=1.5)] = 1
slopes[(slopes>1.5) & (slopes<=100)] = 2
slopes[slopes>100] = 3

#print(set(slopes))

# Plot scatter plot of DstPackets vs SrcPackets, and color points by slopes
df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
                     c = slopes, title='Destination Packets vs Source Packets (Similar Slopes): No Outliers',
                     legend=True, colormap = 'Set2')


testDF_x = df["SrcPackets"][df["SrcPackets"]<=2000]
testDF_y = df["DstPackets"][df["DstPackets"]<=2000]
testDF = pd.concat([testDF_x, testDF_y])
#testDF = df.loc[df["SrcPackets"] <=2000 & df["DstPackets"]<=2000, ["SrcPackets", "DstPackets"] ]
#print(testDF)
#df.plot(x=testDF_x, y=testDF_y, kind='scatter', 
                     #title='Destination Packets vs Source Packets (<=2000): No Outliers')

####################################################

# More exploratory plots

# Removing outliers in SrcPackets and DstPackets
df = nf.remove_outliers(df, 'SrcPackets')
df = nf.remove_outliers(df, 'DstPackets')
df = nf.remove_outliers(df, 'Time')

# Plot a scatter plot of DstPackets vs time
#df.plot(x="Time", y="DstPackets", kind='scatter', title='Destination Packets vs Time: Outliers Removed')

# Plot a scatter plot of SrcPackets vs time
#df.plot(x="Time", y="SrcPackets", kind='scatter', title='Source Packets vs Time: Outliers Removed')

# Plot scatter plot of DstPackets vs Time, and color points by Protocol
#df.plot(x="Time", y="DstPackets", kind='scatter', 
                     #c = df['Protocol'], title='Destination Packets vs Time (Protocol): No Outliers',
                     #legend=True, colormap = 'Accent')

# Plot scatter plot of SrcPackets vs Time, and color points by Protocol
#df.plot(x="Time", y="SrcPackets", kind='scatter', 
                     #c = df['Protocol'], title='Source Packets vs Time (Protocol): No Outliers',
                     #legend=True, colormap = 'Accent')

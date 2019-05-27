# Catherine Beazley
# Netflow Analysis
# Cyber Capstone Project: LANL Proof of Concept

import pandas as pd    
import matplotlib.pyplot as plt
import math
import numpy as np
from copy import deepcopy
import random
import requests
import lxml.html as lh
import scipy.stats.mstats
from statsmodels.stats.proportion import proportions_ztest
from sklearn.decomposition import PCA



# Read in a Netflow file and creates a Pandas Dataframe from it
def make_df(file, header):
    data = []
    count = 0
    for line in file:
        count += 1
        # The count variable controls how many lines of data I am reading in
        if count <= 15000:
            # This subset only includes the lines with 10 commas indicating there is no missing data
            if line.count(',')==10:
                row = line.split(',')
                # Removing the new line character at the end of the last element
                row[10] = row[10].replace('\n', '')
                data.append(row)     
        else:
            break
    df = pd.DataFrame.from_records(data, columns = header)
    
    return df

# Convert Netflow Columns in a dataframe to correct types 
# (need variables like Time to be in ints instead of strings)
def convert_type(df):
    df["Time"] = df["Time"].astype(int)
    df["Duration"] = df["Duration"].astype(int)
    df["Protocol"] = df["Protocol"].astype('category')
    df["SrcPackets"] = df["SrcPackets"].astype(int)
    df["DstPackets"] = df["DstPackets"].astype(int) 
    #df["DstBytes"] = df["DstBytes"].astype(int)
    #df["SrcBytes"] = df["SrcBytes"].astype(int)

# Remove repeated five tuples to only show the last one, which is the culmination of the flow
def remove_repeats(df):
    return df.drop_duplicates(subset=['Time', 'SrcDevice', 'DstDevice', 'Protocol', 'SrcPort', 'DstPort'], keep='last')


# Remove outliers from a column
def remove_outliers(df, col):
    q1 = df[col].quantile(0.25)
    q3 = df[col].quantile(0.75)
    iqr = q3-q1 #Interquartile range
    fence_low  = q1-1.5*iqr
    fence_high = q3+1.5*iqr
    removed = df.loc[(df[col] > fence_low) & (df[col] < fence_high)]
    return removed

# Classify a DstPort as common or uncommon
def cat_dst_port(df, port_col):
    # http://www.pearsonitcertification.com/articles/article.aspx?p=1868080
#    common = ['20', '21', '22', '23', '25', '53', '67', '68', '69', '80', '110', '123', '137', '138', '139', 
#              '143', '161', '162', '179', '389', '443', '636',  '989', '990']
    common = list(udp_tcp_ports(df)['Port#'])
    category = []
    for i in range(len(port_col)):
        if port_col.iloc[i] in common:
            category.append(1)
        else:
            category.append(0)
    return category

def dstport_distribution(df):
    valueCounts = df["DstPort"].value_counts()
    percents = []
    for value in valueCounts:
        percents.append(value/df.shape[0])
    percents = pd.Series(percents).astype(str)
    dist = pd.concat([valueCounts, percents])
    #valueCounts['Percent'] = percents
    return valueCounts

def udp_tcp_ports(dataFrame):
    
    url = 'http://www.meridianoutpost.com/resources/articles/well-known-tcpip-ports.php'
    page = requests.get(url)
    table = lh.fromstring(page.content)
    rows = table.xpath('//tr')[6:]
    
    # Reading in the column headers
    header = []
    i = 0
    for row in rows[0]:
        i += 1
        name = row.text_content()
        name = name.replace("\n", "")
        name = name.replace(" ", "")
        header.append(name)
    
    # Reading in the body of the table
    table = [[]]  
    for j in range(1, len(rows)):
        row = rows[j]
        
        if len(row) != 4:
            break
        
        row_j = []
        for child in row.iterchildren():
            data = child.text_content()
            data = data.replace(" ", "")
            row_j.append(data)

        table.append(row_j)
    
    table = table[1:163][:]
    udp_tcp = pd.DataFrame.from_records(table, columns = header)
    udp_tcp = udp_tcp.loc[:,["Port#", "Portocol"]]
    udp_tcp = udp_tcp[udp_tcp["Port#"] != '902']
    return udp_tcp


def cosine_similarity(slope1, slope2):
    a = np.array([1,slope1])
    b = np.array([1,slope2])
    return np.dot(a, b)/(np.linalg.norm(a)*np.linalg.norm(b))


# Unsupervised Clustering Algorithm to cluster by slope (based off kmeans)
def slope_classifier(k, x_coords, y_coords):    
    # Randomly assigning initial clusters
    slopeClusters = []
    for i in range(k):
        slopeClusters.append((random.uniform(0,math.pi/2)))
    
    # Finding the ratio of y to x (slope for each (x,y) coordinate)
    # Making x values of 0 very small to avoid divide by zero error
    xCopy = x_coords
    xCopy[xCopy==0] = 0.00000000000000000001
    y = np.array(y_coords, dtype = 'float')
    x = np.array(xCopy, dtype = 'float')
    slopes = np.divide(y,x)
    
    
    # Instantiating and empty np array of 0 as a place holder for the old slope clusters
    # will use this to calculate error as slope clusters change each iteration. Once the error
    # is 0, the clusters have stabilized
    old_slopeClusters = np.zeros(len(slopeClusters))
    error = np.divide(np.subtract(slopeClusters, old_slopeClusters), old_slopeClusters)
  
    # Running a loop until centroids stabilize (percent change from old cluster values to new is 0)
    while error.any() != 0:
        
        # Instantiating an empty np array of 0s that will be populated with cluster assignments for each slope  
        clusters = np.zeros(len(slopes))
        
        # For each slope, find the cosine distance to each cluster. Cosine always return [0,1], with values
        # closer to 1 signifying that the two vectors are close; 0 that they are far apart. Finding the max
        # cosine value and the corresponding cluster will be assigned to that slope. 
        for i in range(len(slopes)):               
            distances = []
            for j in range(len(slopeClusters)):
                distances.append(cosine_similarity(slopes[i],slopeClusters[j]))
            cluster = np.argmax(distances)
            clusters[i] = cluster
        
               
        # Making a deep copy of the old centroids to use later for caclulating error
        old_slopeClusters = deepcopy(slopeClusters)
        
        
        # Finding new centroids by taking average of the values assigned to each cluster and
        # replacing the old cluster values with the new averages
        for m in range(k):
            points = [slopes[j] for j in range(len(slopes)) if clusters[j] == m]              
            slopeClusters[m] = sum(points)/len(points)
        
        # Finding the percent change from the old cluster assignments to the new cluster assignments
        error = np.divide(np.subtract(slopeClusters, old_slopeClusters), old_slopeClusters)
        
    return clusters

def create_outliers_df(df, col):
    q1 = df[col].quantile(0.25)
    q3 = df[col].quantile(0.75)
    iqr = q3-q1 
    fence_low  = q1-1.5*iqr
    fence_high = q3+1.5*iqr
    outliers = df.loc[(df[col] <= fence_low) & (df[col] >= fence_high)]
    return outliers
    
        

def main():
    
    # File and Header for Netflow Data Subset
    netflowData = open('netflow_day-02.txt', 'r')
    header = ["Time", "Duration", "SrcDevice", "DstDevice", "Protocol", "SrcPort", "DstPort", "SrcPackets",
              "DstPackets", "SrcBytes", "DstBytes"]
    
    # Creating Pandas Dataframe
    df = make_df(netflowData, header)
    
    # Converting all columns to correct data type
    convert_type(df)
 
    # Filtering by Five-Tuple to get flow
    df = remove_repeats(df)
    print(min(df["Time"]))
    # Removing outliers in SrcPackets and DstPackets
    #df = remove_outliers(df, 'SrcPackets')
    #df = remove_outliers(df, 'DstPackets')
    
#    # Plot a scatter plot of DstPackets vs SrcPackets
#    df.plot(x="SrcPackets", y="DstPackets", kind='scatter', title='Destination Packets vs Source Packets: No Outliers')
#    plt.xlim([0, 20000])
#    plt.ylim([0, 20000])

    # Creating a dataframe of all the outliers in SrcPackets and DstPackets
#    srcOuliers = create_outliers_df(df, 'SrcPackets')
#    dstOutliers = create_outliers_df(df, 'DstPackets')
#    print(srcOuliers.head())
#    print(dstOutliers.head())
#    
#    # Plot scatter plot of DstPackets vs SrcPackets, and color points by Protocol
#    df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
#                     c = df['Protocol'], title='Destination Packets vs Source Packets (Protocol): No Outliers',
#                     legend=True, colormap = 'Accent')
#  
    # Analyzing whether UDP is important
    udpTcpPorts = cat_dst_port(df, df['DstPort'])
    print('UDP/TCP Ports:', udpTcpPorts)
#    df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
#                     c = udpTcpPorts, title='Destination Packets vs Source Packets (UDP/TCP (1) and Not (0) Port)',
#                     legend=True, colormap = 'Accent')
    
    # Adding UDP/TCP as a column
#    df['UDP/TCP'] = udpTcpPorts
#    
#    dfUDP = df[df['UDP/TCP']==1]
#    dfUDP.plot(x="SrcPackets", y="DstPackets", kind='scatter', title='Destination Packets vs Source Packets (UDP/TCP DstPorts Only)')
#    print("UDP/TCP DstPort-------------------------------------------")
#    print(dfUDP.describe())
#    print(dstport_distribution(dfUDP))
#    
#    df.plot(x="SrcPackets", y="DstPackets", kind='scatter', title='Destination Packets vs Source Packets: No Outliers')
#    print("All-------------------------------------------")
#    print(df.describe())
#    
#    dfOther = df[df['UDP/TCP']==0]
#    dfOther.plot(x="SrcPackets", y="DstPackets", kind='scatter', title='Destination Packets vs Source Packets (Other DstPorts Only)')
#    print("Other DstPort-------------------------------------------")
#    print(dfOther.describe())
#    print(dstport_distribution(dfOther))
    
    
    
#    # Clustering the data
#    clusters = slope_classifier(5,df["SrcPackets"], df["DstPackets"])
##    df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
##                     c = clusters, title='Destination Packets vs Source Packets (Clustered Slopes): No Outliers',
##                     legend=True, colormap = 'Accent')
##    
#    # Appending a column for the cluster assignment
#    df["Cluster"] = clusters
##    
##    # Dividing the dataframe by cluster
#    c0 = df[df["Cluster"]==0]
#    c1 = df[df["Cluster"]==1]
#    c2 = df[df["Cluster"]==2]
#    c3 = df[df["Cluster"]==3]
#    c4 = df[df["Cluster"]==4]
    
    # Finding % UDP/TCP per cluster
#    print("Cluster: ", (c0['DstPackets']/c0['SrcPackets']).mean(), " and Percent: ", c0['UDP/TCP'].sum()/ len(c0['UDP/TCP']))
#    print("Cluster: ", (c1['DstPackets']/c1['SrcPackets']).mean(), " and Percent: ", c1['UDP/TCP'].sum()/ len(c1['UDP/TCP']))
#    print("Cluster: ", (c2['DstPackets']/c2['SrcPackets']).mean(), " and Percent: ", c2['UDP/TCP'].sum()/ len(c2['UDP/TCP']))
#    print("Cluster: ", (c3['DstPackets']/c3['SrcPackets']).mean(), " and Percent: ", c3['UDP/TCP'].sum()/ len(c3['UDP/TCP']))
#    print("Cluster: ", (c4['DstPackets']/c4['SrcPackets']).mean(), " and Percent: ", c4['UDP/TCP'].sum()/ len(c4['UDP/TCP']))
#    
#    count = np.array([c0['UDP/TCP'].sum(), c1['UDP/TCP'].sum()])
#    nobs = np.array([len(c0['UDP/TCP']), len(c0['UDP/TCP'])])
#    print(proportions_ztest(count, nobs))
# Can see that normal assumptions do not apply so I need non-parametric testing.
    
    # Statistical Testing of Duration. I am assuming independence because one connection does not influence
    # another. Each line in the dataset should be independent?
    
    # Need to prove identically distributed
    # plot against time. should be no patterns
    # histogram of durations should be roughly normal?
    
    # Creating histograms of duration to see if approx normal
#    c0.hist(column = 'Duration', bins = 30)
#    c1.hist(column = 'Duration', bins = 30)
#    c2.hist(column = 'Duration', bins = 30)

    # Scaling the Duration Columns and saving them as lists
#    s0 = (c0['Duration'] - c0['Duration'].mean())/c0['Duration'].std()
#    #s0.hist(bins=30)
#    
#    l0 = np.log(c0['Duration'])    
#    l1 = np.log(c1['Duration'])    
#    l2 = np.log(c2['Duration'])    
#    l3 = np.log(c3['Duration'])    
#    l4 = np.log(c4['Duration'])
#    
#    
#    l0.hist(bins = 10, alpha = 0.6, label = '0')
#    l1.hist(bins = 10, alpha = 0.6, label = '1')
#    l2.hist(bins = 10, alpha = 0.6, label = '2')
#    l3.hist(bins = 10, alpha = 0.6, label = '3')
#    l4.hist(bins = 10, alpha = 0.6, label = '4')
    
    # Can see that the shapes of the distrbutions are similar so the null hypothesis is 
    # H0: the medians are all equal
    # Ha: the medians are not all equal
    
    
    # Not normal and no clear distribution so what ever stat method I use can't rely on a distribution
    # Kruskal Wallis does not depend on any distrubution in the data
    #kw = scipy.stats.mstats.kruskalwallis(c0['Duration'].tolist(), c1['Duration'].tolist(), 
                                          #c2['Duration'].tolist(), c3['Duration'].tolist(), c4['Duration'].tolist())
    
#    kwLog = scipy.stats.mstats.kruskalwallis(l0.tolist(), l1.tolist(), l2.tolist(), l3.tolist(), l4.tolist())
#    print(kwLog)
#    
#    print("Cluster: ", (c0['DstPackets']/c0['SrcPackets']).mean(), "and" , "Cluster: ", (c1['DstPackets']/c1['SrcPackets']).mean())
#    kwLog01 = scipy.stats.mstats.kruskalwallis(l0.tolist(), l1.tolist())
#    print(kwLog01)
#    
#    print("Cluster: ", (c0['DstPackets']/c0['SrcPackets']).mean(), "and" , "Cluster: ", (c2['DstPackets']/c2['SrcPackets']).mean())
#    kwLog02 = scipy.stats.mstats.kruskalwallis(l0.tolist(), l2.tolist())
#    print(kwLog02)
#    
#    print("Cluster: ", (c0['DstPackets']/c0['SrcPackets']).mean(), "and" , "Cluster: ", (c3['DstPackets']/c3['SrcPackets']).mean())
#    kwLog03 = scipy.stats.mstats.kruskalwallis(l0.tolist(), l3.tolist())
#    print(kwLog03)
#    
#    print("Cluster: ", (c0['DstPackets']/c0['SrcPackets']).mean(), "and" , "Cluster: ", (c4['DstPackets']/c4['SrcPackets']).mean())
#    kwLog04 = scipy.stats.mstats.kruskalwallis(l0.tolist(), l4.tolist())
#    print(kwLog04)
#    
#    print("Cluster: ", (c1['DstPackets']/c1['SrcPackets']).mean(), "and" , "Cluster: ", (c2['DstPackets']/c2['SrcPackets']).mean())
#    kwLog12 = scipy.stats.mstats.kruskalwallis(l1.tolist(), l2.tolist())
#    print(kwLog12)
#    
#    print("Cluster: ", (c1['DstPackets']/c1['SrcPackets']).mean(), "and" , "Cluster: ", (c3['DstPackets']/c3['SrcPackets']).mean())
#    kwLog13 = scipy.stats.mstats.kruskalwallis(l1.tolist(), l4.tolist())
#    print(kwLog13)    
#    
#    print("Cluster: ", (c1['DstPackets']/c1['SrcPackets']).mean(), "and" , "Cluster: ", (c4['DstPackets']/c4['SrcPackets']).mean())
#    kwLog14 = scipy.stats.mstats.kruskalwallis(l1.tolist(), l4.tolist())
#    print(kwLog14)
#    
#    print("Cluster: ", (c2['DstPackets']/c2['SrcPackets']).mean(), "and" , "Cluster: ", (c3['DstPackets']/c3['SrcPackets']).mean())
#    kwLog23 = scipy.stats.mstats.kruskalwallis(l2.tolist(), l3.tolist())
#    print(kwLog23)    
#    
#    print("Cluster: ", (c2['DstPackets']/c2['SrcPackets']).mean(), "and" , "Cluster: ", (c4['DstPackets']/c4['SrcPackets']).mean())
#    kwLog24 = scipy.stats.mstats.kruskalwallis(l2.tolist(), l4.tolist())
#    print(kwLog24)
#    
#    print("Cluster: ", (c3['DstPackets']/c3['SrcPackets']).mean(), "and" , "Cluster: ", (c4['DstPackets']/c4['SrcPackets']).mean())
#    kwLog34 = scipy.stats.mstats.kruskalwallis(l3.tolist(), l4.tolist())
#    print(kwLog34)
    

    
##    print("Cluster 0:\n" , c0.describe())
#    print("Cluster 1:\n" , c1.describe())
#    print("Cluster 2:\n" , c2.describe())
#    print("Cluster 3:\n" , c3.describe())
#    print("Cluster 4:\n" , c4.describe())

    #print(c0)

    # Analyzing DstPort 
#    print("Cluster 0: ", len(df[df["Cluster"]==0]), "\n", dstport_distribution(df[df["Cluster"]==0]))
#    print("Cluster 1: ", len(df[df["Cluster"]==1]), "\n", dstport_distribution(df[df["Cluster"]==1]))
#    print("Cluster 2: ", len(df[df["Cluster"]==2]), "\n", dstport_distribution(df[df["Cluster"]==2]))
#    print("Cluster 3: ", len(df[df["Cluster"]==3]), "\n", dstport_distribution(df[df["Cluster"]==3]))
#    print("Cluster 4: ", len(df[df["Cluster"]==4]), "\n", dstport_distribution(df[df["Cluster"]==4]))
#    
#    # Common Ports
    #cat = cat_dst_port(df["DstPort"])
#    df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
#                     c = cat, title='Destination Packets vs Source Packets (Common (1) and Uncommon (0) Port)',
#                     legend=True, colormap = 'Accent')
#    # TCP UDP Ports
#    print(udp_tcp_ports(df))
    #dsts = dstport_distribution(df)
    #print(dsts)
    #dsts.plot.hist(grid=True, bins=20, rwidth=0.9, color='#607c8e')  
    #sns.countplot(x="DstPort", data=df, order=df["DstPort"].value_counts().iloc[:10].index)

#    sns.countplot(x="Cluster", data=df, palette = 'husl')
#    df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
#                     c = clusters, title='Destination Packets vs Source Packets (Clustered Slopes): No Outliers',
#                     legend=True, colormap = 'husl')
#
#    
    
#    print('==========================================')
#    # PCA stuff
#    pcaDF = df[["Time", "Duration", "Protocol", "SrcPackets", "DstPackets"]]
#    pca = PCA(n_components=2).fit_transform(pcaDF)
#    pcdf = pd.DataFrame(data = pca, columns = ['PC1', 'PC2'])
#    #print(pcdf.head())
#    #pcdf.plot(x="PC1", y="PC2", kind='scatter', c = clusters, title='PCA Plot with Packet Clusters',legend=True, colormap = 'Accent', alpha = 1)
#
#    #pcdf.plot(x="PC1", y="PC2", kind='scatter', title='PCA Plot', colormap = 'Accent', alpha = 0.2)
#    #plt.xlabel('PC1')
#    #plt.ylabel('PC2')
#    #plt.show()
#    
#    
#    # Packet Size
#    df['SrcPacketSize'] = df['SrcPackets']/df['SrcBytes']
#    df['DstPacketSize'] = df['DstPackets']/df['DstBytes']
#    df.plot(x="SrcPacketSize", y="DstPacketSize", kind='scatter', title='Destination Packet Size vs Source Packet Size')


    



if __name__ == "__main__":
    main()
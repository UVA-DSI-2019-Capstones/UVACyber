# Catherine Beazley
# Netflow Analysis
# Cyber Capstone Project

import pandas as pd
import math
import numpy as np
import netflowMethods as nm
from copy import deepcopy

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
    #df["DstBytes"] = df["DstBytes"].astype('long')
    #df["SrcBytes"] = df["SrcBytes"].astype(int)


# Remove repeated five tuples to only show the last one, which is the colmination of the flow
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

# Find frequency that a device is sending out info

# Categorize ports
def cat_dst_port(port_col):
    common = [20, 21, 22, 2325, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 
              143, 161, 162, 179, 389, 443, 636,  989, 990]
    category = []
    for i in range(len(port_col)):
        if port_col[i] in common:
            category[i] = "common"
        else:
            category[i] = "uncommon"
    return category

# do a box and whisker plot or something so show distribution of these
# then pull out the common ones
# then pull out specific ones within common, likek udp or something bc there are multiple numbers for them


  

    
    
#def main():
#    #clusters = slope_classifier(5,nm.df["SrcPackets"], nm.df["DstPackets"])
#    #nm.df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
#                     #c = clusters, title='Destination Packets vs Source Packets (Similar Slopes): No Outliers',
#                     #legend=True, colormap = 'Accent')
#    
#    netflowData = open('netflow_day-02.txt', 'r')
#    header = ["Time", "Duration", "SrcDevice", "DstDevice", "Protocol", "SrcPort", "DstPort", "SrcPackets",
#              "DstPackets", "SrcBytes", "DstBytes"]
#    
#    # Creating Pandas Dataframe
#    df = make_df(netflowData, header)
#
#    # Converting all columns to correct data type
#    convert_type(df)
#    
#    # Filtering by Five-Tuple
#    df = remove_repeats(df)
#    
#    # Removing outliers in SrcPackets and DstPackets
#    df = remove_outliers(df, 'SrcPackets')
#    df = remove_outliers(df, 'DstPackets')
#    
#    #print(cat_dst_port(nm.df["DstPort"]))
#    cat = cat_dst_port(nm.df["DstPort"])
#    df.plot(x="SrcPackets", y="DstPackets", kind='scatter', 
#                     c = cat, title='Destination Packets vs Source Packets (Category Port): No Outliers',
#                     legend=True, colormap = 'Accent')
#
#
#    
#if __name__ == "__main__":
#    main()
    
    

    
    
    

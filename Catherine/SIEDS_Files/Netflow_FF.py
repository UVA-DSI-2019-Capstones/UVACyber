# Catherine Beazley
# Netflow Analysis
# Cyber Capstone Project

import pandas as pd


# Read in a Netflow file and creates a Pandas Dataframe from it
def make_df(file, header):
    data = []
    count = 0
    for line in file:
        count += 1
        # The count variable controls how many lines of data I am reading in
        if count <= 10000:
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

# Use an alg like kmeans to find the k points with a similar ratio y ot x
# because the intercept seems to be zero so each line should be just slope.
# 





    
    
    

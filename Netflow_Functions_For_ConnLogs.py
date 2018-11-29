# Catherine Beazley
# Cyber Capstone
# 11/29/2018

# These are some of the functions I wrote for Netflow that we can use on Conn Logs. 

# Notes: 
#   - most of my functions assume the data is in a pandas dataframe
#   - not sure if 'remove_repeats' will be needed-- depends on the flows

import numpy as np
import random
import math
from copy import deepcopy

# would have to have the same columns titles for this function
def convert_type(df):
    df["Time"] = df["Time"].astype(int)
    df["Duration"] = df["Duration"].astype(int)
    df["Protocol"] = df["Protocol"].astype('category')
    df["SrcPackets"] = df["SrcPackets"].astype(int)
    df["DstPackets"] = df["DstPackets"].astype(int) 
    df["DstBytes"] = df["DstBytes"].astype(int)
    df["SrcBytes"] = df["SrcBytes"].astype(int)
    
# Remove repeated five tuples to only show the last one, which is the culmination of the flow
def remove_repeats(df):
    return df.drop_duplicates(subset=['Time', 'SrcDevice', 'DstDevice', 'Protocol', 'SrcPort', 'DstPort'], keep='last')
    
def cosine_similarity(slope1, slope2):
    a = np.array([1,slope1])
    b = np.array([1,slope2])
    return np.dot(a, b)/(np.linalg.norm(a)*np.linalg.norm(b))

def slope_classifier(k, x_coords, y_coords):    
    
    # Randomly assigning initial cluster centroids
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





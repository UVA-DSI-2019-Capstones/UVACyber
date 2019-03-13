#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 13 16:04:23 2019

@author: babraham
"""
import multiprocessing as mp
import numpy as np
from datetime import datetime, timedelta
import itertools
import pandas as pd
import os
import sklearn
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.linear_model import LogisticRegressionCV
from sklearn.metrics import confusion_matrix, roc_curve, auc
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import GradientBoostingClassifier

import matplotlib.pyplot as plt

#%matplotlib inline


#=========Sample Usage===============#
#lr = LogisticRegression()
#res = train(lr, prepare, parallel=True)
#===================================#

def train(classifier, preprocess_fn, train_list = None, test_list=None, parallel=False):
    
    # if no training/text files provided, infer from directory
    if not train_list or not test_list:
        #train_path = '/scratch/rk9cx/conn_log_labelled_runtime/stratified_samples_W1-W2_larg/train/splits/'
        train_path = '/Users/babraham/Downloads/train'
        train_list = [train_path+'/'+f for f in os.listdir(train_path) if '.csv' in f]     
        #test_path = '/scratch/rk9cx/conn_log_labelled_runtime/stratified_samples_W1-W2_larg/test/splits/'
        test_path = '/Users/babraham/Downloads/test'
        test_list = [test_path+'/'+f for f in os.listdir(train_path) if '.csv' in f]
                    
    if parallel:
        nc = mp.cpu_count()
        print('using {} cores'.format(nc))
        # split train and test files into core lists
        train_lists = make_core_lists(train_list, nc=nc)
        test_lists = make_core_lists(test_list, nc=nc)
        pool = mp.Pool(processes=nc)
        recs = [pool.apply_async(train, args=(classifier,train_lists[i],test_lists[i],False)) for i in range(nc)]
        recs = [r.get() for r in recs]    
        results = []
        for r in recs: results +=r
        return results
        
    else:
        results = []
        for i, train_file in enumerate(train_list):
            # create new model cloning input classifier
            cur_model = sklearn.base.clone(classifier)
            print("-"*10+"training model {}".format(i)+"-"*10)
            X, y = preprocess_fn(train_file)
            cur_model.fit(X, y)
            # data frame to store results
            res = pd.DataFrame()
            
            for j, test_file in enumerate(test_list):
                metrics = {'train_idx':i, 'test_idx':j}
                X_test, y_test = preprocess_fn(test_path + '/test_' + str(j) + '.csv')    
                pred_y = cur_model.predict(X_test)
                print("made predictions for mod {} on test set {}".format(i,j))
                res = pd.concat([res,pd.DataFrame(cur_model.predict_proba(X_test)).T.head(1).T], axis = 1)
                cm= confusion_matrix(y_test, pred_y)
                tn, fp, fn, tp = cm.ravel()
                precision=tp/(tp+fp)
                recall=tp/(tp+fn)
                metrics['test_idx'] = j
                metrics['fpr'] = fp/(fp+ tn)
                metrics['accuracy'] = (tp + tn)/(tn + tp + fn + fp)
                metrics['F1'] = 2 * (precision * recall) / (precision + recall)
                metrics['Fpr'], metrics['tpr'], metrics['threshs'] = roc_curve(y_test, pred_y)
                metrics['auc'] = auc(metrics['Fpr'],metrics['tpr'])
                print("AUC",  metrics['auc'])
                print("F1-score", metrics['F1'])
                results.append(metrics)
                
        return results
        

def prepare(csv_file):
    df = pd.read_csv(csv_file)
    cols = ['ts','src_port','dest_port','duration','src_bytes','dest_bytes']    
    for c in cols: df[c] = df[c].replace('-',0)
    X = df.loc[:,cols]
    y = df['label']
    return X,y

# generic method to split a list across nc cores
def make_core_lists(totlist, nc=None):
    np.random.shuffle(totlist)
    if not nc: nc = mp.cpu_count()
    lists = []
    intvl = len(totlist) / nc
    remaining = len(totlist) - intvl * nc
    for i in range(nc):
        sub = totlist[i*intvl:(i+1)*intvl]
        lists.append(sub)
    #spread remaining elements evenenly
    for j in range(remaining):
	idx = j + intvl * nc
	lists[j].append(totlist[idx])
    return lists

       
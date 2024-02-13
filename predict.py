import warnings
warnings.filterwarnings("ignore")
import os
import json
import sys
import argparse
import math
from collections import Counter

# Third Party Imports
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans

# Local imports
from zat import log_to_dataframe
from zat import dataframe_to_matrix


def entropy(string):
    """Compute entropy on the string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())


def predict(zeek_df):
    # Sanity check either http or dns log

    features = ['id.resp_p', 'method', 'resp_mime_types', 'request_body_len']


    # Use the zat DataframeToMatrix class
    to_matrix = dataframe_to_matrix.DataFrameToMatrix()
    zeek_matrix = to_matrix.fit_transform(zeek_df[features])
    print(zeek_matrix.shape)

    # Train/fit and Predict anomalous instances using the Isolation Forest model
    odd_clf = IsolationForest(contamination=0.2)  # Marking 20% as odd
    odd_clf.fit(zeek_matrix)

    # Now we create a new dataframe using the prediction from our classifier
    predictions = odd_clf.predict(zeek_matrix)
    odd_df = zeek_df[features][predictions == -1]
    display_df = zeek_df[predictions == -1].copy()

    # Now we're going to explore our odd observations with help from KMeans
    odd_matrix = to_matrix.fit_transform(odd_df)
    num_clusters = min(len(odd_df), 4)  # 4 clusters unless we have less than 4 observations
    display_df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(odd_matrix)
    print(odd_matrix.shape)


    features += ['host']
    cluster_groups = display_df[features + ['cluster']].groupby('cluster')

    # Now print out the details for each cluster
    print('<<< Outliers Detected! >>>')
    output = {}

    for key, group in cluster_groups:
        cluster = {}

        cluster['Cluster: '] = key
        cluster['Number of observations:'] = len(group)
        cluster['Session:'] = group
        output[key] = cluster

    return output
if __name__ == '__main__':

    zeek_df = pd.read_json("log.json")


    print("--------------------")
    output = predict(zeek_df)
    print(output)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jan 23 02:10:54 2022

@author: msoguz
"""

import pandas as pd
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
def detect(liste):
    train_CSV = os.path.join("phishing-dataset", "train.csv")
    test_CSV = os.path.join("phishing-dataset", "test.csv")
    train_df = pd.read_csv(train_CSV)
    test_df = pd.read_csv(test_CSV)
    y_train = train_df.pop("target").values
    y_test = test_df.pop("target").values
    X_train = train_df.values
    X_test = test_df.values
    clf = RandomForestClassifier()
    clf.fit(X_train, y_train)
    y_test_pred = clf.predict(X_test)
    data=pd.DataFrame(liste)
    data = data.transpose()
    data.columns = ["has_ip", "long_url", "short_service","has_at","double_slash_redirect","pref_suf","has_sub_domain","ssl_state","long_domain","favicon","port","https_token","req_url","url_of_anchor","tag_links","SFH","submit_to_email","abnormal_url","redirect","mouseover","right_click","popup","iframe","domain_Age","dns_record","traffic","page_rank","google_index","links_to_page","stats_report"]
    results = clf.predict(data)
    return results 
# NSWC Cyber Resilliance Challenge Deliverable 2

import math
import pandas as pd
import numpy as np

cve_used = pd.read_csv('./data/cve_used.csv',index_col=False)
functional_map = pd.read_csv('./data/functional_map.csv',index_col=False)
functional_scores = pd.read_csv('./data/functional_scores.csv',index_col=False)
risk_scores = pd.read_csv('./data/risk_scores.csv',index_col=False)

# Corresponds to column R of Network Elements sheet
def critical_function_score():
    
    nodes = list(functional_map['Endpoint node name'].values)    
    functional_values = list(functional_scores['Functional Value'].values)
    
    _cfs = {}
    
    for n in nodes:
        score = 0
        for f in functional_values:
            cricicality = functional_map.loc[functional_map['Endpoint node name'] == n][f].iloc[0]
            fun_score = functional_scores.loc[functional_scores['Functional Value'] == f]['Score'].iloc[0]
            score += cricicality * fun_score
        _cfs[n] = score
    
    return _cfs
    
# Corresponds to Column U of Network Elements sheet
def cve_score():
    def check_score(s):
        return (0 if math.isnan(s) else s)
    
    # only consider cve if it is in the cve used list
    valid_cves = list(cve_used['CVE'].values)    
    nodes = list(functional_map['Endpoint node name'].values)    
    _scores = {}
    
    for n in nodes:
        node_cves = risk_scores[risk_scores['DEVICE'] == n]
        usable_cves = node_cves[node_cves['CVE'].isin(valid_cves)]
        
        # average score
        with np.errstate(invalid='ignore'):
            _scores[n] = check_score(usable_cves['Score'].sum() / len(list(usable_cves['Score'])))
    
    return _scores

# Corresponds to column W from network elements sheet
def calculate_final_score(_cfs, _scores):
    
    _final = {}
    cfs_weight = .75
    cve_weight = .25
    # weighted sum (for now) of critical function score and cve score for each node
    for k in _cfs.keys():
        _final[k] = cfs_weight * _cfs[k] + cve_weight * _scores[k]
        
    return _final

# New calculation which is the average score over all components
def calculate_overall_score(_final):
    tot = 0
    for k in _final.keys():
        tot += _final[k]
    
    return tot/len(_final.keys())   
    
cfs = critical_function_score()

scores = cve_score()

final = calculate_final_score(cfs, scores)

overall = calculate_overall_score(final)

print(f'Node scores: {final}')

print(f'Overall score: {overall}')
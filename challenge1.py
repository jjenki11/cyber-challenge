# NSWC Cyber Resilliance Challenge Deliverable 2
import math
import pandas as pd
import numpy as np
import datetime

# Load data
cve_used = pd.read_csv('./data/cve_used.csv', index_col=False)
functional_map = pd.read_csv('./data/functional_map.csv', index_col=False)
functional_scores = pd.read_csv('./data/functional_scores.csv', index_col=False)
risk_scores = pd.read_csv('./data/risk_scores.csv', index_col=False)

# --- Utility Functions ---
def normalize(scores):
    """Normalize scores to a range [0, 1]."""
    min_val = min(scores.values())
    max_val = max(scores.values())
    return {k: (v - min_val) / (max_val - min_val) for k, v in scores.items()}

def time_decay(score, date_reported):
    """Apply exponential decay to a score based on days since it was reported."""
    days_since = (datetime.datetime.now() - date_reported).days
    decay_factor = 0.99 ** days_since  # Adjust decay rate if needed
    return score * decay_factor

def classify_risk(score):
    """Classify the impact score into Low, Medium, or High risk."""
    if score >= 80:
        return 'High'
    elif score >= 50:
        return 'Medium'
    else:
        return 'Low'

def check_score(s, fallback):
    """Handle NaN values by replacing them with the fallback (mean)."""
    return (0 if math.isnan(s) else s)

# --- Scoring Functions ---
def critical_function_score():
    """Calculate the critical function score for each node."""
    nodes = list(functional_map['Endpoint node name'].values)
    functional_values = list(functional_scores['Functional Value'].values)
    
    _cfs = {}
    for n in nodes:
        score = 0
        for f in functional_values:
            criticality = functional_map.loc[functional_map['Endpoint node name'] == n][f].iloc[0]
            fun_score = functional_scores.loc[functional_scores['Functional Value'] == f]['Score'].iloc[0]
            score += criticality * fun_score
        _cfs[n] = score

    return normalize(_cfs)  # We normalize scores for consistency

def cve_score():
    """Calculate the CVE score for each node, with time decay applied."""
    valid_cves = list(cve_used['CVE'].values)
    nodes = list(functional_map['Endpoint node name'].values)
    _scores = {}
    
    for n in nodes:
        node_cves = risk_scores[risk_scores['DEVICE'] == n]
        usable_cves = node_cves[node_cves['CVE'].isin(valid_cves)]

        # Apply time decay to CVE scores
        usable_cves['Score'] = usable_cves.apply(
            lambda x: time_decay(x['Score'], x['Reported Date']), axis=1
        )

        # Calculate average score, handle NaN values
        fallback = usable_cves['Score'].mean()  # Use mean as fallback
        try:
            _scores[n] = check_score(usable_cves['Score'].sum() / len(usable_cves['Score']))
        except:
            _scores[n] = fallback

    return normalize(_scores)  # Normalize scores

def calculate_final_score(_cfs, _scores):
    """Calculate the final score using dynamic weights."""
    _final = {}
    
    # Dynamic weighting based on overall network score
    overall_cve_score = sum(_scores.values()) / len(_scores.values())
    cfs_weight = 0.6 + (0.1 * (1 - overall_cve_score))  # Adjust critical function weight
    cve_weight = 1 - cfs_weight  # Complementary weight

    # Weighted sum of critical function and CVE scores for each node
    for k in _cfs.keys():
        _final[k] = cfs_weight * _cfs[k] + cve_weight * _scores[k]

    return _final

def calculate_overall_score(_final):
    """Calculate the overall network resilience score."""
    return sum(_final.values()) / len(_final)

def calculate_device_impact(_cfs, _scores, _overall):
    """Calculate the device impact score based on NIST SP 800-53 formula."""
    _device_impacts = {}
    for k in _cfs.keys():
        impact = (_scores[k] / (_cfs[k] * _overall)) * 100  # Adjust as needed
        _device_impacts[k] = impact

    return _device_impacts

# --- Main Execution ---
cfs = critical_function_score()
scores = cve_score()
final = calculate_final_score(cfs, scores)
overall = calculate_overall_score(final)
device_impacts = calculate_device_impact(cfs, scores, overall)

# Display Results
for device, impact in device_impacts.items():
    risk_level = classify_risk(impact)
    print(f'Device: {device}, Impact Score: {impact:.2f}, Risk Level: {risk_level}')

print(f'Overall Network Resilience Score: {overall:.2f}')

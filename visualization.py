# NSWC Cyber Resilliance Challenge Deliverable 2 and demo

import math
import pandas as pd
import numpy as np
import networkx as nx
import gravis as gv
import os
import panel as pn
import html
import json
import plotly.express as px

cve_used = pd.read_csv('./data/cve_used.csv',index_col=False)
functional_map = pd.read_csv('./data/functional_map.csv',index_col=False)
functional_scores = pd.read_csv('./data/functional_scores.csv',index_col=False)
risk_scores = pd.read_csv('./data/risk_scores.csv',index_col=False)

def update_visuals(event):    
    print('HELLO HELLO 213')
    if not event:
        return

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
def cve_score(_ignore_list):
    def check_score(s):
        return (0 if math.isnan(s) else s)
    
    def get_difference(l1, l2):
        return list(set(l1) - set(l2))
    
    # only consider cve if it is in the cve used list
    valid_cves = get_difference(list(cve_used['CVE'].values), _ignore_list)
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

# Calculate device based impact based on the formula from NIST SP 800-53
# risk = (threat x vulnerabilities) x impact
# risk: cve risk score
# threat: critical functional score
# vulnerabilities: overall network score
def calculate_device_impact(_cfs, _scores, _overall):
    # impact = risk / (threat * vulnerabilities)
    _device_impacts = {}
    for k in _cfs.keys():
        _device_impacts[k] = (_scores[k] / (_cfs[k] * _overall)) * 100
    
    return _device_impacts 

def create_graph(sd):
    def get_color(node):
        if sd[node] >= 20:
            return 'red'
        elif sd[node] >=10 and sd[node] < 20: 
            return 'yellow'
        else:
            return 'green'

    G=nx.Graph()

    node_list = list(sd.keys())
    for n in node_list:
        G.add_node(n, color=get_color(n), size=10+sd[n])

    # Add edges from network topology
    G.add_edge("Internet", "Firewall")
    G.add_edge("Firewall", "Router")

    G.add_edge("Router", "Layer 2 Switches (Ethernet) 1")
    G.add_edge("Router", "Layer 2 Switches (Ethernet) 2")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Layer 2 Switches (Ethernet) 3")
    G.add_edge("Layer 2 Switches (Ethernet) 3", "WAC510 Wireless Access Point")

    G.add_edge("WAC510 Wireless Access Point", "Quality Assurance (Laptop 1)")
    G.add_edge("WAC510 Wireless Access Point", "Quality Assurance (Laptop 2)")
    G.add_edge("WAC510 Wireless Access Point", "August Smart Lock Pro")

    G.add_edge("Layer 2 Switches (Ethernet) 1", "System Administrator Terminal")
    G.add_edge("Layer 2 Switches (Ethernet) 1", "Virtulalization Manager Server")
    G.add_edge("Layer 2 Switches (Ethernet) 1", "Virtulalization Manager SAN Archive")
    G.add_edge("Layer 2 Switches (Ethernet) 1", "Cybersecurity Capability & Tools server")
    G.add_edge("Layer 2 Switches (Ethernet) 1", "Audit Log Server")

    G.add_edge("Layer 2 Switches (Ethernet) 2", "Software Development (Workstation 1)")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Software Development (Workstation 2)")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Software Development (Workstation 3)")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Software Development (Workstation 4)")

    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #1")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #2")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #3")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #4")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #5")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #6")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #7")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #8")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #9")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #10")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #11")
    G.add_edge("Layer 2 Switches (Ethernet) 2", "Server Rack, Server #12")

    G.add_edge("Layer 2 Switches (Ethernet) 3", "Software Development SAN 1")
    G.add_edge("Layer 2 Switches (Ethernet) 3", "Quality Assurance SAN")
    G.add_edge("Layer 2 Switches (Ethernet) 3", "Company Management SAN")
    G.add_edge("Layer 2 Switches (Ethernet) 3", "Company Management (Workstation 5)")
    G.add_edge("Layer 2 Switches (Ethernet) 3", "Company Management (Workstation 6)")
    
    return G


# ****************put in cves to ignore on demo day****************
cves_to_ignore = [

]

cfs = critical_function_score()

scores = cve_score(cves_to_ignore)

final = calculate_final_score(cfs, scores)

overall = calculate_overall_score(final)

device_impacts = calculate_device_impact(cfs, scores, overall)

impact_graph = create_graph(device_impacts)


# each time we want to refresh the dashboard, we need to recreate the html graph
impact_graph_html = 'impact_graph.html'

try:
    os.remove(impact_graph_html)
except OSError:
    pass
fig = gv.three(impact_graph)
fig.export_html(impact_graph_html)

pn.extension("plotly")
pn.extension('tabulator')

HtmlFile = open('impact_graph.html', 'r', encoding='utf-8')
source_code = HtmlFile.read()
escaped_html = html.escape(source_code)
# Create iframe embedding the escaped HTML and display it
iframe_html = f'<iframe srcdoc="{escaped_html}" style="height:100%; width:100%" frameborder="0"></iframe>'

html_pane = pn.pane.HTML(iframe_html, height=500, sizing_mode="stretch_width")

types = {}
types_score = {}


for k in device_impacts.keys():
    v = functional_map.loc[functional_map['Endpoint node name'] == k]['Type'].iloc[0]
    if not v in types:
        types[v] = 0
        types_score[v] = []
    types[v] += 1
    types_score[v].append(device_impacts[k])

df_data = [[k, types[k]] for k in types.keys()]
df_impact = [[k, device_impacts[k]] for k in device_impacts.keys()]

pie_df = pd.DataFrame(df_data, columns=['Type','Count'])
impact_df = pd.DataFrame(df_impact, columns=['Device','Impact Score'])

fig = px.pie(pie_df, values='Count', names='Type')
fig.update_layout(
    title="Device Types",
    width=500,
    height=500,
    margin=dict(t=50, b=50, r=50, l=50),
)

pie_chart = pn.pane.Plotly(fig)

styles = {
    "box-shadow": "rgba(50, 50, 93, 0.25) 0px 6px 12px -2px, rgba(0, 0, 0, 0.3) 0px 3px 7px -3px",
    "border-radius": "4px",
    "padding": "10px",
}
overall_card = pn.indicators.Number(
        value=overall, name="Overall Network Score", format="{value:,.0f}", styles=styles
)
server_card = pn.indicators.Number(
        value=np.sum(types_score['Server'])/len(types_score['Server']), name="Average Server Score", format="{value:,.0f}", styles=styles
)
networking_card = pn.indicators.Number(
        value=np.sum(types_score['Networking'])/len(types_score['Networking']), name="Average Networking Score", format="{value:,.0f}", styles=styles
)
workstation_card = pn.indicators.Number(
        value=np.sum(types_score['Workstation'])/len(types_score['Workstation']), name="Average Workstation Score", format="{value:,.0f}", styles=styles
)

row1 = pn.Row(overall_card,server_card,networking_card,workstation_card)
row2 = pn.Row(pie_chart, html_pane)

cve_data_table = pn.widgets.Tabulator(cve_used, page_size=20, pagination='local')
functional_map_table = pn.widgets.Tabulator(functional_map, page_size=20, pagination='local')
functional_scores_table= pn.widgets.Tabulator(functional_scores, page_size=20, pagination='local')
risk_scores_table = pn.widgets.Tabulator(risk_scores, page_size=20, pagination='local')
device_impacts_table = pn.widgets.Tabulator(impact_df, page_size=20, pagination='local')

row3 = pn.Tabs(
    ('Functional Map', functional_map_table), 
    ('CVE data', cve_data_table),     
    ('Functional Scores', functional_scores_table), 
    ('Risk Scores', risk_scores_table),
    ('Device Impacts', device_impacts_table)
)

fbox = pn.Column(
    pn.Accordion(('Info Cards',row1)), 
    pn.Accordion(('Visualizations',row2)), 
    pn.Accordion(('Data', row3))
)


pn.serve(fbox)


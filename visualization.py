# NSWC Cyber Resilliance Challenge Deliverable 2 and demo
# Desmond Ndambi and Jeff Jenkins

# Import statements
import math
import pandas as pd
import numpy as np
import networkx as nx
import gravis as gv
import os
import panel as pn
import html
import plotly.express as px
# load panel extensions
pn.extension("plotly")
pn.extension("tabulator")

# Helper functions definitions

# Critical function score calculates a device specific score based on critical functions provided
# in the challenge document
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

# CVE score calculates the average CVE risk per device based on the tables given in the challenge document
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

# Final score assumes equal weight between critical function score and cve score to produce
# a device specific combined metric
def calculate_final_score(_cfs, _scores, weights):
    
    _final = {}
    cfs_weight = weights['cfs']
    cve_weight = weights['cve']
    # weighted sum of critical function score and cve score for each device
    for k in _cfs.keys():
        _final[k] = cfs_weight * _cfs[k] + cve_weight * _scores[k]
        
    return _final

# Overall score is a calculation which averages the final score over all devices
# in the network
def calculate_overall_score(_final):
    tot = 0
    for k in _final.keys():
        tot += _final[k]
    
    return tot/len(_final.keys())

# Calculate device based impact using on the formula from NIST SP 800-53
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

# Creates a graph (of nodes and edges) based on the network topology provided
# in the challenge document
def create_graph(sd):
    # We color code nodes with a high score (bigger than 20) red
    # nodes with medium score (between 10 and 20) yellow 
    # nodes with a low score (lower than 10) green
    def get_color(node):
        if sd[node] >= 20:
            return 'red'
        elif sd[node] >=10 and sd[node] < 20: 
            return 'yellow'
        else:
            return 'green'

    # create a networkx graph
    G=nx.Graph()

    node_list = list(sd.keys())
    # set node color based on our function above, and size based on device impact score
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
    
    # Each time we want to refresh the dashboard, we need to recreate the html graph
    try:
        os.remove('impact_graph.html')
    except OSError:
        pass
    
    # Create a 3d rendering of the network graph
    fig = gv.three(G)
    fig.export_html('impact_graph.html')    

    HtmlFile = open('impact_graph.html', 'r', encoding='utf-8')
    source_code = HtmlFile.read()
    escaped_html = html.escape(source_code)
    # Create iframe embedding the escaped HTML and display it
    return pn.pane.HTML(f'<iframe srcdoc="{escaped_html}" style="height:100%; width:100%" frameborder="0"></iframe>', 
                        height=500, sizing_mode="stretch_width")

def compute_impact_stats(_functional_map, _device_impacts):
    types = {}
    types_score = {}

    for k in _device_impacts.keys():
        v = _functional_map.loc[_functional_map['Endpoint node name'] == k]['Type'].iloc[0]
        if not v in types:
            types[v] = 0
            types_score[v] = []
        types[v] += 1
        types_score[v].append(_device_impacts[k])
    
    impact_df = pd.DataFrame([[k, device_impacts[k]] for k in _device_impacts.keys()], columns=['Device','Impact Score'])
    return types, types_score, impact_df

def create_pie_chart(_types):
    df_data = [[k, _types[k]] for k in _types.keys()]
    pie_df = pd.DataFrame(df_data, columns=['Type','Count'])

    fig = px.pie(pie_df, values='Count', names='Type')
    fig.update_layout(
        title="Device Types",
        width=500,
        height=500,
        margin=dict(t=50, b=50, r=50, l=50),
    )
    return pn.pane.Plotly(fig)

def create_info_cards(_overall, _types_score):
    styles = {
        "box-shadow": "rgba(50, 50, 93, 0.25) 0px 6px 12px -2px, rgba(0, 0, 0, 0.3) 0px 3px 7px -3px",
        "border-radius": "4px",
        "padding": "10px",
    }
    overall_card = pn.indicators.Number(
            value=_overall, name="Overall Network Score", format="{value:,.0f}", styles=styles
    )
    server_card = pn.indicators.Number(
            value=np.sum(_types_score['Server'])/len(_types_score['Server']), name="Average Server Score", format="{value:,.0f}", styles=styles
    )
    networking_card = pn.indicators.Number(
            value=np.sum(_types_score['Networking'])/len(_types_score['Networking']), name="Average Networking Score", format="{value:,.0f}", styles=styles
    )
    workstation_card = pn.indicators.Number(
            value=np.sum(_types_score['Workstation'])/len(_types_score['Workstation']), name="Average Workstation Score", format="{value:,.0f}", styles=styles
    )
    return overall_card, server_card, networking_card, workstation_card

def create_tables(  _cve_used,
                    _functional_map,
                    _functional_scores,
                    _risk_scores,
                    _device_impacts_table):
    return pn.widgets.Tabulator(_cve_used, page_size=20, pagination='local'),\
        pn.widgets.Tabulator(_functional_map, page_size=20, pagination='local'),\
        pn.widgets.Tabulator(_functional_scores, page_size=20, pagination='local'),\
        pn.widgets.Tabulator(_risk_scores, page_size=20, pagination='local'),\
        pn.widgets.Tabulator(_device_impacts_table, page_size=20, pagination='local')


# The main program entry point is here :)
if __name__ == "__main__":
    
    # Data loading and filtering code
    
    # Load csv data into pandas dataframes
    cve_used = pd.read_csv('./data/cve_used.csv',index_col=False)
    functional_map = pd.read_csv('./data/functional_map.csv',index_col=False)
    functional_scores = pd.read_csv('./data/functional_scores.csv',index_col=False)
    risk_scores = pd.read_csv('./data/risk_scores.csv',index_col=False)

    # **put in cves to filter/ignore from computation**
    cves_to_ignore = [

    ]
    
    # Computation code

    # compute critical function score
    cfs = critical_function_score()
    # compute cve score
    scores = cve_score(cves_to_ignore)
    # compute final score given cfs and cve scores, with weights for each score
    final = calculate_final_score(cfs, scores, {'cfs': 0.5, 'cve': 0.5})
    # compute overall network score given device specific final scores
    overall = calculate_overall_score(final)
    # compute device impact given cfs, cve scores, and overall network score
    device_impacts = calculate_device_impact(cfs, scores, overall)    
    # compute stats from functional map and device impacts
    types, types_score, impact_df = compute_impact_stats(functional_map, device_impacts)
    
    
    # Dashboard creation code
    
    # generate visual 'impact graph' to be used in the dashboard
    impact_pane = create_graph(device_impacts)
    # generate pie chart for types of network elements
    pie_pane = create_pie_chart(types)
    # generate info cards for the top of the dashboard
    overall_card, server_card, networking_card, workstation_card = create_info_cards(overall, types_score)
    # generate tables for all of our dataframes
    cve_data_table,functional_map_table,functional_scores_table,risk_scores_table,device_impacts_table = create_tables(cve_used,\
                                                                                                                        functional_map,\
                                                                                                                        functional_scores,\
                                                                                                                        risk_scores,\
                                                                                                                        impact_df)
    # create a row to hold the info cards
    row1 = pn.Row(overall_card,server_card,networking_card,workstation_card)
    # create a row to hold the pie chart and 3d graph
    row2 = pn.Row(pie_pane, impact_pane)
    # create a row with tabs to toggle through the data tables
    row3 = pn.Tabs(
        ('Functional Map', functional_map_table), 
        ('CVE data', cve_data_table),     
        ('Functional Scores', functional_scores_table), 
        ('Risk Scores', risk_scores_table),
        ('Device Impacts', device_impacts_table)
    )

    #create a column to hold collapsible panels with our rows
    dashboard = pn.Column(
        pn.Accordion(('Info Cards',row1)), 
        pn.Accordion(('Visualizations',row2)), 
        pn.Accordion(('Data', row3))
    )

    # serve the dashboard to the web browser
    pn.serve(dashboard)
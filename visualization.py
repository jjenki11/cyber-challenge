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


# put in cves to ignore on demo day
cves_to_ignore = [
   
]
    
    
cfs = critical_function_score()

scores = cve_score(cves_to_ignore)

final = calculate_final_score(cfs, scores)

overall = calculate_overall_score(final)

device_impacts = calculate_device_impact(cfs, scores, overall)

impact_graph = create_graph(device_impacts)

gv.vis(impact_graph)
# fig.export_jpg('impact_graph.jpg')



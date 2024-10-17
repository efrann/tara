from datetime import datetime
import plotly.graph_objs as go

def parse_port_input(port_input):
    if not port_input:
        return ""
    
    ports = []
    for part in port_input.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return f"AND vo.port IN ({','.join(map(str, ports))})"

def create_vulnerability_distribution(vulnerability_data):
    return go.Figure(data=[go.Pie(
        labels=['Kritik', 'Yüksek', 'Orta', 'Düşük', 'Bilgi'], 
        values=[d['count'] for d in vulnerability_data],
        marker=dict(colors=['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#3498db'])
    )])

def create_top_vulnerabilities_graph(top_vulnerabilities_data):
    return go.Figure(data=[go.Pie(
        labels=[row['vulnerability_name'] for row in top_vulnerabilities_data],
        values=[row['count'] for row in top_vulnerabilities_data],
        hole=.3,
        marker=dict(
            colors=[
                '#e74c3c' if row['severity'] == 4 else
                '#e67e22' if row['severity'] == 3 else
                '#f1c40f' if row['severity'] == 2 else
                '#2ecc71' if row['severity'] == 1 else
                '#3498db' if row['severity'] == 0 else
                '#95a5a6' for row in top_vulnerabilities_data
            ]
        ),
        textinfo='label',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br><extra></extra>',
        insidetextorientation='radial',
        textfont=dict(size=10, color='white'),
    )])

def create_top_ports_graph(top_ports_data):
    return go.Figure(data=[go.Bar(
        x=[str(row['port']) for row in top_ports_data],
        y=[row['count'] for row in top_ports_data],
        marker_color='#3498db'
    )])

def format_last_updated():
    return f"Son Güncelleme: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

def create_severity_div(severity, count, color):
    return html.Div([
        html.H4(severity, style={'color': color, 'margin': '0'}),
        html.P(count, style={'fontSize': '24px', 'fontWeight': 'bold', 'margin': '0', 'color': 'white'})
    ], style={
        'backgroundColor': '#34495e',
        'padding': '10px',
        'borderRadius': '5px',
        'textAlign': 'center',
        'margin': '5px',
        'minWidth': '100px',
        'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'
    })

def create_applied_filters_div(severity, scan_name, vulnerability_name, ip_address, port, search_value):
    applied_filters = []
    if severity:
        severity_map = {4: 'Kritik', 3: 'Yüksek', 2: 'Orta', 1: 'Düşük', 0: 'Bilgi'}
        applied_filters.append(f"Önem Derecesi: {', '.join(severity_map[s] for s in severity if s in severity_map)}")
    if scan_name:
        applied_filters.append(f"Tarama Adı: {scan_name}")
    if vulnerability_name:
        applied_filters.append(f"Zafiyet Adı: {vulnerability_name}")
    if ip_address:
        applied_filters.append(f"IP Adresi: {ip_address}")
    if port:
        applied_filters.append(f"Port: {port}")
    if search_value:
        applied_filters.append(f"Arama: {search_value}")
    
    return html.Div([
        html.H4("Uygulanan Filtreler:"),
        html.Ul([html.Li(filter_text) for filter_text in applied_filters]) if applied_filters else html.P("Filtre uygulanmadı.")
    ])
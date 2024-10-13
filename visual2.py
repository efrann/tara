import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go
import pandas as pd
import pymysql
from datetime import datetime, timedelta
import math

# MySQL bağlantısı
db = pymysql.connect(
    host="localhost",
    user="root",
    password="Nessus_Report123*-",
    database="nessusdb"
)

# Verileri çekme fonksiyonu
def get_data(severity=None, scan_name=None, vulnerability_name=None):
    with db.cursor(pymysql.cursors.DictCursor) as cursor:
        # Severity filtresi için WHERE koşulu
        severity_condition = ""
        if severity:
            severity_condition = f"AND p.severity IN ({','.join(map(str, severity))})"
        
        # Scan name filtresi için WHERE koşulu
        scan_name_condition = ""
        if scan_name:
            scan_name_condition = f"AND s.name LIKE '%{scan_name}%'"
        
        # Vulnerability name filtresi için WHERE koşulu
        vulnerability_name_condition = ""
        if vulnerability_name:
            vulnerability_name_condition = f"AND p.name LIKE '%{vulnerability_name}%'"

        # Özet bilgi sorgusu
        summary_query = f"""
        SELECT 
            s.name AS scan_name,
            f.name AS folder_name,
            MAX(FROM_UNIXTIME(sr.scan_start)) AS last_scan_date,
            sr.host_count AS total_hosts,
            sr.critical_count AS total_critical,
            sr.high_count AS total_high,
            sr.medium_count AS total_medium,
            sr.low_count AS total_low,
            sr.info_count AS total_info
        FROM 
            scan s
        LEFT JOIN 
            folder f ON s.folder_id = f.folder_id
        JOIN 
            scan_run sr ON s.scan_id = sr.scan_id
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
        {scan_name_condition}
        GROUP BY 
            s.name, f.name, sr.host_count, sr.critical_count, sr.high_count, sr.medium_count, sr.low_count, sr.info_count
        ORDER BY 
            last_scan_date DESC
        """
        
        cursor.execute(summary_query)
        summary_data = cursor.fetchall()
        
        # Zafiyet dağılımı sorgusu
        vulnerability_query = f"""
        SELECT 
            p.severity,
            COUNT(*) as count
        FROM 
            host_vuln hv
        JOIN 
            plugin p ON hv.plugin_id = p.plugin_id
        JOIN
            scan_run sr ON hv.scan_run_id = sr.scan_run_id
        JOIN
            scan s ON sr.scan_id = s.scan_id
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
        {severity_condition} {scan_name_condition}
        GROUP BY 
            p.severity
        """
        
        cursor.execute(vulnerability_query)
        vulnerability_data = cursor.fetchall()
        
        # Detaylı zafiyet listesi sorgusu
        detailed_vulnerability_query = f"""
        SELECT 
            s.name AS scan_name,
            h.host_ip,
            COALESCE(p.name, 'Bilinmeyen Zafiyet') AS vulnerability_name,
            p.severity,
            p.family AS plugin_family,
            vo.port,
            FROM_UNIXTIME(sr.scan_start) AS scan_date
        FROM 
            scan s
        JOIN 
            scan_run sr ON s.scan_id = sr.scan_id
        JOIN 
            host h ON sr.scan_run_id = h.scan_run_id
        JOIN 
            host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND sr.scan_run_id = hv.scan_run_id
        JOIN 
            plugin p ON hv.plugin_id = p.plugin_id
        LEFT JOIN
            vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
        {severity_condition} {scan_name_condition} {vulnerability_name_condition}
        ORDER BY 
            sr.scan_start DESC, p.severity DESC
        LIMIT 1000
        """
        
        cursor.execute(detailed_vulnerability_query)
        detailed_vulnerability_data = cursor.fetchall()

        # En çok görülen 10 zafiyet sorgusu
        top_vulnerabilities_query = f"""
        SELECT 
            f.name AS folder_name,
            s.name AS scan_name,
            COALESCE(p.name, 'Bilinmeyen Zafiyet') AS vulnerability_name,
            p.severity,
            COUNT(*) as count
        FROM 
            host_vuln hv
        JOIN 
            plugin p ON hv.plugin_id = p.plugin_id
        JOIN
            scan_run sr ON hv.scan_run_id = sr.scan_run_id
        JOIN
            scan s ON sr.scan_id = s.scan_id
        JOIN
            folder f ON s.folder_id = f.folder_id
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
        {severity_condition} {scan_name_condition} {vulnerability_name_condition}
        GROUP BY 
            f.name, s.name, p.plugin_id, p.name, p.severity
        ORDER BY 
            count DESC
        LIMIT 10
        """
        
        cursor.execute(top_vulnerabilities_query)
        top_vulnerabilities_data = cursor.fetchall()

        # Toplam zafiyet sayıları sorgusu
        total_vulnerabilities_query = f"""
        SELECT 
            SUM(CASE WHEN p.severity = 4 THEN 1 ELSE 0 END) as total_critical,
            SUM(CASE WHEN p.severity = 3 THEN 1 ELSE 0 END) as total_high,
            SUM(CASE WHEN p.severity = 2 THEN 1 ELSE 0 END) as total_medium,
            SUM(CASE WHEN p.severity = 1 THEN 1 ELSE 0 END) as total_low,
            SUM(CASE WHEN p.severity = 0 THEN 1 ELSE 0 END) as total_info
        FROM 
            host_vuln hv
        JOIN 
            plugin p ON hv.plugin_id = p.plugin_id
        JOIN
            scan_run sr ON hv.scan_run_id = sr.scan_run_id
        JOIN
            scan s ON sr.scan_id = s.scan_id
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
        {severity_condition} {scan_name_condition}
        """
        
        cursor.execute(total_vulnerabilities_query)
        total_vulnerabilities_data = cursor.fetchone()

        # Mevcut taramaları çekmek için yeni bir sorgu ekleyelim
        scan_list_query = """
        SELECT DISTINCT s.name
        FROM scan s
        JOIN scan_run sr ON s.scan_id = sr.scan_id
        ORDER BY s.name
        """
        cursor.execute(scan_list_query)
        scan_list = [row['name'] for row in cursor.fetchall()]

    return summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data, scan_list

# Define your styles
external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

# Custom CSS
custom_styles = r'''
@keyframes pulse {
    0% {
        opacity: 1;
    }
    50% {
        opacity: 0.7;
    }
    100% {
        opacity: 1;
    }
}

body {
    background-color: #2c3e50;
    color: white;
    font-family: Arial, sans-serif;
}

.dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner td, 
.dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner th {
    border: 1px solid #34495e !important;
}

/* Add more custom styles here */
'''

app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

# Add the custom styles to the app's layout
app.layout = html.Div([
    html.Style(custom_styles),
    html.Div([
        html.H1("Nessus Tarama Sonuçları Gösterge Paneli", style={'textAlign': 'center', 'color': 'white'}),
        html.Img(src="/assets/nessus_logo.png", style={'height': '50px', 'float': 'right'}),
    ], style={'backgroundColor': '#2c3e50', 'padding': '10px'}),

    html.Div([
        html.P(id='last-updated', style={'color': 'white', 'textAlign': 'right'}),
        html.P("Bu sayfa her 1 dakikada bir otomatik olarak yenilenir.", style={'color': 'white', 'textAlign': 'right', 'fontStyle': 'italic'}),
    ], style={'backgroundColor': '#2c3e50', 'padding': '10px'}),

    html.Div([
        html.Div([
            html.Label("Severity:", style={'color': 'white'}),
            dcc.Dropdown(
                id='severity-dropdown',
                options=[
                    {'label': 'Critical', 'value': 4},
                    {'label': 'High', 'value': 3},
                    {'label': 'Medium', 'value': 2},
                    {'label': 'Low', 'value': 1},
                    {'label': 'Info', 'value': 0}
                ],
                multi=True,
                style={'width': '200px', 'backgroundColor': '#34495e', 'color': 'black'}
            ),
        ], style={'display': 'inline-block', 'verticalAlign': 'top', 'marginRight': '20px'}),
        html.Div([
            html.Label("Tarama Seç:", style={'color': 'white'}),
            dcc.Dropdown(
                id='scan-dropdown',
                options=[],  # Bu seçenekler callback ile doldurulacak
                style={'width': '200px', 'backgroundColor': '#34495e', 'color': 'black'}
            ),
        ], style={'display': 'inline-block', 'verticalAlign': 'top', 'marginRight': '20px'}),
        html.Div([
            html.Label("Zafiyet Adı:", style={'color': 'white'}),
            dcc.Input(id='vulnerability-name-input', type='text', style={'width': '200px', 'backgroundColor': '#34495e', 'color': 'white'}),
        ], style={'display': 'inline-block', 'verticalAlign': 'top', 'marginRight': '20px'}),
        html.Button('Filtrele', id='filter-button', style={'marginTop': '20px', 'backgroundColor': '#e74c3c', 'color': 'white'}),
    ], style={'backgroundColor': '#2c3e50', 'padding': '10px'}),

    html.Div([
        html.Div([
            html.H3("Toplam Zafiyet Sayıları", style={'textAlign': 'center', 'color': 'white'}),
            html.Div(id='total-vulnerabilities', style={'display': 'flex', 'justifyContent': 'space-around', 'flexWrap': 'wrap'}),
        ], style={'backgroundColor': '#2c3e50', 'padding': '20px', 'margin': '10px', 'borderRadius': '10px'}),
    ]),

    html.Div([
        html.Div([
            html.H3("Özet Bilgiler", style={'textAlign': 'center', 'color': 'white'}),
            dash_table.DataTable(
                id='summary-table',
                columns=[
                    {"name": "Klasör Adı", "id": "folder_name"},
                    {"name": "Tarama Adı", "id": "scan_name"},
                    {"name": "Son Tarama Tarihi", "id": "last_scan_date"},
                    {"name": "Toplam Host", "id": "total_hosts"},
                    {"name": "Kritik", "id": "total_critical"},
                    {"name": "Yüksek", "id": "total_high"},
                    {"name": "Orta", "id": "total_medium"},
                    {"name": "Düşük", "id": "total_low"},
                    {"name": "Bilgi", "id": "total_info"}
                ],
                style_table={
                    'height': '400px',
                    'overflowY': 'auto',
                    'borderRadius': '10px',
                    'boxShadow': '0 4px 6px rgba(0, 0, 0, 0.1)',
                },
                style_cell={
                    'backgroundColor': '#34495e',
                    'color': 'white',
                    'textAlign': 'left',
                    'padding': '12px',
                    'fontFamily': 'Arial, sans-serif',
                    'fontSize': '14px',
                    'border': '1px solid #2c3e50',
                },
                style_header={
                    'backgroundColor': '#2c3e50',
                    'fontWeight': 'bold',
                    'textTransform': 'uppercase',
                    'letterSpacing': '1px',
                    'borderBottom': '2px solid #e74c3c',
                },
                style_data_conditional=[
                    {
                        'if': {'row_index': 'odd'},
                        'backgroundColor': '#2c3e50',
                    },
                    {
                        'if': {'column_id': col, 'filter_query': f'{{{col}}} > 0'},
                        'backgroundColor': '#3498db',
                        'color': 'white',
                        'fontWeight': 'bold',
                        'animation': 'pulse 2s infinite',
                    } for col in ['total_critical', 'total_high', 'total_medium', 'total_low', 'total_info']
                ] + [
                    {
                        'if': {'column_id': 'total_critical', 'filter_query': '{total_critical} > 0'},
                        'backgroundColor': '#e74c3c',
                    },
                    {
                        'if': {'column_id': 'total_high', 'filter_query': '{total_high} > 0'},
                        'backgroundColor': '#e67e22',
                    },
                    {
                        'if': {'column_id': 'total_medium', 'filter_query': '{total_medium} > 0'},
                        'backgroundColor': '#f1c40f',
                    },
                    {
                        'if': {'column_id': 'total_low', 'filter_query': '{total_low} > 0'},
                        'backgroundColor': '#2ecc71',
                    },
                    {
                        'if': {'column_id': 'total_info', 'filter_query': '{total_info} > 0'},
                        'backgroundColor': '#3498db',
                    }
                ],
                sort_action="native",
                sort_mode="multi",
                filter_action="native",
                page_action="native",
                page_current=0,
                page_size=10,
                style_as_list_view=True,
            ),
        ], className="six columns"),

        html.Div([
            html.H3("Zafiyet Dağılımı", style={'textAlign': 'center', 'color': 'white'}),
            dcc.Graph(id='vulnerability-distribution')
        ], className="six columns"),
    ], className="row", style={'backgroundColor': '#2c3e50', 'padding': '20px', 'margin': '10px', 'borderRadius': '10px'}),

    html.Div([
        html.Div([
            html.H3("En Çok Görülen 10 Zafiyet", style={'textAlign': 'center', 'color': 'white'}),
            dash_table.DataTable(
                id='top-vulnerabilities-table',
                columns=[
                    {"name": "Klasör Adı", "id": "folder_name"},
                    {"name": "Tarama Adı", "id": "scan_name"},
                    {"name": "Zafiyet Adı", "id": "vulnerability_name"},
                    {"name": "Önem Derecesi", "id": "severity"},
                    {"name": "Sayı", "id": "count"}
                ],
                style_table={'height': '300px', 'overflowY': 'auto'},
                style_cell={'backgroundColor': '#34495e', 'color': 'white'},
                style_header={'backgroundColor': '#e74c3c', 'fontWeight': 'bold'},
                style_data_conditional=[
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Kritik"'},
                        'color': '#e74c3c',
                        'fontWeight': 'bold'
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Yüksek"'},
                        'color': '#e67e22',
                        'fontWeight': 'bold'
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Orta"'},
                        'color': '#f1c40f',
                        'fontWeight': 'bold'
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Düşük"'},
                        'color': '#2ecc71',
                        'fontWeight': 'bold'
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Bilgi"'},
                        'color': '#3498db',
                        'fontWeight': 'bold'
                    }
                ]
            ),
        ], className="six columns"),

        html.Div([
            html.H3("Detaylı Zafiyet Listesi", style={'textAlign': 'center', 'color': 'white'}),
            dash_table.DataTable(
                id='vulnerability-table',
                columns=[{"name": i, "id": i} for i in ['scan_name', 'host_ip', 'vulnerability_name', 'severity', 'plugin_family', 'port', 'scan_date']],
                style_table={'height': '300px', 'overflowY': 'auto'},
                style_cell={'backgroundColor': '#34495e', 'color': 'white'},
                style_header={'backgroundColor': '#e74c3c', 'fontWeight': 'bold'},
                filter_action="native",
                sort_action="native",
                sort_mode="multi",
                page_action="native",
                page_current=0,
                page_size=10,
            )
        ], className="six columns"),
    ], className="row", style={'backgroundColor': '#2c3e50', 'padding': '10px', 'margin': '10px'}),

    dcc.Interval(
        id='interval-component',
        interval=60*1000,  # Her 1 dakikada bir güncelle
        n_intervals=0
    )
], style={'backgroundColor': '#2c3e50'})

@app.callback(
    [Output('summary-table', 'data'),
     Output('vulnerability-distribution', 'figure'),
     Output('vulnerability-table', 'data'),
     Output('top-vulnerabilities-table', 'data'),
     Output('total-vulnerabilities', 'children'),
     Output('last-updated', 'children'),
     Output('scan-dropdown', 'options')],
    [Input('filter-button', 'n_clicks'),
     Input('interval-component', 'n_intervals')],
    [State('severity-dropdown', 'value'),
     State('scan-dropdown', 'value'),
     State('vulnerability-name-input', 'value')]
)
def update_data(n_clicks, n_intervals, severity, scan_name, vulnerability_name):
    summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data, scan_list = get_data(severity, scan_name, vulnerability_name)
    
    print("Summary Data:", summary_data)  # Debug için eklendi
    
    # Özet tablo verisi
    summary_table_data = [{
        'folder_name': row['folder_name'],
        'scan_name': row['scan_name'],
        'last_scan_date': row['last_scan_date'],
        'total_hosts': row['total_hosts'],
        'total_critical': row['total_critical'],
        'total_high': row['total_high'],
        'total_medium': row['total_medium'],
        'total_low': row['total_low'],
        'total_info': row['total_info']
    } for row in summary_data]
    
    # Zafiyet dağılımı grafiği
    labels = ['Toplam', 'Kritik', 'Yüksek', 'Orta', 'Düşük']
    parents = ['', 'Toplam', 'Toplam', 'Toplam', 'Toplam']
    values = [
        sum(item['count'] for item in vulnerability_data if item['severity'] in [1, 2, 3, 4]),
        sum(item['count'] for item in vulnerability_data if item['severity'] == 4),
        sum(item['count'] for item in vulnerability_data if item['severity'] == 3),
        sum(item['count'] for item in vulnerability_data if item['severity'] == 2),
        sum(item['count'] for item in vulnerability_data if item['severity'] == 1)
    ]
    colors = ['#2c3e50', '#e74c3c', '#e67e22', '#f1c40f', '#2ecc71']

    vulnerability_distribution = {
        'data': [go.Sunburst(
            labels=labels,
            parents=parents,
            values=values,
            branchvalues="total",
            marker=dict(colors=colors),
            textinfo='label+value',
            insidetextorientation='radial',
            hoverinfo='label+value+percent parent'
        )],
        'layout': go.Layout(
            paper_bgcolor='#2c3e50',
            plot_bgcolor='#2c3e50',
            font=dict(color='white', size=14),
            margin=dict(t=80, l=0, r=0, b=0),
            height=600,
            showlegend=False
        )
    }

    # Detaylı zafiyet listesi
    vulnerability_table_data = detailed_vulnerability_data
    
    # En çok görülen 10 zafiyet
    severity_map = {
        4: {'text': 'Kritik', 'color': '#e74c3c'},
        3: {'text': 'Yüksek', 'color': '#e67e22'},
        2: {'text': 'Orta', 'color': '#f1c40f'},
        1: {'text': 'Düşük', 'color': '#2ecc71'},
        0: {'text': 'Bilgi', 'color': '#3498db'}
    }
    
    top_vulnerabilities_table_data = [{
        'folder_name': row['folder_name'],
        'scan_name': row['scan_name'],
        'vulnerability_name': row['vulnerability_name'],
        'severity': severity_map[row['severity']]['text'],
        'severity_color': severity_map[row['severity']]['color'],
        'count': row['count']
    } for row in top_vulnerabilities_data]
    
    # Toplam zafiyet sayıları
    severity_info = [
        {"name": "Kritik", "color": "#e74c3c", "key": "total_critical"},
        {"name": "Yüksek", "color": "#e67e22", "key": "total_high"},
        {"name": "Orta", "color": "#f1c40f", "key": "total_medium"},
        {"name": "Düşük", "color": "#2ecc71", "key": "total_low"},
        {"name": "Bilgi", "color": "#3498db", "key": "total_info"}
    ]
    
    total_vulnerabilities = [
        html.Div([
            html.H4(info["name"], style={'color': info["color"], 'margin': '0', 'fontSize': '18px'}),
            html.P(total_vulnerabilities_data[info["key"]], style={
                'fontSize': '36px', 
                'fontWeight': 'bold', 
                'margin': '10px 0',
                'color': info["color"]
            })
        ], style={
            'textAlign': 'center', 
            'backgroundColor': '#34495e', 
            'padding': '15px', 
            'borderRadius': '10px', 
            'margin': '10px',
            'minWidth': '120px',
            'boxShadow': '0 4px 8px 0 rgba(0,0,0,0.2)'
        }) for info in severity_info
    ]
    
    # Son güncelleme zamanını oluştur
    last_updated = f"Son Güncelleme: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    # Tarama dropdown seçeneklerini oluştur
    scan_options = [{'label': scan, 'value': scan} for scan in scan_list]

    return summary_table_data, vulnerability_distribution, vulnerability_table_data, top_vulnerabilities_table_data, total_vulnerabilities, last_updated, scan_options

if __name__ == '__main__':
    app.run_server(debug=True)

import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go
import pandas as pd
import pymysql
from datetime import datetime, timedelta
import dash_bootstrap_components as dbc

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
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
        {severity_condition} {scan_name_condition} {vulnerability_name_condition}
        GROUP BY 
            p.plugin_id, p.name, p.severity
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

    return summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data

# Dash uygulaması
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])

app.layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            html.H1("Nessus Tarama Sonuçları Gösterge Paneli", className="text-center mb-4"),
            html.Img(src="/assets/nessus_logo.png", style={'height': '50px', 'float': 'right'}),
        ], width=12)
    ], className="mb-4"),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Label("Severity:"),
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
                    ),
                ])
            ], className="mb-3"),
        ], width=4),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Label("Tarama Adı:"),
                    dcc.Input(id='scan-name-input', type='text', className="form-control"),
                ])
            ], className="mb-3"),
        ], width=4),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Label("Zafiyet Adı:"),
                    dcc.Input(id='vulnerability-name-input', type='text', className="form-control"),
                ])
            ], className="mb-3"),
        ], width=4),
    ]),

    dbc.Row([
        dbc.Col([
            dbc.Button('Filtrele', id='filter-button', color="primary", className="mt-2 mb-4"),
        ], width=12, className="text-center"),
    ]),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader(html.H3("Toplam Zafiyet Sayıları", className="text-center")),
                dbc.CardBody(id='total-vulnerabilities'),
            ], className="mb-4"),
        ], width=12),
    ]),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader(html.H3("Özet Bilgiler", className="text-center")),
                dbc.CardBody([
                    dash_table.DataTable(
                        id='summary-table',
                        columns=[
                            {"name": "Tarama Adı", "id": "scan_name"},
                            {"name": "Klasör Adı", "id": "folder_name"},
                            {"name": "Son Tarama Tarihi", "id": "last_scan_date"},
                            {"name": "Toplam Host", "id": "total_hosts"},
                            {"name": "Kritik", "id": "total_critical"},
                            {"name": "Yüksek", "id": "total_high"},
                            {"name": "Orta", "id": "total_medium"},
                            {"name": "Düşük", "id": "total_low"},
                            {"name": "Bilgi", "id": "total_info"}
                        ],
                        style_table={'overflowX': 'auto'},
                        style_cell={
                            'textAlign': 'left',
                            'padding': '5px',
                            'whiteSpace': 'normal',
                            'height': 'auto',
                        },
                        style_header={
                            'backgroundColor': 'rgb(30, 30, 30)',
                            'fontWeight': 'bold'
                        },
                        style_data={
                            'backgroundColor': 'rgb(50, 50, 50)',
                            'color': 'white'
                        },
                        sort_action="native",
                        sort_mode="multi",
                    ),
                ]),
            ], className="mb-4"),
        ], width=6),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader(html.H3("Zafiyet Dağılımı", className="text-center")),
                dbc.CardBody([
                    dcc.Graph(id='vulnerability-distribution')
                ]),
            ], className="mb-4"),
        ], width=6),
    ]),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader(html.H3("En Çok Görülen 10 Zafiyet", className="text-center")),
                dbc.CardBody([
                    dash_table.DataTable(
                        id='top-vulnerabilities-table',
                        columns=[{"name": i, "id": i} for i in ['vulnerability_name', 'severity', 'count']],
                        style_table={'overflowX': 'auto'},
                        style_cell={
                            'textAlign': 'left',
                            'padding': '5px',
                            'whiteSpace': 'normal',
                            'height': 'auto',
                        },
                        style_header={
                            'backgroundColor': 'rgb(30, 30, 30)',
                            'fontWeight': 'bold'
                        },
                        style_data={
                            'backgroundColor': 'rgb(50, 50, 50)',
                            'color': 'white'
                        },
                    ),
                ]),
            ], className="mb-4"),
        ], width=6),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader(html.H3("Detaylı Zafiyet Listesi", className="text-center")),
                dbc.CardBody([
                    dash_table.DataTable(
                        id='vulnerability-table',
                        columns=[{"name": i, "id": i} for i in ['scan_name', 'host_ip', 'vulnerability_name', 'severity', 'plugin_family', 'port', 'scan_date']],
                        style_table={'overflowX': 'auto'},
                        style_cell={
                            'textAlign': 'left',
                            'padding': '5px',
                            'whiteSpace': 'normal',
                            'height': 'auto',
                        },
                        style_header={
                            'backgroundColor': 'rgb(30, 30, 30)',
                            'fontWeight': 'bold'
                        },
                        style_data={
                            'backgroundColor': 'rgb(50, 50, 50)',
                            'color': 'white'
                        },
                        filter_action="native",
                        sort_action="native",
                        sort_mode="multi",
                        page_action="native",
                        page_current=0,
                        page_size=10,
                    )
                ]),
            ], className="mb-4"),
        ], width=6),
    ]),

    dcc.Interval(
        id='interval-component',
        interval=60*1000,  # Her 1 dakikada bir güncelle
        n_intervals=0
    )
], fluid=True)

@app.callback(
    [Output('summary-table', 'data'),
     Output('vulnerability-distribution', 'figure'),
     Output('vulnerability-table', 'data'),
     Output('top-vulnerabilities-table', 'data'),
     Output('total-vulnerabilities', 'children')],
    [Input('filter-button', 'n_clicks'),
     Input('interval-component', 'n_intervals')],
    [State('severity-dropdown', 'value'),
     State('scan-name-input', 'value'),
     State('vulnerability-name-input', 'value')]
)
def update_data(n_clicks, n_intervals, severity, scan_name, vulnerability_name):
    summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data = get_data(severity, scan_name, vulnerability_name)
    
    print("Summary Data:", summary_data)  # Debug için eklendi
    
    # Özet tablo verisi
    summary_table_data = [{
        'scan_name': row['scan_name'],
        'folder_name': row['folder_name'],
        'last_scan_date': row['last_scan_date'],
        'total_hosts': row['total_hosts'],
        'total_critical': row['total_critical'],
        'total_high': row['total_high'],
        'total_medium': row['total_medium'],
        'total_low': row['total_low'],
        'total_info': row['total_info']
    } for row in summary_data]
    
    # Zafiyet dağılımı grafiği
    vulnerability_distribution = {
        'data': [
            go.Pie(
                labels=['Critical', 'High', 'Medium', 'Low', 'Info'],
                values=[
                    sum(item['count'] for item in vulnerability_data if item['severity'] == 4),
                    sum(item['count'] for item in vulnerability_data if item['severity'] == 3),
                    sum(item['count'] for item in vulnerability_data if item['severity'] == 2),
                    sum(item['count'] for item in vulnerability_data if item['severity'] == 1),
                    sum(item['count'] for item in vulnerability_data if item['severity'] == 0)
                ],
                marker=dict(colors=['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#3498db'])
            )
        ],
        'layout': go.Layout(
            title='Zafiyet Dağılımı',
            paper_bgcolor='#2c3e50',
            plot_bgcolor='#2c3e50',
            font=dict(color='white')
        )
    }

    # Detaylı zafiyet listesi
    vulnerability_table_data = detailed_vulnerability_data
    
    # En çok görülen 10 zafiyet
    top_vulnerabilities_table_data = top_vulnerabilities_data
    
    # Toplam zafiyet sayıları
    total_vulnerabilities = [
        html.Div([
            html.H4("Kritik", style={'color': '#e74c3c'}),
            html.P(total_vulnerabilities_data['total_critical'])
        ]),
        html.Div([
            html.H4("Yüksek", style={'color': '#e67e22'}),
            html.P(total_vulnerabilities_data['total_high'])
        ]),
        html.Div([
            html.H4("Orta", style={'color': '#f1c40f'}),
            html.P(total_vulnerabilities_data['total_medium'])
        ]),
        html.Div([
            html.H4("Düşük", style={'color': '#2ecc71'}),
            html.P(total_vulnerabilities_data['total_low'])
        ]),
        html.Div([
            html.H4("Bilgi", style={'color': '#3498db'}),
            html.P(total_vulnerabilities_data['total_info'])
        ])
    ]
    
    return summary_table_data, vulnerability_distribution, vulnerability_table_data, top_vulnerabilities_table_data, total_vulnerabilities

if __name__ == '__main__':
    app.run_server(debug=True)

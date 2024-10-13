import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go
import pandas as pd
import pymysql
from datetime import datetime, timedelta
import math
import random

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

    return summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data

# Dash uygulaması
app = dash.Dash(__name__, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'])

app.layout = html.Div([
    html.Div([
        html.Img(src="/assets/nessus_logo.png", style={'height': '50px', 'float': 'left', 'margin-right': '20px'}),
        html.H1("Nessus Zafiyet Tarama Sonuçları", style={'color': 'white', 'margin': 0}),
        html.P(id='last-updated', style={'color': '#FFD700', 'float': 'right', 'margin-top': '10px'}),
    ], style={'backgroundColor': '#1e2130', 'padding': '20px', 'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center'}),

    html.Div([
        html.Div([
            html.H3("Toplam Zafiyetler", style={'color': '#FFD700'}),
            html.H2(id='total-vulnerabilities', style={'color': 'white', 'fontSize': '48px'}),
            html.P(id='new-vulnerabilities', style={'color': '#00FF00'}),
        ], className="three columns", style={'backgroundColor': '#2c3e50', 'padding': '20px', 'textAlign': 'center', 'borderRadius': '10px'}),

        html.Div([
            html.H3("Kritik Zafiyetler", style={'color': '#FF4136'}),
            html.H2(id='critical-vulnerabilities', style={'color': 'white', 'fontSize': '48px'}),
            html.P(id='new-critical-vulnerabilities', style={'color': '#00FF00'}),
        ], className="three columns", style={'backgroundColor': '#2c3e50', 'padding': '20px', 'textAlign': 'center', 'borderRadius': '10px'}),

        html.Div([
            html.H3("Yüksek Zafiyetler", style={'color': '#FF851B'}),
            html.H2(id='high-vulnerabilities', style={'color': 'white', 'fontSize': '48px'}),
            html.P(id='new-high-vulnerabilities', style={'color': '#00FF00'}),
        ], className="three columns", style={'backgroundColor': '#2c3e50', 'padding': '20px', 'textAlign': 'center', 'borderRadius': '10px'}),

        html.Div([
            html.H3("Orta Zafiyetler", style={'color': '#FFDC00'}),
            html.H2(id='medium-vulnerabilities', style={'color': 'white', 'fontSize': '48px'}),
            html.P(id='new-medium-vulnerabilities', style={'color': '#00FF00'}),
        ], className="three columns", style={'backgroundColor': '#2c3e50', 'padding': '20px', 'textAlign': 'center', 'borderRadius': '10px'}),
    ], className="row", style={'margin': '20px 0'}),

    html.Div([
        html.Div([
            html.Label("Tarama Seç:", style={'color': 'white'}),
            dcc.Dropdown(id='scan-dropdown', style={'backgroundColor': '#2c3e50', 'color': 'black'}),
        ], className="three columns"),

        html.Div([
            html.Label("Tarih Aralığı:", style={'color': 'white'}),
            dcc.DatePickerRange(id='date-range', style={'backgroundColor': '#2c3e50'}),
        ], className="six columns"),

        html.Div([
            html.Button('Filtrele', id='filter-button', style={'backgroundColor': '#e74c3c', 'color': 'white', 'marginTop': '20px'}),
        ], className="three columns"),
    ], className="row", style={'backgroundColor': '#1e2130', 'padding': '20px', 'borderRadius': '10px', 'margin': '20px 0'}),

    html.Div([
        html.Div([
            dcc.Graph(id='vulnerability-distribution')
        ], className="six columns", style={'backgroundColor': '#2c3e50', 'padding': '20px', 'borderRadius': '10px'}),

        html.Div([
            dcc.Graph(id='vulnerability-trend')
        ], className="six columns", style={'backgroundColor': '#2c3e50', 'padding': '20px', 'borderRadius': '10px'}),
    ], className="row"),

    html.Div([
        html.H3("En Çok Görülen 10 Zafiyet", style={'color': 'white', 'textAlign': 'center'}),
        dash_table.DataTable(
            id='top-vulnerabilities-table',
            style_table={'height': '300px', 'overflowY': 'auto'},
            style_cell={'backgroundColor': '#2c3e50', 'color': 'white'},
            style_header={'backgroundColor': '#e74c3c', 'fontWeight': 'bold'},
        )
    ], style={'backgroundColor': '#1e2130', 'padding': '20px', 'borderRadius': '10px', 'margin': '20px 0'}),

    dcc.Interval(
        id='interval-component',
        interval=60*1000,  # Her 1 dakikada bir güncelle
        n_intervals=0
    )
], style={'backgroundColor': '#1e2130', 'padding': '20px'})

@app.callback(
    [Output('total-vulnerabilities', 'children'),
     Output('critical-vulnerabilities', 'children'),
     Output('high-vulnerabilities', 'children'),
     Output('medium-vulnerabilities', 'children'),
     Output('new-vulnerabilities', 'children'),
     Output('new-critical-vulnerabilities', 'children'),
     Output('new-high-vulnerabilities', 'children'),
     Output('new-medium-vulnerabilities', 'children'),
     Output('vulnerability-distribution', 'figure'),
     Output('vulnerability-trend', 'figure'),
     Output('top-vulnerabilities-table', 'data'),
     Output('last-updated', 'children')],
    [Input('filter-button', 'n_clicks'),
     Input('interval-component', 'n_intervals')],
    [State('scan-dropdown', 'value'),
     State('date-range', 'start_date'),
     State('date-range', 'end_date')]
)
def update_data(n_clicks, n_intervals, selected_scan, start_date, end_date):
    # Burada veritabanından veri çekme ve işleme kodlarınız olacak
    # Örnek olarak bazı dummy veriler oluşturalım
    total_vulnerabilities = 1000
    critical_vulnerabilities = 200
    high_vulnerabilities = 300
    medium_vulnerabilities = 500
    new_vulnerabilities = "+50"
    new_critical_vulnerabilities = "+10"
    new_high_vulnerabilities = "+20"
    new_medium_vulnerabilities = "+20"

    # Zafiyet dağılımı grafiği
    vulnerability_distribution = {
        'data': [go.Pie(
            labels=['Kritik', 'Yüksek', 'Orta'],
            values=[critical_vulnerabilities, high_vulnerabilities, medium_vulnerabilities],
            hole=0.3
        )],
        'layout': go.Layout(title='Zafiyet Dağılımı')
    }

    # Zafiyet trendi grafiği
    vulnerability_trend = {
        'data': [go.Scatter(x=[1, 2, 3, 4, 5], y=[100, 150, 200, 180, 210], mode='lines+markers')],
        'layout': go.Layout(title='Zafiyet Trendi')
    }

    # En çok görülen 10 zafiyet
    top_vulnerabilities = [{'Zafiyet': f'Zafiyet {i}', 'Sayı': random.randint(50, 200)} for i in range(1, 11)]

    last_updated = f"Son Güncelleme: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    return (total_vulnerabilities, critical_vulnerabilities, high_vulnerabilities, medium_vulnerabilities,
            new_vulnerabilities, new_critical_vulnerabilities, new_high_vulnerabilities, new_medium_vulnerabilities,
            vulnerability_distribution, vulnerability_trend, top_vulnerabilities, last_updated)

if __name__ == '__main__':
    app.run_server(debug=True)

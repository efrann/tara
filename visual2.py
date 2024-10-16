import dash
from dash import dcc, html, dash_table, callback_context
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
def get_data(severity=None, scan_name=None, vulnerability_name=None, ip_address=None):
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

        # IP adresi filtresi için WHERE koşulu
        ip_address_condition = ""
        if ip_address:
            ip_address_condition = f"AND h.host_ip LIKE '%{ip_address}%'"

        # Özet bilgi sorgusu
        summary_query = f"""
        SELECT 
            s.name AS scan_name,
            f.name AS folder_name,
            MAX(FROM_UNIXTIME(sr.scan_start)) AS last_scan_date,
            COUNT(DISTINCT h.host_ip) AS total_hosts,
            SUM(CASE WHEN p.severity = 4 THEN 1 ELSE 0 END) AS total_critical,
            SUM(CASE WHEN p.severity = 3 THEN 1 ELSE 0 END) AS total_high,
            SUM(CASE WHEN p.severity = 2 THEN 1 ELSE 0 END) AS total_medium,
            SUM(CASE WHEN p.severity = 1 THEN 1 ELSE 0 END) AS total_low,
            SUM(CASE WHEN p.severity = 0 THEN 1 ELSE 0 END) AS total_info
        FROM 
            scan s
        LEFT JOIN 
            folder f ON s.folder_id = f.folder_id
        JOIN 
            scan_run sr ON s.scan_id = sr.scan_id
        JOIN
            host h ON sr.scan_run_id = h.scan_run_id
        LEFT JOIN 
            host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
        LEFT JOIN 
            plugin p ON hv.plugin_id = p.plugin_id
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
        {severity_condition}
        {scan_name_condition}
        {vulnerability_name_condition}
        {ip_address_condition}
        GROUP BY 
            s.name, f.name
        """
        
        # Severity seçimine göre sıralama ekliyoruz
        if severity:
            if 4 in severity:
                summary_query += " ORDER BY total_critical DESC"
            elif 3 in severity:
                summary_query += " ORDER BY total_high DESC"
            elif 2 in severity:
                summary_query += " ORDER BY total_medium DESC"
            elif 1 in severity:
                summary_query += " ORDER BY total_low DESC"
            elif 0 in severity:
                summary_query += " ORDER BY total_info DESC"
        else:
            summary_query += " ORDER BY last_scan_date DESC"
        
        cursor.execute(summary_query)
        summary_data = cursor.fetchall()
        
        # Tarih formatını değiştir
        for row in summary_data:
            if row['last_scan_date']:
                date = row['last_scan_date']
                turkish_months = ["Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", 
                                  "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"]
                row['last_scan_date'] = date.strftime(f"%d {turkish_months[date.month - 1]} %Y %H:%M")
        
        # Zafiyet dağılımı sorgusu
        vulnerability_query = f"""
        SELECT 
            p.severity,
            COUNT(DISTINCT hv.host_vuln_id) as count
        FROM 
            scan s
        JOIN 
            scan_run sr ON s.scan_id = sr.scan_id
        JOIN
            host h ON sr.scan_run_id = h.scan_run_id
        LEFT JOIN 
            host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
        LEFT JOIN 
            plugin p ON hv.plugin_id = p.plugin_id
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
        {severity_condition} {scan_name_condition} {vulnerability_name_condition} {ip_address_condition}
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
            CASE 
                WHEN p.severity = 4 THEN 'Kritik'
                WHEN p.severity = 3 THEN 'Yüksek'
                WHEN p.severity = 2 THEN 'Orta'
                WHEN p.severity = 1 THEN 'Düşük'
                WHEN p.severity = 0 THEN 'Bilgi'
                ELSE 'Bilinmeyen'
            END AS severity,
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
            host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
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
        {severity_condition} {scan_name_condition} {vulnerability_name_condition} {ip_address_condition}
        ORDER BY 
            sr.scan_start DESC, p.severity DESC
        LIMIT 1000
        """
        
        cursor.execute(detailed_vulnerability_query)
        detailed_vulnerability_data = cursor.fetchall()

        # Detaylı zafiyet listesindeki tarih formatını değiştir
        for row in detailed_vulnerability_data:
            if row['scan_date']:
                date = row['scan_date']
                turkish_months = ["Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", 
                                  "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"]
                row['scan_date'] = date.strftime(f"%d {turkish_months[date.month - 1]} %Y")

        # En çok görülen 10 zafiyet sorgusu
        top_vulnerabilities_query = f"""
        SELECT 
            f.name AS folder_name,
            s.name AS scan_name,
            COALESCE(p.name, 'Bilinmeyen Zafiyet') AS vulnerability_name,
            p.severity,
            COUNT(DISTINCT hv.host_vuln_id) as count
        FROM 
            scan s
        JOIN 
            scan_run sr ON s.scan_id = sr.scan_id
        JOIN
            host h ON sr.scan_run_id = h.scan_run_id
        LEFT JOIN 
            host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
        LEFT JOIN 
            plugin p ON hv.plugin_id = p.plugin_id
        JOIN
            folder f ON s.folder_id = f.folder_id
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
        {severity_condition} {scan_name_condition} {vulnerability_name_condition} {ip_address_condition}
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
            scan s
        JOIN 
            scan_run sr ON s.scan_id = sr.scan_id
        JOIN
            host h ON sr.scan_run_id = h.scan_run_id
        LEFT JOIN 
            host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
        LEFT JOIN 
            plugin p ON hv.plugin_id = p.plugin_id
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
        {severity_condition} {scan_name_condition} {vulnerability_name_condition} {ip_address_condition}
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

        # Port kullanım sorgusu
        port_usage_query = f"""
        SELECT 
            vo.port,
            COUNT(*) as count
        FROM 
            scan s
        JOIN 
            scan_run sr ON s.scan_id = sr.scan_id
        JOIN
            host h ON sr.scan_run_id = h.scan_run_id
        JOIN 
            host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
        JOIN 
            plugin p ON hv.plugin_id = p.plugin_id
        JOIN
            vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
        WHERE 
            sr.scan_run_id = (
                SELECT MAX(scan_run_id) 
                FROM scan_run 
                WHERE scan_id = s.scan_id
            )
            AND p.family = 'Port scanners'
            {severity_condition} {scan_name_condition} {vulnerability_name_condition} {ip_address_condition}
        GROUP BY 
            vo.port
        ORDER BY 
            count DESC
        LIMIT 10
        """
        
        cursor.execute(port_usage_query)
        port_usage_data = cursor.fetchall()

    return summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data, scan_list, port_usage_data

# Dash uygulaması
app = dash.Dash(__name__, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'])

app.layout = html.Div([
    # Header
    html.Div([
        html.H1("Nessus Tarama Sonuçları Gösterge Paneli", style={'textAlign': 'center', 'color': 'white', 'marginBottom': '0'}),
        html.Img(src="/assets/nessus_logo.png", style={'height': '50px', 'float': 'right', 'marginTop': '-50px'}),
    ], style={'backgroundColor': '#2c3e50', 'padding': '20px', 'boxShadow': '0 4px 8px 0 rgba(0,0,0,0.2)'}),

    # Last updated info
    html.Div([
        html.P(id='last-updated', style={'color': 'white', 'textAlign': 'right', 'margin': '5px 0'}),
        html.P("Bu sayfa her 1 dakikada bir otomatik olarak yenilenir.", style={'color': '#bdc3c7', 'textAlign': 'right', 'fontStyle': 'italic', 'margin': '5px 0'}),
    ], style={'backgroundColor': '#34495e', 'padding': '10px', 'borderRadius': '0 0 10px 10px'}),

    # Filters
    html.Div([
        html.Div([
            html.Label("Önem Derecesi:", style={'color': 'white', 'marginBottom': '5px', 'display': 'block'}),
            dcc.Dropdown(
                id='severity-dropdown',
                options=[
                    {'label': 'Kritik', 'value': 4},
                    {'label': 'Yüksek', 'value': 3},
                    {'label': 'Orta', 'value': 2},
                    {'label': 'Düşük', 'value': 1},
                    {'label': 'Bilgi', 'value': 0}
                ],
                multi=True,
                placeholder="Seçiniz...",
                style={'width': '100%', 'backgroundColor': '#34495e', 'color': 'black'}
            ),
        ], style={'display': 'inline-block', 'verticalAlign': 'top', 'marginRight': '20px', 'width': '20%'}),
        html.Div([
            html.Label("Tarama Seç:", style={'color': 'white', 'marginBottom': '5px', 'display': 'block'}),
            dcc.Dropdown(
                id='scan-dropdown',
                options=[],
                placeholder="Seçiniz...",
                style={'width': '100%', 'backgroundColor': '#34495e', 'color': 'black'}
            ),
        ], style={'display': 'inline-block', 'verticalAlign': 'top', 'marginRight': '20px', 'width': '20%'}),
        html.Div([
            html.Label("Zafiyet Adı:", style={'color': 'white', 'marginBottom': '5px', 'display': 'block'}),
            dcc.Input(
                id='vulnerability-name-input',
                type='text',
                placeholder="Zafiyet adı girin...",
                style={'width': '100%', 'backgroundColor': '#34495e', 'color': 'white', 'border': '1px solid #3498db', 'borderRadius': '5px', 'padding': '8px'}
            ),
        ], style={'display': 'inline-block', 'verticalAlign': 'top', 'marginRight': '20px', 'width': '20%'}),
        html.Div([
            html.Label("IP Adresi:", style={'color': 'white', 'marginBottom': '5px', 'display': 'block'}),
            dcc.Input(
                id='ip-address-input',
                type='text',
                placeholder="IP adresi girin...",
                style={'width': '100%', 'backgroundColor': '#34495e', 'color': 'white', 'border': '1px solid #3498db', 'borderRadius': '5px', 'padding': '8px'}
            ),
        ], style={'display': 'inline-block', 'verticalAlign': 'top', 'marginRight': '20px', 'width': '20%'}),
        html.Button('Filtrele', id='filter-button', n_clicks=0, style={
            'marginTop': '25px',
            'backgroundColor': '#3498db',
            'color': 'white',
            'border': 'none',
            'padding': '10px 20px',
            'borderRadius': '5px',
            'cursor': 'pointer',
            'transition': 'background-color 0.3s',
        }),
    ], style={'backgroundColor': '#2c3e50', 'padding': '20px', 'marginTop': '20px', 'borderRadius': '10px', 'boxShadow': '0 4px 8px 0 rgba(0,0,0,0.2)'}),

    # Total Vulnerabilities
    html.Div([
        html.H3("Toplam Zafiyet Sayıları", style={'textAlign': 'center', 'color': 'white', 'marginBottom': '20px'}),
        html.Div([
            html.Div(id='severity-4', n_clicks=0),
            html.Div(id='severity-3', n_clicks=0),
            html.Div(id='severity-2', n_clicks=0),
            html.Div(id='severity-1', n_clicks=0),
            html.Div(id='severity-0', n_clicks=0),
        ], id='total-vulnerabilities', style={'display': 'flex', 'justifyContent': 'space-around', 'flexWrap': 'wrap'}),
    ], style={'backgroundColor': '#34495e', 'padding': '20px', 'margin': '20px 0', 'borderRadius': '10px', 'boxShadow': '0 4px 8px 0 rgba(0,0,0,0.2)'}),

    # Graphs
    html.Div([
        html.Div([
            dcc.Graph(id='vulnerability-distribution', style={'height': '400px'})
        ], className="four columns"),

        html.Div([
            dcc.Graph(id='top-vulnerabilities-graph', style={'height': '400px'})
        ], className="four columns"),

        html.Div([
            dcc.Graph(id='port-usage-graph', style={'height': '400px'})
        ], className="four columns"),
    ], className="row", style={'backgroundColor': '#2c3e50', 'padding': '20px', 'margin': '20px 0', 'borderRadius': '10px', 'boxShadow': '0 4px 8px 0 rgba(0,0,0,0.2)'}),

    # Tables
    html.Div([
        html.Div([
            html.H3("Özet Bilgiler", style={
                'textAlign': 'center', 
                'color': '#ecf0f1', 
                'backgroundColor': '#34495e', 
                'padding': '10px', 
                'marginBottom': '20px',
                'borderRadius': '5px',
            }),
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
                style_table={'height': '300px', 'overflowY': 'auto'},
                style_cell={
                    'backgroundColor': '#34495e',
                    'color': '#ecf0f1',
                    'border': '1px solid #2c3e50',
                    'textAlign': 'left',
                    'padding': '10px',
                    'whiteSpace': 'normal',
                    'height': 'auto',
                },
                style_header={
                    'backgroundColor': '#2c3e50',
                    'fontWeight': 'bold',
                    'border': '1px solid #34495e',
                    'color': '#3498db',
                },
                style_data_conditional=[
                    {
                        'if': {'column_id': 'total_critical'},
                        'backgroundColor': 'rgba(231, 76, 60, 0.1)',
                        'color': '#e74c3c',
                        'fontWeight': 'bold',
                        'textShadow': '0px 0px 1px #000000'
                    },
                    {
                        'if': {'column_id': 'total_high'},
                        'backgroundColor': 'rgba(230, 126, 34, 0.1)',
                        'color': '#e67e22',
                        'fontWeight': 'bold',
                        'textShadow': '0px 0px 1px #000000'
                    },
                    {
                        'if': {'column_id': 'total_medium'},
                        'backgroundColor': 'rgba(241, 196, 15, 0.1)',
                        'color': '#f1c40f',
                        'fontWeight': 'bold',
                        'textShadow': '0px 0px 1px #000000'
                    },
                    {
                        'if': {'column_id': 'total_low'},
                        'backgroundColor': 'rgba(46, 204, 113, 0.1)',
                        'color': '#2ecc71',
                        'fontWeight': 'bold',
                        'textShadow': '0px 0px 1px #000000'
                    },
                    {
                        'if': {'column_id': 'total_info'},
                        'backgroundColor': 'rgba(52, 152, 219, 0.1)',
                        'color': '#3498db',
                        'fontWeight': 'bold',
                        'textShadow': '0px 0px 1px #000000'
                    }
                ],
            ),
        ], className="six columns"),

        html.Div([
            html.H3("En Çok Görülen 10 Zafiyet", style={
                'textAlign': 'center', 
                'color': '#ecf0f1', 
                'backgroundColor': '#34495e', 
                'padding': '10px', 
                'marginBottom': '20px',
                'borderRadius': '5px',
            }),
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
                style_cell={
                    'backgroundColor': '#34495e',
                    'color': '#ecf0f1',
                    'border': '1px solid #2c3e50',
                    'textAlign': 'left',
                    'padding': '10px',
                    'whiteSpace': 'normal',
                    'height': 'auto',
                },
                style_header={
                    'backgroundColor': '#2c3e50',
                    'fontWeight': 'bold',
                    'border': '1px solid #34495e',
                    'color': '#3498db',
                },
                style_data_conditional=[
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Kritik"'},
                        'backgroundColor': 'rgba(231, 76, 60, 0.1)',
                        'color': '#e74c3c',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Yüksek"'},
                        'backgroundColor': 'rgba(230, 126, 34, 0.1)',
                        'color': '#e67e22',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Orta"'},
                        'backgroundColor': 'rgba(241, 196, 15, 0.1)',
                        'color': '#f1c40f',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Düşük"'},
                        'backgroundColor': 'rgba(46, 204, 113, 0.1)',
                        'color': '#2ecc71',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Bilgi"'},
                        'backgroundColor': 'rgba(52, 152, 219, 0.1)',
                        'color': '#3498db',
                        'fontWeight': 'bold',
                    }
                ],
            ),
        ], className="six columns"),
    ], className="row", style={'backgroundColor': '#2c3e50', 'padding': '20px', 'margin': '20px 0', 'borderRadius': '10px', 'boxShadow': '0 4px 8px 0 rgba(0,0,0,0.2)'}),

    html.Div([
        html.Div([
            html.H3("Detaylı Zafiyet Listesi", style={
                'textAlign': 'center', 
                'color': '#ecf0f1', 
                'backgroundColor': '#34495e', 
                'padding': '10px', 
                'marginBottom': '20px',
                'borderRadius': '5px',
            }),
            dash_table.DataTable(
                id='vulnerability-table',
                columns=[
                    {"name": "Tarama Adı", "id": "scan_name"},
                    {"name": "Host IP", "id": "host_ip"},
                    {"name": "Zafiyet Adı", "id": "vulnerability_name"},
                    {"name": "Önem Derecesi", "id": "severity"},
                    {"name": "Plugin Ailesi", "id": "plugin_family"},
                    {"name": "Port", "id": "port"},
                    {"name": "Tarama Tarihi", "id": "scan_date"}
                ],
                style_table={'height': '300px', 'overflowY': 'auto'},
                style_cell={
                    'backgroundColor': '#34495e',
                    'color': '#ecf0f1',
                    'border': '1px solid #2c3e50',
                    'textAlign': 'left',
                    'padding': '10px',
                    'whiteSpace': 'normal',
                    'height': 'auto',
                },
                style_header={
                    'backgroundColor': '#2c3e50',
                    'fontWeight': 'bold',
                    'border': '1px solid #34495e',
                    'color': '#3498db',
                },
                style_data_conditional=[
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Kritik"'},
                        'backgroundColor': 'rgba(231, 76, 60, 0.1)',
                        'color': '#e74c3c',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Yüksek"'},
                        'backgroundColor': 'rgba(230, 126, 34, 0.1)',
                        'color': '#e67e22',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Orta"'},
                        'backgroundColor': 'rgba(241, 196, 15, 0.1)',
                        'color': '#f1c40f',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Düşük"'},
                        'backgroundColor': 'rgba(46, 204, 113, 0.1)',
                        'color': '#2ecc71',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity', 'filter_query': '{severity} = "Bilgi"'},
                        'backgroundColor': 'rgba(52, 152, 219, 0.1)',
                        'color': '#3498db',
                        'fontWeight': 'bold',
                    }
                ],
            )
        ], className="twelve columns"),
    ], className="row", style={'backgroundColor': '#2c3e50', 'padding': '20px', 'margin': '20px 0', 'borderRadius': '10px', 'boxShadow': '0 4px 8px 0 rgba(0,0,0,0.2)'}),

    dcc.Interval(
        id='interval-component',
        interval=60*1000,  # Her 1 dakikada bir güncelle
        n_intervals=0
    ),

    # Hidden div for storing clicked severity
    html.Div(id='clicked-severity', style={'display': 'none'}),

    # Tıklanan port için gizli div
    html.Div(id='clicked-port', style={'display': 'none'}),
])

@app.callback(
    [Output('summary-table', 'data'),
     Output('vulnerability-distribution', 'figure'),
     Output('vulnerability-table', 'data'),
     Output('top-vulnerabilities-table', 'data'),
     Output('top-vulnerabilities-graph', 'figure'),
     Output('port-usage-graph', 'figure'),
     Output('severity-4', 'children'),
     Output('severity-3', 'children'),
     Output('severity-2', 'children'),
     Output('severity-1', 'children'),
     Output('severity-0', 'children'),
     Output('last-updated', 'children'),
     Output('scan-dropdown', 'options'),
     Output('severity-dropdown', 'value')],
    [Input('filter-button', 'n_clicks'),
     Input('interval-component', 'n_intervals'),
     Input('clicked-severity', 'children'),
     Input('clicked-port', 'children')],
    [State('severity-dropdown', 'value'),
     State('scan-dropdown', 'value'),
     State('vulnerability-name-input', 'value'),
     State('ip-address-input', 'value')]
)
def update_data(n_clicks, n_intervals, clicked_severity, clicked_port, severity, scan_name, vulnerability_name, ip_address):
    ctx = dash.callback_context
    if not ctx.triggered:
        button_id = 'No clicks yet'
    else:
        button_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if button_id == 'clicked-severity' and clicked_severity:
        severity = [int(clicked_severity)]
    
    if button_id == 'clicked-port' and clicked_port:
        ip_address = None  # Reset IP address filter when port is clicked
        vulnerability_name = f"Port {clicked_port}"  # Filter by port in vulnerability name

    summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data, scan_list, port_usage_data = get_data(severity, scan_name, vulnerability_name, ip_address)
    
    #print("Summary Data:", summary_data)  # Debug için eklendi
    
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
    
    # Severity seçimine göre sıralama
    if severity:
        if 4 in severity:
            summary_table_data = sorted(summary_table_data, key=lambda x: x['total_critical'], reverse=True)
        elif 3 in severity:
            summary_table_data = sorted(summary_table_data, key=lambda x: x['total_high'], reverse=True)
        elif 2 in severity:
            summary_table_data = sorted(summary_table_data, key=lambda x: x['total_medium'], reverse=True)
        elif 1 in severity:
            summary_table_data = sorted(summary_table_data, key=lambda x: x['total_low'], reverse=True)
        elif 0 in severity:
            summary_table_data = sorted(summary_table_data, key=lambda x: x['total_info'], reverse=True)
    
    # Zafiyet dağılımı grafiği
    labels = ['Total', 'Critical', 'High', 'Medium', 'Low']
    parents = ['', 'Total', 'Total', 'Total', 'Total']
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
            margin=dict(t=0, l=0, r=0, b=0),
            height=400,
            showlegend=False
        )
    }

    # Detaylı zafiyet listesi
    vulnerability_table_data = detailed_vulnerability_data
    
    # En çok görülen 10 zafiyet
    severity_map = {
        4: 'Kritik',
        3: 'Yüksek',
        2: 'Orta',
        1: 'Düşük',
        0: 'Bilgi'
    }
    
    top_vulnerabilities_table_data = [{
        'folder_name': row['folder_name'],
        'scan_name': row['scan_name'],
        'vulnerability_name': row['vulnerability_name'],
        'severity': severity_map[row['severity']],
        'count': row['count']
    } for row in top_vulnerabilities_data]
    
    # Toplam zafiyet sayıları
    severity_info = [
        {"name": "Kritik", "color": "#e74c3c", "key": "total_critical", "value": 4},
        {"name": "Yüksek", "color": "#e67e22", "key": "total_high", "value": 3},
        {"name": "Orta", "color": "#f1c40f", "key": "total_medium", "value": 2},
        {"name": "Düşük", "color": "#2ecc71", "key": "total_low", "value": 1},
        {"name": "Bilgi", "color": "#3498db", "key": "total_info", "value": 0}
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
            'boxShadow': '0 4px 8px 0 rgba(0,0,0,0.2)',
            'cursor': 'pointer'
        })
        for info in severity_info
    ]
    
    # Son güncelleme zamanını oluştur
    last_updated = f"Son Güncelleme: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    # Tarama dropdown seçeneklerini oluştur
    scan_options = [{'label': scan, 'value': scan} for scan in scan_list]

    # Veri kontrolü
    if not top_vulnerabilities_data:
        # Eğer veri yoksa, boş bir grafik döndür
        top_vulnerabilities_graph = go.Figure()
        top_vulnerabilities_graph.add_annotation(text="Veri bulunamadı", showarrow=False)
        return summary_table_data, vulnerability_distribution, vulnerability_table_data, top_vulnerabilities_table_data, top_vulnerabilities_graph, total_vulnerabilities[0], total_vulnerabilities[1], total_vulnerabilities[2], total_vulnerabilities[3], total_vulnerabilities[4], last_updated, scan_options, severity if severity is not None else dash.no_update

    # En çok görülen 10 zafiyet daire grafiği
    top_vulnerabilities_graph = go.Figure(
        go.Sunburst(
            ids=['Most Occurent 10 Vulnerabilities'] + [f"vuln_{i}" for i in range(len(top_vulnerabilities_data))],
            labels=['Most Occurent 10 Vulnerabilities'] + [f"{row['vulnerability_name'][:20]}..." if len(row['vulnerability_name']) > 20 else row['vulnerability_name'] for row in top_vulnerabilities_data],
            parents=[''] + ['Most Occurent 10 Vulnerabilities'] * len(top_vulnerabilities_data),
            values=[sum(row['count'] for row in top_vulnerabilities_data)] + [row['count'] for row in top_vulnerabilities_data],
            branchvalues="total",
            marker=dict(
                colors=['#2c3e50'] + [
                    '#e74c3c' if row['severity'] == 4 else
                    '#e67e22' if row['severity'] == 3 else
                    '#f1c40f' if row['severity'] == 2 else
                    '#2ecc71' if row['severity'] == 1 else
                    '#3498db' if row['severity'] == 0 else
                    '#95a5a6' for row in top_vulnerabilities_data
                ]
            ),
            textinfo='label',
            hovertemplate='<b>%{customdata}</b><br>Count: %{value}<br><extra></extra>',
            insidetextorientation='radial',
            textfont=dict(size=10, color='white'),
            customdata=['Most Occurent 10 Vulnerabilities'] + [row['vulnerability_name'] for row in top_vulnerabilities_data],
        )
    )

    top_vulnerabilities_graph.update_layout(
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor='#2c3e50',
        plot_bgcolor='#34495e',
        font=dict(color='white', size=14),
        height=400,
        showlegend=False,
    )

    # Port kullanım grafiği
    port_usage_graph = go.Figure(
        go.Bar(
            x=[str(row['port']) for row in port_usage_data],
            y=[row['count'] for row in port_usage_data],
            marker_color='#3498db',
            text=[row['count'] for row in port_usage_data],
            textposition='auto',
            hoverinfo='text',
            hovertext=[f"Port: {row['port']}<br>Kullanım: {row['count']}" for row in port_usage_data],
        )
    )

    port_usage_graph.update_layout(
        title='En Çok Kullanılan 10 Port',
        xaxis_title='Port Numarası',
        yaxis_title='Kullanım Sayısı',
        paper_bgcolor='#2c3e50',
        plot_bgcolor='#34495e',
        font=dict(color='white'),
        margin=dict(l=50, r=50, t=50, b=50),
        height=400,
    )

    return (summary_table_data, vulnerability_distribution, vulnerability_table_data, 
            top_vulnerabilities_table_data, top_vulnerabilities_graph, 
            port_usage_graph,
            total_vulnerabilities[0], total_vulnerabilities[1], total_vulnerabilities[2], 
            total_vulnerabilities[3], total_vulnerabilities[4], 
            last_updated, scan_options, severity if severity is not None else dash.no_update)

# Combine the two callbacks into one
@app.callback(
    Output('clicked-severity', 'children'),
    [Input(f'severity-{i}', 'n_clicks') for i in range(5)] +
    [Input('vulnerability-distribution', 'clickData')],
    [State('severity-dropdown', 'value')]
)
def update_clicked_severity(*args):
    ctx = dash.callback_context
    if not ctx.triggered:
        return dash.no_update
    
    triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]
    current_severity = args[-1]

    if 'severity-' in triggered_id:
        clicked_severity = triggered_id.split('-')[1]
        if current_severity and int(clicked_severity) in current_severity:
            return None
        return clicked_severity
    elif triggered_id == 'vulnerability-distribution':
        clickData = args[-2]  # clickData is the second to last argument
        if not clickData:
            return dash.no_update
        
        clicked_label = clickData['points'][0]['label']
        severity_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        
        if clicked_label in severity_map:
            clicked_severity = severity_map[clicked_label]
            if current_severity and clicked_severity in current_severity:
                return None
            return str(clicked_severity)
    
    return dash.no_update

# Add a new callback for button hover effect
@app.callback(
    Output('filter-button', 'style'),
    [Input('filter-button', 'n_clicks')]
)
def update_button_style(n_clicks):
    changed_id = [p['prop_id'] for p in callback_context.triggered][0]
    if 'filter-button' in changed_id:
        return {
            'marginTop': '25px',
            'backgroundColor': '#2980b9',
            'color': 'white',
            'border': 'none',
            'padding': '10px 20px',
            'borderRadius': '5px',
            'cursor': 'pointer',
            'transition': 'background-color 0.3s',
        }
    else:
        return {
            'marginTop': '25px',
            'backgroundColor': '#3498db',
            'color': 'white',
            'border': 'none',
            'padding': '10px 20px',
            'borderRadius': '5px',
            'cursor': 'pointer',
            'transition': 'background-color 0.3s',
        }

@app.callback(
    Output('clicked-port', 'children'),
    [Input('port-usage-graph', 'clickData')]
)
def update_clicked_port(clickData):
    if clickData is not None:
        return clickData['points'][0]['x']
    return None

if __name__ == '__main__':
    app.run_server(debug=True)

import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go
import pandas as pd
import pymysql
from datetime import datetime, timedelta
import math
from pymysql.cursors import DictCursor
from contextlib import contextmanager
import urllib.parse

@contextmanager
def get_db_connection():
    connection = pymysql.connect(
        host="localhost",
        user="root",
        password="Nessus_Report123*-",
        database="nessusdb",
        cursorclass=DictCursor
    )
    try:
        yield connection
    finally:
        connection.close()

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

# Verileri çekme fonksiyonu
def get_data(severity=None, scan_name=None, vulnerability_name=None, ip_address=None, port=None):
    with get_db_connection() as connection:
        with connection.cursor() as cursor:
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

            # Port filtresi için WHERE koşulu
            port_condition = parse_port_input(port)

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
            LEFT JOIN
                vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
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
            {port_condition}
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
            
            # Zafiyet dağılımı sorgusu (bu sorgu grafik için kullanılıyor)
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
            LEFT JOIN
                vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
            WHERE 
                sr.scan_run_id = (
                    SELECT MAX(scan_run_id) 
                    FROM scan_run 
                    WHERE scan_id = s.scan_id
                )
            {severity_condition} {scan_name_condition} {vulnerability_name_condition} {ip_address_condition} {port_condition}
            GROUP BY 
                p.severity
            """
            
            cursor.execute(vulnerability_query)
            vulnerability_data = cursor.fetchall()

            # Toplam zafiyet sayıları sorgusu (grafik verilerini kullanarak)
            total_vulnerabilities_data = {
                'total_critical': next((item['count'] for item in vulnerability_data if item['severity'] == 4), 0),
                'total_high': next((item['count'] for item in vulnerability_data if item['severity'] == 3), 0),
                'total_medium': next((item['count'] for item in vulnerability_data if item['severity'] == 2), 0),
                'total_low': next((item['count'] for item in vulnerability_data if item['severity'] == 1), 0),
                'total_info': next((item['count'] for item in vulnerability_data if item['severity'] == 0), 0)
            }

            # Detaylı zafiyet listesi sorgusunu güncelleyelim
            detailed_vulnerability_query = f"""
            SELECT 
                s.name AS scan_name,
                h.host_ip,
                h.host_fqdn,
                COALESCE(p.name, 'Bilinmeyen Zafiyet') AS vulnerability_name,
                p.severity,
                CASE 
                    WHEN p.severity = 4 THEN 'Kritik'
                    WHEN p.severity = 3 THEN 'Yüksek'
                    WHEN p.severity = 2 THEN 'Orta'
                    WHEN p.severity = 1 THEN 'Düşük'
                    WHEN p.severity = 0 THEN 'Bilgi'
                    ELSE 'Bilinmeyen'
                END AS severity_text,
                p.family AS plugin_family,
                vo.port,
                p.cvss3_base_score,
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
            {severity_condition} {scan_name_condition} {vulnerability_name_condition} {ip_address_condition} {port_condition}
            ORDER BY 
                p.severity DESC, sr.scan_start DESC
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
            LEFT JOIN
                vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
            WHERE 
                sr.scan_run_id = (
                    SELECT MAX(scan_run_id) 
                    FROM scan_run 
                    WHERE scan_id = s.scan_id
                )
            {severity_condition} {scan_name_condition} {vulnerability_name_condition} {ip_address_condition} {port_condition}
            GROUP BY 
                f.name, s.name, p.plugin_id, p.name, p.severity
            ORDER BY 
                count DESC
            LIMIT 10
            """
            
            cursor.execute(top_vulnerabilities_query)
            top_vulnerabilities_data = cursor.fetchall()

            # Mevcut taramaları çekmek için yeni bir sorgu ekleyelim
            scan_list_query = """
            SELECT DISTINCT s.name
            FROM scan s
            JOIN scan_run sr ON s.scan_id = sr.scan_id
            ORDER BY s.name
            """
            cursor.execute(scan_list_query)
            scan_list = [row['name'] for row in cursor.fetchall()]

            # En çok kullanılan 10 port sorgusu
            top_ports_query = f"""
            SELECT 
                vo.port,
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
            LEFT JOIN
                vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
            WHERE 
                sr.scan_run_id = (
                    SELECT MAX(scan_run_id) 
                    FROM scan_run 
                    WHERE scan_id = s.scan_id
                )
                AND vo.port IS NOT NULL
            {severity_condition} {scan_name_condition} {vulnerability_name_condition} {ip_address_condition} {port_condition}
            GROUP BY 
                vo.port
            ORDER BY 
                count DESC
            LIMIT 10
            """
            
            cursor.execute(top_ports_query)
            top_ports_data = cursor.fetchall()

            # IP'ye özgü port bilgilerini çeken yeni sorgu
            ip_ports_query = f"""
            SELECT DISTINCT vo.port
            FROM host h
            JOIN host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
            JOIN vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
            WHERE h.host_ip = %s
            ORDER BY vo.port
            """
            
            ip_ports_data = []
            if ip_address:
                cursor.execute(ip_ports_query, (ip_address,))
                ip_ports_data = cursor.fetchall()

    return summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data, scan_list, top_ports_data, ip_ports_data

# Dash uygulaması
app = dash.Dash(__name__, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'], suppress_callback_exceptions=True)

# Ana sayfa layout'u
def get_main_layout():
    return html.Div([
        html.H1("Nessus Zafiyet Analizi", style={'textAlign': 'center', 'color': 'white'}),
        
        # Severity sayıları
        html.Div([
            html.Div([
                html.H3("Kritik", style={'color': '#e74c3c'}),
                html.H2(id='critical-count', style={'color': '#e74c3c'}),
                dcc.Link("Detaylı Analiz", href='/detailed-analysis?severity=4', target='_blank')
            ], style={'textAlign': 'center', 'flex': 1}),
            html.Div([
                html.H3("Yüksek", style={'color': '#e67e22'}),
                html.H2(id='high-count', style={'color': '#e67e22'}),
                dcc.Link("Detaylı Analiz", href='/detailed-analysis?severity=3', target='_blank')
            ], style={'textAlign': 'center', 'flex': 1}),
            html.Div([
                html.H3("Orta", style={'color': '#f1c40f'}),
                html.H2(id='medium-count', style={'color': '#f1c40f'}),
                dcc.Link("Detaylı Analiz", href='/detailed-analysis?severity=2', target='_blank')
            ], style={'textAlign': 'center', 'flex': 1}),
            html.Div([
                html.H3("Düşük", style={'color': '#2ecc71'}),
                html.H2(id='low-count', style={'color': '#2ecc71'}),
                dcc.Link("Detaylı Analiz", href='/detailed-analysis?severity=1', target='_blank')
            ], style={'textAlign': 'center', 'flex': 1}),
            html.Div([
                html.H3("Bilgi", style={'color': '#3498db'}),
                html.H2(id='info-count', style={'color': '#3498db'}),
                dcc.Link("Detaylı Analiz", href='/detailed-analysis?severity=0', target='_blank')
            ], style={'textAlign': 'center', 'flex': 1}),
        ], style={'display': 'flex', 'justifyContent': 'space-between', 'marginBottom': '20px'}),
        
        # Grafikler
        html.Div([
            dcc.Graph(id='vulnerability-distribution', style={'width': '50%'}),
            dcc.Graph(id='top-vulnerabilities-graph', style={'width': '50%'})
        ], style={'display': 'flex'}),
        
        # Özet tablo
        html.H2("Özet Bilgiler", style={'color': 'white'}),
        dash_table.DataTable(id='summary-table'),
        
        # En çok görülen 10 zafiyet
        html.H2("En Çok Görülen 10 Zafiyet", style={'color': 'white'}),
        dash_table.DataTable(id='top-vulnerabilities-table'),
        
        dcc.Interval(
            id='interval-component',
            interval=300*1000,  # 5 dakikada bir güncelle
            n_intervals=0
        ),
    ], style={'backgroundColor': '#2c3e50', 'padding': '20px', 'color': 'white'})

# Detaylı analiz sayfası layout'u
def get_detailed_analysis_layout():
    return html.Div([
        html.H1("Detaylı Zafiyet Analizi", style={'textAlign': 'center', 'color': 'white'}),
        dcc.Input(
            id='search-input',
            type='text',
            placeholder='Ara...',
            style={'width': '100%', 'marginBottom': '10px', 'backgroundColor': '#34495e', 'color': 'white'}
        ),
        dash_table.DataTable(id='detailed-vulnerability-table')
    ], style={'backgroundColor': '#2c3e50', 'padding': '20px'})

# Ana uygulama layout'u
app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content')
])

# URL'ye göre sayfa içeriğini güncelleyelim
@app.callback(Output('page-content', 'children'),
              [Input('url', 'pathname')])
def display_page(pathname):
    if pathname == '/detailed-analysis':
        return get_detailed_analysis_layout()
    else:
        return get_main_layout()

# Ana sayfa için callback'ler
@app.callback(
    [Output('critical-count', 'children'),
     Output('high-count', 'children'),
     Output('medium-count', 'children'),
     Output('low-count', 'children'),
     Output('info-count', 'children'),
     Output('vulnerability-distribution', 'figure'),
     Output('top-vulnerabilities-graph', 'figure'),
     Output('summary-table', 'data'),
     Output('summary-table', 'columns'),
     Output('top-vulnerabilities-table', 'data'),
     Output('top-vulnerabilities-table', 'columns')],
    [Input('interval-component', 'n_intervals')]
)
def update_main_page(n):
    # Verileri çek
    summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data, scan_list, top_ports_data, ip_ports_data = get_data()
    
    # Severity sayıları
    critical_count = total_vulnerabilities_data['total_critical']
    high_count = total_vulnerabilities_data['total_high']
    medium_count = total_vulnerabilities_data['total_medium']
    low_count = total_vulnerabilities_data['total_low']
    info_count = total_vulnerabilities_data['total_info']
    
    # Vulnerability distribution grafiği
    vulnerability_distribution = go.Figure(data=[go.Pie(
        labels=['Kritik', 'Yüksek', 'Orta', 'Düşük', 'Bilgi'],
        values=[critical_count, high_count, medium_count, low_count, info_count],
        marker_colors=['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#3498db']
    )])
    vulnerability_distribution.update_layout(
        title_text="Zafiyet Dağılımı",
        paper_bgcolor='#2c3e50',
        plot_bgcolor='#2c3e50',
        font=dict(color='white')
    )
    
    # Top vulnerabilities grafiği
    top_vulnerabilities = go.Figure(data=[go.Bar(
        x=[vuln['vulnerability_name'] for vuln in top_vulnerabilities_data[:10]],
        y=[vuln['count'] for vuln in top_vulnerabilities_data[:10]],
        marker_color='#3498db'
    )])
    top_vulnerabilities.update_layout(
        title_text="En Çok Görülen 10 Zafiyet",
        xaxis_title="Zafiyet Adı",
        yaxis_title="Sayı",
        paper_bgcolor='#2c3e50',
        plot_bgcolor='#2c3e50',
        font=dict(color='white')
    )
    
    # Özet tablo
    summary_columns = [{"name": i, "id": i} for i in summary_data[0].keys()]
    
    # Top vulnerabilities tablo
    top_vulnerabilities_columns = [{"name": i, "id": i} for i in top_vulnerabilities_data[0].keys()]
    
    return (
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        vulnerability_distribution,
        top_vulnerabilities,
        summary_data,
        summary_columns,
        top_vulnerabilities_data[:10],
        top_vulnerabilities_columns
    )

# Detaylı analiz sayfası için callback
@app.callback(
    [Output('detailed-vulnerability-table', 'data'),
     Output('detailed-vulnerability-table', 'columns')],
    [Input('url', 'search')]
)
def update_detailed_table(search):
    parsed = urllib.parse.urlparse(search)
    severity = urllib.parse.parse_qs(parsed.query).get('severity', [None])[0]
    
    if severity is not None:
        severity = [int(severity)]
        summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data, scan_list, top_ports_data, ip_ports_data = get_data(severity=severity)
        
        # Detaylı zafiyet listesini severity'ye göre sırala ve severity_text'i ekle
        detailed_vulnerability_data = sorted(detailed_vulnerability_data, key=lambda x: x['severity'], reverse=True)
        for item in detailed_vulnerability_data:
            if item['severity'] == 4:
                item['severity_text'] = 'Kritik'
            elif item['severity'] == 3:
                item['severity_text'] = 'Yüksek'
            elif item['severity'] == 2:
                item['severity_text'] = 'Orta'
            elif item['severity'] == 1:
                item['severity_text'] = 'Düşük'
            elif item['severity'] == 0:
                item['severity_text'] = 'Bilgi'
            else:
                item['severity_text'] = 'Bilinmeyen'
        
        columns = [{"name": i, "id": i} for i in detailed_vulnerability_data[0].keys()]
        return detailed_vulnerability_data, columns
    return [], []

# Arama işlevi için callback
@app.callback(
    Output('detailed-vulnerability-table', 'filter_query'),
    [Input('search-input', 'value')]
)
def update_table_filter(search_value):
    if search_value:
        return f'{{vulnerability_name}} contains "{search_value}" || {{host_ip}} contains "{search_value}" || {{host_fqdn}} contains "{search_value}"'
    return ''

if __name__ == '__main__':
    app.run_server(debug=True)

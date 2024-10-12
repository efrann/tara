import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go
import pandas as pd
import pymysql
from datetime import datetime, timedelta

# MySQL bağlantısı
db = pymysql.connect(
    host="localhost",
    user="your_username",
    password="your_password",
    database="nessusdb"
)

# Verileri çekme fonksiyonu
def get_data(start_date=None, end_date=None, severity=None, scan_name=None):
    with db.cursor(pymysql.cursors.DictCursor) as cursor:
        # Tarih filtresi için WHERE koşulu
        date_condition = ""
        if start_date and end_date:
            date_condition = f"AND sr.scan_start BETWEEN UNIX_TIMESTAMP('{start_date}') AND UNIX_TIMESTAMP('{end_date}')"
        
        # Severity filtresi için WHERE koşulu
        severity_condition = ""
        if severity:
            severity_condition = f"AND p.severity IN ({','.join(map(str, severity))})"
        
        # Scan name filtresi için WHERE koşulu
        scan_name_condition = ""
        if scan_name:
            scan_name_condition = f"AND s.name LIKE '%{scan_name}%'"

        # Özet bilgi sorgusu
        summary_query = f"""
        SELECT 
            s.name AS scan_name,
            sr.scan_run_id,
            FROM_UNIXTIME(sr.scan_start) AS scan_start_time,
            sr.host_count,
            sr.critical_count,
            sr.high_count,
            sr.medium_count,
            sr.low_count,
            sr.info_count
        FROM 
            scan s
        JOIN 
            scan_run sr ON s.scan_id = sr.scan_id
        WHERE 1=1 {date_condition} {scan_name_condition}
        ORDER BY 
            sr.scan_start DESC
        LIMIT 10
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
        WHERE 1=1 {date_condition} {severity_condition} {scan_name_condition}
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
            p.name AS vulnerability_name,
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
        WHERE 1=1 {date_condition} {severity_condition} {scan_name_condition}
        ORDER BY 
            sr.scan_start DESC, p.severity DESC
        LIMIT 1000
        """
        
        cursor.execute(detailed_vulnerability_query)
        detailed_vulnerability_data = cursor.fetchall()
        
        # En çok görülen 10 zafiyet
        top_vulnerabilities_query = f"""
        SELECT 
            p.name AS vulnerability_name,
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
        WHERE 1=1 {date_condition} {severity_condition} {scan_name_condition}
        GROUP BY 
            p.plugin_id
        ORDER BY 
            count DESC
        LIMIT 10
        """
        
        cursor.execute(top_vulnerabilities_query)
        top_vulnerabilities_data = cursor.fetchall()
    
    return summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data

app = dash.Dash(__name__)

app.layout = html.Div([
    html.H1("Nessus Tarama Sonuçları Gösterge Paneli"),
    
    html.Div([
        html.Label("Başlangıç Tarihi:"),
        dcc.DatePickerSingle(
            id='start-date-picker',
            date=datetime.now().date() - timedelta(days=30)
        ),
        html.Label("Bitiş Tarihi:"),
        dcc.DatePickerSingle(
            id='end-date-picker',
            date=datetime.now().date()
        ),
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
            multi=True
        ),
        html.Label("Tarama Adı:"),
        dcc.Input(id='scan-name-input', type='text'),
        html.Button('Filtrele', id='filter-button')
    ]),
    
    html.Div([
        html.H2("Özet Bilgiler"),
        dash_table.DataTable(
            id='summary-table',
            columns=[{"name": i, "id": i} for i in ['scan_name', 'scan_start_time', 'host_count', 'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count']],
            data=[],
            style_table={'height': '300px', 'overflowY': 'auto'}
        ),
    ]),
    
    html.Div([
        html.H2("Zafiyet Dağılımı"),
        dcc.Graph(id='vulnerability-distribution')
    ]),
    
    html.Div([
        html.H2("En Çok Görülen 10 Zafiyet"),
        dash_table.DataTable(
            id='top-vulnerabilities-table',
            columns=[{"name": i, "id": i} for i in ['vulnerability_name', 'severity', 'count']],
            data=[],
            style_table={'height': '300px', 'overflowY': 'auto'}
        ),
    ]),
    
    html.Div([
        html.H2("Detaylı Zafiyet Listesi"),
        dash_table.DataTable(
            id='vulnerability-table',
            columns=[{"name": i, "id": i} for i in ['scan_name', 'host_ip', 'vulnerability_name', 'severity', 'plugin_family', 'port', 'scan_date']],
            data=[],
            style_table={'height': '400px', 'overflowY': 'auto'},
            filter_action="native",
            sort_action="native",
            sort_mode="multi",
            page_action="native",
            page_current=0,
            page_size=20,
        )
    ]),
    
    dcc.Interval(
        id='interval-component',
        interval=60*1000,  # Her 1 dakikada bir güncelle
        n_intervals=0
    )
])

@app.callback(
    [Output('summary-table', 'data'),
     Output('vulnerability-distribution', 'figure'),
     Output('vulnerability-table', 'data'),
     Output('top-vulnerabilities-table', 'data')],
    [Input('filter-button', 'n_clicks'),
     Input('interval-component', 'n_intervals')],
    [State('start-date-picker', 'date'),
     State('end-date-picker', 'date'),
     State('severity-dropdown', 'value'),
     State('scan-name-input', 'value')]
)
def update_data(n_clicks, n_intervals, start_date, end_date, severity, scan_name):
    summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data = get_data(start_date, end_date, severity, scan_name)
    
    # Özet tablo verisi
    summary_table_data = summary_data
    
    # Zafiyet dağılımı grafiği
    severity_labels = {0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
    vulnerability_distribution = go.Figure(data=[go.Pie(
        labels=[severity_labels[row['severity']] for row in vulnerability_data],
        values=[row['count'] for row in vulnerability_data],
        hole=.3
    )])
    vulnerability_distribution.update_layout(title_text="Zafiyet Dağılımı")
    
    # Detaylı zafiyet listesi
    vulnerability_table_data = detailed_vulnerability_data
    
    # En çok görülen 10 zafiyet
    top_vulnerabilities_table_data = top_vulnerabilities_data
    
    return summary_table_data, vulnerability_distribution, vulnerability_table_data, top_vulnerabilities_table_data

if __name__ == '__main__':
    app.run_server(debug=True)

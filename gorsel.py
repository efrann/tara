import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import pandas as pd
import pymysql
from datetime import datetime

# MySQL bağlantısı
db = pymysql.connect(
    host="localhost",
    user="your_username",
    password="your_password",
    database="nessusdb"
)

# Verileri çekme fonksiyonu
def get_data():
    with db.cursor(pymysql.cursors.DictCursor) as cursor:
        # Özet bilgi sorgusu
        summary_query = """
        SELECT 
            f.name AS folder_name,
            s.name AS scan_name,
            sr.scan_run_id,
            FROM_UNIXTIME(sr.scan_start) AS scan_start_time,
            FROM_UNIXTIME(sr.scan_end) AS scan_end_time,
            sr.host_count,
            sr.critical_count,
            sr.high_count,
            sr.medium_count,
            sr.low_count,
            sr.info_count
        FROM 
            folder f
        JOIN 
            scan s ON f.folder_id = s.folder_id
        JOIN 
            (SELECT 
                scan_id, 
                MAX(scan_start) AS latest_scan_start
             FROM 
                scan_run
             GROUP BY 
                scan_id) latest ON s.scan_id = latest.scan_id
        JOIN 
            scan_run sr ON latest.scan_id = sr.scan_id AND latest.latest_scan_start = sr.scan_start
        ORDER BY 
            f.name, s.name, sr.scan_start_time
        """
        
        cursor.execute(summary_query)
        summary_data = cursor.fetchall()
        
        # Detaylı zafiyet listesi sorgusu
        vulnerability_query = """
        SELECT 
            f.name AS folder_name,
            s.name AS scan_name,
            sr.scan_run_id,
            FROM_UNIXTIME(sr.scan_start) AS scan_start_time,
            h.host_ip,
            h.host_fqdn,
            p.plugin_id,
            p.name AS vulnerability_name,
            p.severity,
            p.family AS plugin_family,
            vo.port
        FROM 
            folder f
        JOIN 
            scan s ON f.folder_id = s.folder_id
        JOIN 
            (SELECT 
                scan_id, 
                MAX(scan_start) AS latest_scan_start
             FROM 
                scan_run
             GROUP BY 
                scan_id) latest ON s.scan_id = latest.scan_id
        JOIN 
            scan_run sr ON latest.scan_id = sr.scan_id AND latest.latest_scan_start = sr.scan_start
        LEFT JOIN
            host h ON sr.scan_run_id = h.scan_run_id
        LEFT JOIN
            host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND sr.scan_run_id = hv.scan_run_id
        LEFT JOIN
            plugin p ON hv.plugin_id = p.plugin_id
        LEFT JOIN
            vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
        ORDER BY 
            f.name, s.name, sr.scan_start_time, h.host_ip, p.severity DESC, p.name
        """
        
        cursor.execute(vulnerability_query)
        vulnerability_data = cursor.fetchall()
    
    return summary_data, vulnerability_data

app = dash.Dash(__name__)

# ... (app.layout kodu aynı kalır) ...

@app.callback(
    [Output('summary-table', 'data'),
     Output('vulnerability-distribution', 'figure'),
     Output('vulnerability-table', 'data')],
    [Input('interval-component', 'n_intervals')]
)
def update_data(n):
    summary_data, vulnerability_data = get_data()
    
    # Özet tablo verisi
    summary_table_data = [{k: v for k, v in row.items() if k in ['folder_name', 'scan_name', 'scan_start_time', 'host_count', 'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count']} for row in summary_data]
    
    # Zafiyet dağılımı grafiği
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for row in vulnerability_data:
        if row['severity'] == 4:
            severity_counts['Critical'] += 1
        elif row['severity'] == 3:
            severity_counts['High'] += 1
        elif row['severity'] == 2:
            severity_counts['Medium'] += 1
        elif row['severity'] == 1:
            severity_counts['Low'] += 1
        elif row['severity'] == 0:
            severity_counts['Info'] += 1
    
    vulnerability_distribution = go.Figure(data=[go.Pie(
        labels=list(severity_counts.keys()),
        values=list(severity_counts.values()),
        hole=.3
    )])
    vulnerability_distribution.update_layout(title_text="Zafiyet Dağılımı")
    
    # Detaylı zafiyet listesi
    vulnerability_table_data = [{k: v for k, v in row.items() if k in ['folder_name', 'scan_name', 'host_ip', 'vulnerability_name', 'severity', 'plugin_family', 'port']} for row in vulnerability_data]
    
    return summary_table_data, vulnerability_distribution, vulnerability_table_data

if __name__ == '__main__':
    app.run_server(debug=True)

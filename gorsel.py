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
        ORDER BY 
            sr.scan_start DESC
        LIMIT 10
        """
        
        cursor.execute(summary_query)
        summary_data = cursor.fetchall()
        
        # Zafiyet dağılımı sorgusu
        vulnerability_query = """
        SELECT 
            p.severity,
            COUNT(*) as count
        FROM 
            host_vuln hv
        JOIN 
            plugin p ON hv.plugin_id = p.plugin_id
        GROUP BY 
            p.severity
        """
        
        cursor.execute(vulnerability_query)
        vulnerability_data = cursor.fetchall()
        
        # Detaylı zafiyet listesi sorgusu
        detailed_vulnerability_query = """
        SELECT 
            s.name AS scan_name,
            h.host_ip,
            p.name AS vulnerability_name,
            p.severity,
            p.family AS plugin_family,
            vo.port
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
        ORDER BY 
            sr.scan_start DESC, p.severity DESC
        LIMIT 1000
        """
        
        cursor.execute(detailed_vulnerability_query)
        detailed_vulnerability_data = cursor.fetchall()
    
    return summary_data, vulnerability_data, detailed_vulnerability_data

app = dash.Dash(__name__)

app.layout = html.Div([
    html.H1("Nessus Tarama Sonuçları Gösterge Paneli"),
    
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
        html.H2("Detaylı Zafiyet Listesi"),
        dash_table.DataTable(
            id='vulnerability-table',
            columns=[{"name": i, "id": i} for i in ['scan_name', 'host_ip', 'vulnerability_name', 'severity', 'plugin_family', 'port']],
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
     Output('vulnerability-table', 'data')],
    [Input('interval-component', 'n_intervals')]
)
def update_data(n):
    summary_data, vulnerability_data, detailed_vulnerability_data = get_data()
    
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
    
    return summary_table_data, vulnerability_distribution, vulnerability_table_data

if __name__ == '__main__':
    app.run_server(debug=True)

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
    user="root",
    password="Nessus_Report123*-",
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
            MAX(FROM_UNIXTIME(sr.scan_start)) AS last_scan_date,
            COUNT(DISTINCT sr.scan_run_id) AS scan_count,
            SUM(sr.host_count) AS total_hosts,
            SUM(sr.critical_count) AS total_critical,
            SUM(sr.high_count) AS total_high,
            SUM(sr.medium_count) AS total_medium,
            SUM(sr.low_count) AS total_low,
            SUM(sr.info_count) AS total_info
        FROM 
            scan s
        JOIN 
            scan_run sr ON s.scan_id = sr.scan_id
        WHERE 1=1 {date_condition} {scan_name_condition}
        GROUP BY 
            s.name
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

        # En çok görülen 10 zafiyet sorgusu
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
        WHERE 1=1 {date_condition} {severity_condition} {scan_name_condition}
        """
        
        cursor.execute(total_vulnerabilities_query)
        total_vulnerabilities_data = cursor.fetchone()

    return summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data

# Dash uygulaması
app = dash.Dash(__name__, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'])

app.layout = html.Div([
    html.Div([
        html.H1("Nessus Tarama Sonuçları Gösterge Paneli", style={'textAlign': 'center', 'color': 'white'}),
        html.Img(src="/assets/nessus_logo.png", style={'height': '50px', 'float': 'right'}),
    ], style={'backgroundColor': '#1f2c56', 'padding': '10px'}),

    html.Div([
        html.Div([
            html.Label("Başlangıç Tarihi:", style={'color': 'white'}),
            dcc.DatePickerSingle(id='start-date-picker', style={'backgroundColor': '#1f2c56'}),
            html.Label("Bitiş Tarihi:", style={'color': 'white', 'marginLeft': '20px'}),
            dcc.DatePickerSingle(id='end-date-picker', style={'backgroundColor': '#1f2c56'}),
        ], style={'display': 'inline-block'}),
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
                style={'width': '200px', 'backgroundColor': '#1f2c56'}
            ),
        ], style={'display': 'inline-block', 'marginLeft': '20px'}),
        html.Div([
            html.Label("Tarama Adı:", style={'color': 'white'}),
            dcc.Input(id='scan-name-input', type='text', style={'backgroundColor': '#1f2c56', 'color': 'white'}),
        ], style={'display': 'inline-block', 'marginLeft': '20px'}),
        html.Button('Filtrele', id='filter-button', style={'marginLeft': '20px', 'backgroundColor': '#e55467', 'color': 'white'}),
    ], style={'backgroundColor': '#1f2c56', 'padding': '10px'}),

    html.Div([
        html.Div([
            html.H3("Toplam Zafiyet Sayıları", style={'textAlign': 'center', 'color': 'white'}),
            html.Div(id='total-vulnerabilities', style={'display': 'flex', 'justifyContent': 'space-around'}),
        ], style={'backgroundColor': '#1f2c56', 'padding': '10px', 'margin': '10px'}),
    ]),

    html.Div([
        html.Div([
            html.H3("Özet Bilgiler", style={'textAlign': 'center', 'color': 'white'}),
            dash_table.DataTable(
                id='summary-table',
                columns=[{"name": i, "id": i} for i in ['scan_name', 'last_scan_date', 'scan_count', 'total_hosts', 'total_critical', 'total_high', 'total_medium', 'total_low', 'total_info']],
                style_table={'height': '300px', 'overflowY': 'auto'},
                style_cell={'backgroundColor': '#1f2c56', 'color': 'white'},
                style_header={'backgroundColor': '#e55467', 'fontWeight': 'bold'},
            ),
        ], className="six columns"),

        html.Div([
            html.H3("Zafiyet Dağılımı", style={'textAlign': 'center', 'color': 'white'}),
            dcc.Graph(id='vulnerability-distribution')
        ], className="six columns"),
    ], className="row", style={'backgroundColor': '#1f2c56', 'padding': '10px', 'margin': '10px'}),

    html.Div([
        html.Div([
            html.H3("En Çok Görülen 10 Zafiyet", style={'textAlign': 'center', 'color': 'white'}),
            dash_table.DataTable(
                id='top-vulnerabilities-table',
                columns=[{"name": i, "id": i} for i in ['vulnerability_name', 'severity', 'count']],
                style_table={'height': '300px', 'overflowY': 'auto'},
                style_cell={'backgroundColor': '#1f2c56', 'color': 'white'},
                style_header={'backgroundColor': '#e55467', 'fontWeight': 'bold'},
            ),
        ], className="six columns"),

        html.Div([
            html.H3("Detaylı Zafiyet Listesi", style={'textAlign': 'center', 'color': 'white'}),
            dash_table.DataTable(
                id='vulnerability-table',
                columns=[{"name": i, "id": i} for i in ['scan_name', 'host_ip', 'vulnerability_name', 'severity', 'plugin_family', 'port', 'scan_date']],
                style_table={'height': '300px', 'overflowY': 'auto'},
                style_cell={'backgroundColor': '#1f2c56', 'color': 'white'},
                style_header={'backgroundColor': '#e55467', 'fontWeight': 'bold'},
                filter_action="native",
                sort_action="native",
                sort_mode="multi",
                page_action="native",
                page_current=0,
                page_size=10,
            )
        ], className="six columns"),
    ], className="row", style={'backgroundColor': '#1f2c56', 'padding': '10px', 'margin': '10px'}),

    dcc.Interval(
        id='interval-component',
        interval=60*1000,  # Her 1 dakikada bir güncelle
        n_intervals=0
    )
], style={'backgroundColor': '#1f2c56'})

@app.callback(
    [Output('summary-table', 'data'),
     Output('vulnerability-distribution', 'figure'),
     Output('vulnerability-table', 'data'),
     Output('top-vulnerabilities-table', 'data'),
     Output('total-vulnerabilities', 'children')],
    [Input('filter-button', 'n_clicks'),
     Input('interval-component', 'n_intervals')],
    [State('start-date-picker', 'date'),
     State('end-date-picker', 'date'),
     State('severity-dropdown', 'value'),
     State('scan-name-input', 'value')]
)
def update_data(n_clicks, n_intervals, start_date, end_date, severity, scan_name):
    summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data = get_data(start_date, end_date, severity, scan_name)
    
    # Özet tablo verisi
    summary_table_data = summary_data
    
    # Zafiyet dağılımı grafiği
    severity_labels = {0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
    vulnerability_distribution = go.Figure(data=[go.Pie(
        labels=[severity_labels[row['severity']] for row in vulnerability_data],
        values=[row['count'] for row in vulnerability_data],
        hole=.3,
        marker=dict(colors=['#FFA07A', '#98FB98', '#87CEFA', '#DDA0DD', '#F08080'])
    )])
    vulnerability_distribution.update_layout(
        title_text="Zafiyet Dağılımı",
        paper_bgcolor='#1f2c56',
        plot_bgcolor='#1f2c56',
        font=dict(color='white')
    )
    
    # Detaylı zafiyet listesi
    vulnerability_table_data = detailed_vulnerability_data
    
    # En çok görülen 10 zafiyet
    top_vulnerabilities_table_data = top_vulnerabilities_data
    
    # Toplam zafiyet sayıları
    total_vulnerabilities = [
        html.Div([
            html.H4("Critical", style={'color': '#F08080'}),
            html.H2(f"{total_vulnerabilities_data['total_critical']:,}", style={'color': '#F08080'})
        ]),
        html.Div([
            html.H4("High", style={'color': '#DDA0DD'}),
            html.H2(f"{total_vulnerabilities_data['total_high']:,}", style={'color': '#DDA0DD'})
        ]),
        html.Div([
            html.H4("Medium", style={'color': '#87CEFA'}),
            html.H2(f"{total_vulnerabilities_data['total_medium']:,}", style={'color': '#87CEFA'})
        ]),
        html.Div([
            html.H4("Low", style={'color': '#98FB98'}),
            html.H2(f"{total_vulnerabilities_data['total_low']:,}", style={'color': '#98FB98'})
        ]),
        html.Div([
            html.H4("Info", style={'color': '#FFA07A'}),
            html.H2(f"{total_vulnerabilities_data['total_info']:,}", style={'color': '#FFA07A'})
        ]),
    ]
    
    return summary_table_data, vulnerability_distribution, vulnerability_table_data, top_vulnerabilities_table_data, total_vulnerabilities

if __name__ == '__main__':
    app.run_server(debug=True)

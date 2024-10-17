import dash_core_components as dcc
import dash_html_components as html
import dash_bootstrap_components as dbc
import dash_table

def create_main_layout():
    return html.Div([
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
            html.Div([
                html.Label("Port:", style={'color': 'white', 'marginBottom': '5px', 'display': 'block'}),
                dcc.Input(
                    id='port-input',
                    type='text',
                    placeholder="Port numarası girin...",
                    style={'width': '100%', 'backgroundColor': '#34495e', 'color': 'white', 'border': '1px solid #3498db', 'borderRadius': '5px', 'padding': '8px'}
                ),
            ], style={'display': 'inline-block', 'verticalAlign': 'top', 'marginRight': '20px', 'width': '20%'}),
            html.Div([
                html.Button('Filtrele', id='filter-button', n_clicks=0, style={
                    'backgroundColor': '#3498db',
                    'color': 'white',
                    'border': 'none',
                    'padding': '10px 20px',
                    'borderRadius': '5px',
                    'cursor': 'pointer',
                    'transition': 'background-color 0.3s',
                    'marginRight': '10px',
                    'marginTop': '25px',
                }),
                html.A(
                    html.Button('Detaylı Zafiyet Listesi', style={
                        'backgroundColor': '#2ecc71',
                        'color': 'white',
                        'border': 'none',
                        'padding': '10px 20px',
                        'borderRadius': '5px',
                        'cursor': 'pointer',
                        'transition': 'background-color 0.3s',
                        'marginTop': '25px',
                    }),
                    id='open-new-tab',
                    href='',
                    target='_blank'
                ),
            ], style={'display': 'inline-block', 'verticalAlign': 'bottom'}),
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
                dcc.Graph(id='top-ports-graph', style={'height': '400px'})
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

        dcc.Interval(
            id='interval-component',
            interval=60*1000,  # Her 1 dakikada bir güncelle
            n_intervals=0
        ),

        # Hidden div for storing clicked severity
        html.Div(id='clicked-severity', style={'display': 'none'}),
    ])

def create_detailed_analysis_layout():
    return html.Div([
        html.H1("Detaylı Zafiyet Listesi", style={'textAlign': 'center', 'color': 'white'}),
        html.Div([
            dcc.Input(id='search-input', type='text', placeholder='Ara...', style={'width': '100%', 'marginBottom': '10px'}),
            dash_table.DataTable(
                id='vulnerability-table',
                columns=[
                    {"name": "Tarama Adı", "id": "scan_name"},
                    {"name": "IP Adresi", "id": "host_ip"},
                    {"name": "Host FQDN", "id": "host_fqdn"},
                    {"name": "Zafiyet Adı", "id": "vulnerability_name"},
                    {"name": "Önem Derecesi", "id": "severity_text"},
                    {"name": "Plugin Ailesi", "id": "plugin_family"},
                    {"name": "Port", "id": "port"},
                    {"name": "CVSS3 Skoru", "id": "cvss3_base_score"},
                    {"name": "Tarama Tarihi", "id": "scan_date"}
                ],
                style_table={'height': '400px', 'overflowY': 'auto'},
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
                        'if': {'column_id': 'severity_text', 'filter_query': '{severity_text} = "Kritik"'},
                        'backgroundColor': 'rgba(231, 76, 60, 0.1)',
                        'color': '#e74c3c',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity_text', 'filter_query': '{severity_text} = "Yüksek"'},
                        'backgroundColor': 'rgba(230, 126, 34, 0.1)',
                        'color': '#e67e22',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity_text', 'filter_query': '{severity_text} = "Orta"'},
                        'backgroundColor': 'rgba(241, 196, 15, 0.1)',
                        'color': '#f1c40f',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity_text', 'filter_query': '{severity_text} = "Düşük"'},
                        'backgroundColor': 'rgba(46, 204, 113, 0.1)',
                        'color': '#2ecc71',
                        'fontWeight': 'bold',
                    },
                    {
                        'if': {'column_id': 'severity_text', 'filter_query': '{severity_text} = "Bilgi"'},
                        'backgroundColor': 'rgba(52, 152, 219, 0.1)',
                        'color': '#3498db',
                        'fontWeight': 'bold',
                    }
                ],
                page_size=15,
                sort_action='native',
                filter_action='native',
            ),
        ], style={'backgroundColor': '#2c3e50', 'padding': '20px', 'borderRadius': '10px'}),
        html.Div(id='ip-ports-info', style={'marginTop': '20px', 'color': 'white'}),
        html.Div(id='applied-filters', style={'marginTop': '20px', 'color': 'white'}),
    ])
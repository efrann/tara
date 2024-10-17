from dash.dependencies import Input, Output, State
from dash import html
import plotly.graph_objs as go
from urllib.parse import urlencode
import dash
from database import get_data, get_ip_ports_data
from datetime import datetime

def register_callbacks(app):
    @app.callback(
        [Output('summary-table', 'data'),
         Output('vulnerability-distribution', 'figure'),
         Output('top-vulnerabilities-table', 'data'),
         Output('top-vulnerabilities-graph', 'figure'),
         Output('top-ports-graph', 'figure'),
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
         Input('clicked-severity', 'children')],
        [State('severity-dropdown', 'value'),
         State('scan-dropdown', 'value'),
         State('vulnerability-name-input', 'value'),
         State('ip-address-input', 'value'),
         State('port-input', 'value')]
    )
    def update_main_page(n_clicks, n_intervals, clicked_severity, severity, scan_name, vulnerability_name, ip_address, port):
        summary_data, vulnerability_data, detailed_vulnerability_data, top_vulnerabilities_data, total_vulnerabilities_data, scan_list, top_ports_data, ip_ports_data = get_data(severity, scan_name, vulnerability_name, ip_address, port)

        # Summary table data
        summary_table_data = summary_data if summary_data else []

        # Vulnerability distribution
        if vulnerability_data:
            vulnerability_distribution = go.Figure(data=[go.Pie(
                labels=['Kritik', 'Yüksek', 'Orta', 'Düşük', 'Bilgi'], 
                values=[d['count'] for d in vulnerability_data],
                marker=dict(colors=['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#3498db'])
            )])
            vulnerability_distribution.update_layout(
                margin=dict(l=0, r=0, t=0, b=0),
                paper_bgcolor='#2c3e50',
                plot_bgcolor='#34495e',
                font=dict(color='white'),
                height=300
            )
        else:
            vulnerability_distribution = go.Figure()

        # Top vulnerabilities table data
        top_vulnerabilities_table_data = top_vulnerabilities_data if top_vulnerabilities_data else []

        # Top vulnerabilities graph
        if top_vulnerabilities_data:
            top_vulnerabilities_graph = go.Figure(data=[go.Pie(
                labels=[row['vulnerability_name'] for row in top_vulnerabilities_data],
                values=[row['count'] for row in top_vulnerabilities_data],
                hole=.3,
                marker=dict(
                    colors=[
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
            )])
            top_vulnerabilities_graph.update_layout(
                margin=dict(l=0, r=0, t=0, b=0),
                paper_bgcolor='#2c3e50',
                plot_bgcolor='#34495e',
                font=dict(color='white', size=14),
                height=400,
                title=dict(text='Most Occurent 10 Vulnerabilities', font=dict(color='white', size=16)),
                showlegend=False,
            )
        else:
            top_vulnerabilities_graph = go.Figure()

        # Top ports graph
        if top_ports_data:
            top_ports_graph = go.Figure(data=[go.Bar(
                x=[str(row['port']) for row in top_ports_data],
                y=[row['count'] for row in top_ports_data],
                marker_color='#3498db'
            )])
            top_ports_graph.update_layout(
                margin=dict(l=0, r=0, t=0, b=0),
                paper_bgcolor='#2c3e50',
                plot_bgcolor='#34495e',
                font=dict(color='white', size=14),
                height=400,
                title=dict(text='Most Used 10 Ports', font=dict(color='white', size=16)),
                showlegend=False,
            )
        else:
            top_ports_graph = go.Figure()

        # Total vulnerabilities
        total_vulnerabilities = [html.Div("Veri yok")] * 5  # Varsayılan değer
        if total_vulnerabilities_data:
            total_vulnerabilities = [
                html.Div([
                    html.H4(info['severity_text'], style={'color': info['color'], 'margin': '0'}),
                    html.P(f"{info['count']} zafiyet", style={'color': 'white', 'margin': '0'})
                ], style={
                    'backgroundColor': info['bg_color'],
                    'padding': '10px',
                    'borderRadius': '5px',
                    'textAlign': 'center',
                    'boxShadow': '0 2px 4px rgba(0,0,0,0.1)',
                    'flex': '1',
                    'margin': '5px',
                    'minWidth': '120px'
                })
                for info in total_vulnerabilities_data
            ]

        # Last updated
        last_updated = f"Son Güncelleme: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        # Scan options
        scan_options = [{'label': scan, 'value': scan} for scan in scan_list] if scan_list else []

        # If a severity was clicked, update the severity dropdown
        if clicked_severity:
            severity = [int(clicked_severity)]

        return (summary_table_data, vulnerability_distribution, top_vulnerabilities_table_data, top_vulnerabilities_graph, top_ports_graph,
                total_vulnerabilities[0], total_vulnerabilities[1], total_vulnerabilities[2], total_vulnerabilities[3], total_vulnerabilities[4], 
                last_updated, scan_options, severity)

    @app.callback(
        Output('clicked-severity', 'children'),
        [Input('severity-4', 'n_clicks'),
         Input('severity-3', 'n_clicks'),
         Input('severity-2', 'n_clicks'),
         Input('severity-1', 'n_clicks'),
         Input('severity-0', 'n_clicks')]
    )
    def update_clicked_severity(n4, n3, n2, n1, n0):
        ctx = dash.callback_context
        if not ctx.triggered:
            return dash.no_update
        else:
            button_id = ctx.triggered[0]['prop_id'].split('.')[0]
            clicked_severity = button_id.split('-')[1]
            return clicked_severity

    @app.callback(
        [Output('vulnerability-table', 'data'),
         Output('ip-ports-info', 'children'),
         Output('applied-filters', 'children')],
        [Input('url', 'search'),
         Input('search-input', 'value')]
    )
    def update_detailed_analysis(search, search_value):
        params = parse_qs(search[1:])
        severity = params.get('severity', [None])[0]
        severity = [int(s) for s in severity.split(',')] if severity else None
        scan_name = params.get('scan_name', [None])[0]
        vulnerability_name = params.get('vulnerability_name', [None])[0]
        ip_address = params.get('ip_address', [None])[0]
        port = params.get('port', [None])[0]

        detailed_vulnerability_data = get_data(severity, scan_name, vulnerability_name, ip_address, port)
        ip_ports_data = get_ip_ports_data(ip_address) if ip_address else None

        if search_value:
            search_value = search_value.lower()
            detailed_vulnerability_data = [
                item for item in detailed_vulnerability_data
                if any(search_value in str(value).lower() for value in item.values())
            ]
        
        # IP portları bilgisini al
        ip_ports_info = html.Div("IP adresi belirtilmedi.")
        if ip_address:
            if ip_ports_data:
                port_list = [str(port['port']) for port in ip_ports_data]
                ip_ports_info = html.Div([
                    html.H4(f"{ip_address} IP adresi için açık portlar:", style={'color': '#3498db'}),
                    html.Ul([html.Li(port) for port in port_list], style={'columns': '3', 'listStyleType': 'none'})
                ])
        
        # Uygulanan filtreleri göster
        applied_filters = []
        if severity:
            severity_map = {4: 'Kritik', 3: 'Yüksek', 2: 'Orta', 1: 'Düşük', 0: 'Bilgi'}
            applied_filters.append(f"Önem Derecesi: {', '.join(severity_map[s] for s in severity if s in severity_map)}")
        if scan_name:
            applied_filters.append(f"Tarama Adı: {scan_name}")
        if vulnerability_name:
            applied_filters.append(f"Zafiyet Adı: {vulnerability_name}")
        if ip_address:
            applied_filters.append(f"IP Adresi: {ip_address}")
        if port:
            applied_filters.append(f"Port: {port}")
        if search_value:
            applied_filters.append(f"Arama: {search_value}")
        
        applied_filters_div = html.Div([
            html.H4("Uygulanan Filtreler:"),
            html.Ul([html.Li(filter_text) for filter_text in applied_filters]) if applied_filters else html.P("Filtre uygulanmadı.")
        ])
        
        return detailed_vulnerability_data, ip_ports_info, applied_filters_div

    @app.callback(
        Output('open-new-tab', 'href'),
        [Input('severity-dropdown', 'value'),
         Input('scan-dropdown', 'value'),
         Input('vulnerability-name-input', 'value'),
         Input('ip-address-input', 'value'),
         Input('port-input', 'value')]
    )
    def update_detailed_analysis_link(severity, scan_name, vulnerability_name, ip_address, port):
        params = {}
        if severity:
            params['severity'] = ','.join(map(str, severity))
        if scan_name:
            params['scan_name'] = scan_name
        if vulnerability_name:
            params['vulnerability_name'] = vulnerability_name
        if ip_address:
            params['ip_address'] = ip_address
        if port:
            params['port'] = port
        
        return f'/detailed-analysis?{urlencode(params)}'

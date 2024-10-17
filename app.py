import dash
import dash_bootstrap_components as dbc
from dash import html, dcc
from dash.dependencies import Input, Output
from layouts import create_main_layout, create_detailed_analysis_layout
from callbacks import register_callbacks

# Dash uygulamasını oluştur
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
server = app.server

# Ana layout
app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content')
])

# Sayfa yönlendirmesi için callback
@app.callback(Output('page-content', 'children'),
              [Input('url', 'pathname')])
def display_page(pathname):
    if pathname == '/detailed-analysis':
        return create_detailed_analysis_layout()
    else:
        return create_main_layout()

# Callback'leri kaydet
register_callbacks(app)

if __name__ == '__main__':
    app.run_server(debug=True)


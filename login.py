import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
from flask_login import login_user, LoginManager, UserMixin, logout_user, current_user
from werkzeug.security import check_password_hash
import pymysql
from contextlib import contextmanager

# Veritabanı bağlantısı için context manager
@contextmanager
def get_db_connection():
    connection = pymysql.connect(
        host="localhost",
        user="root",
        password="Nessus_Report123*-",
        database="nessusdb",
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        yield connection
    finally:
        connection.close()

# User sınıfı
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# Kullanıcı doğrulama fonksiyonu
def authenticate_user(username, password):
    with get_db_connection() as connection:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username = %s"
            cursor.execute(sql, (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], password):
                return User(user['id'], user['username'])
    return None

# Login layout
login_layout = html.Div([
    html.H2('Giriş Yap', style={'textAlign': 'center', 'color': '#ecf0f1'}),
    dcc.Input(
        placeholder='Kullanıcı Adı',
        type='text',
        id='username',
        style={'width': '100%', 'marginBottom': '10px', 'padding': '10px'}
    ),
    dcc.Input(
        placeholder='Şifre',
        type='password',
        id='password',
        style={'width': '100%', 'marginBottom': '10px', 'padding': '10px'}
    ),
    html.Button(
        'Giriş',
        id='login-button',
        n_clicks=0,
        style={
            'width': '100%',
            'backgroundColor': '#3498db',
            'color': 'white',
            'padding': '10px',
            'marginTop': '10px'
        }
    ),
    html.Div(id='login-output')
], style={
    'width': '300px',
    'margin': '100px auto',
    'padding': '20px',
    'backgroundColor': '#34495e',
    'borderRadius': '5px',
    'boxShadow': '0 0 10px rgba(0,0,0,0.1)'
})

# Login callback
def login_callback(n_clicks, username, password):
    if n_clicks > 0:
        user = authenticate_user(username, password)
        if user:
            login_user(user)
            return dcc.Location(pathname="/", id="redirect")
        else:
            return html.Div('Geçersiz kullanıcı adı veya şifre', style={'color': 'red', 'marginTop': '10px'})
    return ""

# Logout callback
def logout_callback():
    logout_user()
    return dcc.Location(pathname="/login", id="redirect")

# Login manager
login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as connection:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM users WHERE id = %s"
            cursor.execute(sql, (int(user_id),))
            user = cursor.fetchone()
            if user:
                return User(user['id'], user['username'])
    return None


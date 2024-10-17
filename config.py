import configparser
import os

# Konfigürasyon dosyasının yolunu belirle
config_path = os.path.join(os.path.dirname(__file__), 'config.ini')

# Configparser nesnesini oluştur ve dosyayı oku
config = configparser.ConfigParser()
config.read(config_path)

# Veritabanı yapılandırmasını oku
DB_CONFIG = {
    'host': config['mysql']['hostname'],
    'user': config['mysql']['username'],
    'password': config['mysql']['password'],
    'database': config['mysql']['database']
}

# Uygulama ayarlarını oku
APP_CONFIG = {
    'debug': config['app'].getboolean('debug'),
    'port': config['app'].getint('port')
}

# Diğer konfigürasyon değişkenleri...


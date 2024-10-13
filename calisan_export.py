#!/usr/bin/env python3
import configparser
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import pymysql.cursors
import os
from datetime import datetime
from operator import itemgetter

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Read configuration
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

nessus_hostname = config.get('nessus','hostname')
nessus_port = config.get('nessus','port')
access_key = 'accessKey=' + config.get('nessus','access_key') + ';'
secret_key = 'secretKey=' + config.get('nessus','secret_key') + ';'
base = 'https://{hostname}:{port}'.format(hostname=nessus_hostname, port=nessus_port)
trash = config.getboolean('nessus','trash')

db_hostname = config.get('mysql','hostname')
username = config.get('mysql','username')
password = config.get('mysql','password')
database = config.get('mysql','database')

# Nessus endpoints
FOLDERS = '/folders'
SCANS = '/scans'

SCAN_ID = SCANS + '/{scan_id}'
HOST_ID = SCAN_ID + '/hosts/{host_id}'
PLUGIN_ID = HOST_ID + '/plugins/{plugin_id}'

SCAN_RUN = SCAN_ID + '?history_id={history_id}'
HOST_VULN = HOST_ID + '?history_id={history_id}'
PLUGIN_OUTPUT = PLUGIN_ID + '?history_id={history_id}'

# Database connection
connection = pymysql.connect(host=db_hostname,
                             user=username,
                             password=password,
                             db=database,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor,
                             autocommit=False)

# ---Functions---
# Nessus API functions
def request(url):
    url = base + url
    headers = {'X-ApiKeys': access_key + secret_key}
    response = requests.get(url=url,headers=headers,verify=False)
    return response.json()

def get_folders():
    return request(FOLDERS)

def get_scans():
    return request(SCANS)

def get_scan(scan_id):
    return request(SCAN_ID.format(scan_id=scan_id))

def get_scan_run(scan_id, history_id):
    return request(SCAN_RUN.format(scan_id=scan_id, history_id=history_id))

def get_host_vuln(scan_id, host_id, history_id):
    return request(HOST_VULN.format(scan_id=scan_id, host_id=host_id, history_id=history_id))

def get_plugin_output(scan_id, host_id, plugin_id, history_id):
    return request(PLUGIN_OUTPUT.format(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id, history_id=history_id))

# --- Functions for database operations ---
#
#
#
#
def update_folders():
    print("Klasör güncelleme işlemi başlıyor...")
    folders = get_folders()
    print(f"Toplam {len(folders['folders'])} klasör bulundu:")
    
    # Klasör isimlerini yazdır.
    for folder in folders['folders']:
        print(f"- {folder['name']} (ID: {folder['id']}, Tür: {folder['type']})")
    
    print("\nKlasör güncelleme detayları:")
    updated_count = 0
    inserted_count = 0

    with connection.cursor() as cursor:
        #Update folders
        for folder in folders['folders']:
            sql = """INSERT INTO `folder` (`folder_id`, `type`, `name`)
                     VALUES (%s, %s, %s)
                 ON DUPLICATE KEY UPDATE type=%s, name=%s"""
            cursor.execute(sql, (folder['id'], folder['type'], folder['name'], folder['type'], folder['name']))

            if cursor.rowcount == 1:
                inserted_count += 1
                print(f"Yeni klasör eklendi: ID={folder['id']}, Ad={folder['name']}")
            elif cursor.rowcount == 2:
                updated_count += 1
                print(f"Klasör güncellendi: ID={folder['id']}, Ad={folder['name']}")  

    connection.commit()
    print(f"\nKlasör güncelleme işlemi tamamlandı. {inserted_count} yeni klasör eklendi, {updated_count} klasör güncellendi.")

def update_plugin(plugin, cursor):
    #Check existing plugin_id in plugin DB
    sql = "SELECT `plugin_id`, `mod_date` FROM `plugin` WHERE `plugin_id` = %s"
    cursor.execute(sql, (plugin['plugin_id']))
    result = cursor.fetchone()

    #Split reference into array into string delimited by new line
    reference = None
    if plugin['pluginattributes'].get('see_also') is not None:
        reference = '\n'.join(plugin['pluginattributes'].get('see_also'))

    if result != None:
        if result['mod_date'] != plugin['pluginattributes']['plugin_information'].get('plugin_modification_date', None):
            #New version of plugin exists, build update query
            sql = "UPDATE `plugin` \
            SET `severity` = %s, `name` = %s, `family` = %s, `synopsis` = %s, `description` = %s, `solution` = %s,\
            `cvss_base_score` = %s, `cvss3_base_score` = %s, `cvss_vector` = %s, `cvss3_vector` = %s, `ref` = %s, `pub_date` = %s, `mod_date` = %s\
             WHERE `plugin_id` = %s"
            
            cursor.execute(sql, (
            plugin['severity'],
            plugin['pluginname'],
            plugin['pluginfamily'],
            plugin['pluginattributes']['synopsis'],
            plugin['pluginattributes']['description'],
            plugin['pluginattributes']['solution'],
            plugin['pluginattributes']['risk_information'].get('cvss_base_score', None),
            plugin['pluginattributes']['risk_information'].get('cvss3_base_score', None),
            plugin['pluginattributes']['risk_information'].get('cvss_vector', None),
            plugin['pluginattributes']['risk_information'].get('cvss3_vector', None),
            reference,
            plugin['pluginattributes']['plugin_information'].get('plugin_publication_date', None),
            plugin['pluginattributes']['plugin_information'].get('plugin_modification_date', None),
            plugin['plugin_id']
            ))

        else:
            #Looks like the plugin version is the same, skip update
            return None
    else:
        #Doesn't exist, build insert query
        sql = "INSERT INTO `plugin` (`plugin_id`, `severity`, `name`, `family`, `synopsis`, `description`, `solution`,\
             `cvss_base_score`, `cvss3_base_score`, `cvss_vector`, `cvss3_vector`, `ref`, `pub_date`, `mod_date`)\
                  VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        
        cursor.execute(sql, (
            plugin['plugin_id'],
            plugin['severity'],
            plugin['pluginname'],
            plugin['pluginfamily'],
            plugin['pluginattributes']['synopsis'],
            plugin['pluginattributes']['description'],
            plugin['pluginattributes']['solution'],
            plugin['pluginattributes']['risk_information'].get('cvss_base_score', None),
            plugin['pluginattributes']['risk_information'].get('cvss3_base_score', None),
            plugin['pluginattributes']['risk_information'].get('cvss_vector', None),
            plugin['pluginattributes']['risk_information'].get('cvss3_vector', None),
            reference,
            plugin['pluginattributes']['plugin_information'].get('plugin_publication_date', None),
            plugin['pluginattributes']['plugin_information'].get('plugin_modification_date', None)
            ))
    
def insert_vuln_output(vuln_output, host_vuln_id, cursor):
    for output in vuln_output:
        for port in output['ports'].keys():
            sql = "INSERT INTO `vuln_output` (`host_vuln_id`, `port`, `output`) VALUES (%s, %s, %s)"
            cursor.execute(sql, (host_vuln_id, port, output['plugin_output']))


def insert_host_vuln(scan_id, host_id, plugin_id, history_id, cursor):
    #Need to insert plugin first to have FK relationship
    #Get vuln output which includes plugin info
    vuln_output = get_plugin_output(scan_id, host_id, plugin_id, history_id)
    update_plugin(vuln_output['info']['plugindescription'], cursor)

    #Insert host vuln
    sql = "INSERT INTO `host_vuln` (`nessus_host_id`, `scan_run_id`, `plugin_id`) VALUES (%s, %s, %s)"
    cursor.execute(sql, (host_id, history_id, plugin_id))

    #Finally insert vuln output
    insert_vuln_output(vuln_output['outputs'], cursor.lastrowid, cursor)



def insert_host(scan_id, host_id, history_id, cursor):
    #Get the host vulnerabilities for a scan run
    host = get_host_vuln(scan_id, host_id, history_id)

    #Count number of vulns of each severity for this host in this scan run
    #0 is informational, 4 is critical
    sev_count = [0] * 5
    for vuln in host['vulnerabilities']:
        sev_count[vuln['severity']] += vuln['count']

    # Insert host information
    sql = "INSERT INTO `host` (`nessus_host_id`, `scan_run_id`, `scan_id`, `host_ip`, `host_fqdn`, `host_start`, `host_end`, `os`,\
          `critical_count`, `high_count`, `medium_count`, `low_count`, `info_count`)\
              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    
    cursor.execute(sql, (
        host_id,
        history_id, 
        scan_id, 
        host['info']['host-ip'],
        host['info'].get('host-fqdn', None),
        host['info'].get('host_start', None), 
        host['info'].get('host_end', None),
        host['info'].get('operating-system', None), 
        sev_count[4], sev_count[3], sev_count[2], sev_count[1], sev_count[0]
    ))
    #Insert host vulns
    for vuln in host['vulnerabilities']:
        insert_host_vuln(scan_id, host_id, vuln['plugin_id'], history_id, cursor)

        
def insert_scan_run(scan_id, history_id):
    # Get scan runs for a scan
    scan_run = get_scan_run(scan_id, history_id)

    # Count number of vulns of each severity for this scan run
    #0 is informational, 4 is critical
    sev_count = [0] * 5
    for vuln in scan_run['vulnerabilities']:
        sev_count[vuln['severity']] += vuln['count']

    with connection.cursor() as cursor: 
        #Insert scan run details
        sql = "INSERT INTO `scan_run` (`scan_run_id`, `scan_id`, `scanner_start`, `scanner_end`, `targets`,\
              `host_count`, `critical_count`, `high_count`, `medium_count`, `low_count`, `info_count`)\
                  VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        
        cursor.execute(sql, (
            history_id, 
            scan_id, 
            scan_run['info']['scanner_start'],
            scan_run['info']['scanner_end'],
            scan_run['info']['targets'],
            scan_run['info']['hostcount'],
            sev_count[4], sev_count[3], sev_count[2], sev_count[1], sev_count[0]
            ))
        
        #Insert hosts in scan run
        for host in scan_run['hosts']:
            insert_host(scan_id, host['host_id'], history_id, cursor)
            
    connection.commit()
#get_scans() fonksiyonu ile Nessus'tan tüm taramaları alır.



def format_timestamp(timestamp):
    if timestamp and timestamp != 'Bilinmiyor':
        dt = datetime.fromtimestamp(int(timestamp))
        return dt.strftime("%d %b %Y, %H:%M:%S")
    return 'Bilinmiyor'

def update_scans():
    scans = get_scans()
    print(f"Toplam {len(scans['scans'])} tarama bulundu.")

    with connection.cursor() as cursor:
        #upsert scans
        for scan in scans['scans']:
            sql = """INSERT INTO `scan` (`scan_id`, `folder_id`, `type`, `name`)\
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE folder_id=%s, type=%s, name=%s"""
            
            cursor.execute(sql, (
                scan['id'], 
                scan['folder_id'], 
                scan['type'], 
                scan['name'], 
                scan['folder_id'], 
                scan['type'], 
                scan['name']
        ))

    connection.commit()
    print("Tarama bilgileri veritabanına kaydedildi.")

    for scan in scans['scans']:
        print(f"\nİşleniyor: {scan['name']} (ID: {scan['id']})")

        #Retrieve scan details about the current scan
        scan_details = get_scan(scan['id'])

        if scan_details['history'] is not None:
            sorted_history = sorted(scan_details['history'], key=itemgetter('creation_date'), reverse=True)[:1]
            print(f" Bu tarama için {len(sorted_history)} en güncel çalıştırma işlenecek.")

        #Check each of the latest runs of each scan
        for scan_run in sorted_history:
            print(f" Çalıştırma ID: {scan_run['history_id']}, Durum : {scan_run['status']}")

            #Only import if scan finished completely
            if scan_run['status'] == 'completed':
                scan_run_details = get_scan_run(scan['id'], scan_run['history_id'])
                host_start = format_timestamp(scan_run_details['info'].get('scanner_start'))
                host_end = format_timestamp(scan_run_details['info'].get('scanner_end'))
                print(f"    Host Başlangıç: {host_start}, Host Bitiş: {host_end}")

                result = None
                with connection.cursor() as cursor:
                    sql = "SELECT * FROM `scan_run` WHERE `scan_run_id` = %s"
                    cursor.execute(sql, (scan_run['history_id'],))
                    result = cursor.fetchone()

                #If scan run hasn't been inserted
                if result == None:
                    print(f"      Yeni çalıştırma ekleniyor: {scan_run['history_id']}")
                    insert_scan_run(scan['id'], scan_run['history_id'])
                else:
                    print(f"      Çalıştırma zaten mevcut: {scan_run['history_id']}")
            else:
                print(f"      Tamamlanmamış çalıştırma, atlanıyor: {scan_run['history_id']}")
        else:
            print(f"  Bu tarama için geçmiş çalıştırma bulunamadı.")
    print("\nTüm taramalar işlendi.")    
    
    
update_folders()
update_scans()

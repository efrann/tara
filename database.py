import pymysql
from pymysql.cursors import DictCursor
from contextlib import contextmanager
from config import DB_CONFIG

@contextmanager
def get_db_connection():
    connection = pymysql.connect(
        **DB_CONFIG,
        charset='utf8mb4',
        cursorclass=DictCursor
    )
    try:
        yield connection
    finally:
        connection.close()

def parse_port_input(port_input):
    if not port_input:
        return ""
    
    ports = []
    for part in port_input.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return f"AND vo.port IN ({','.join(map(str, ports))})"

def get_data(severity=None, scan_name=None, vulnerability_name=None, ip_address=None, port=None):
    with get_db_connection() as connection:
        with connection.cursor() as cursor:
            # Severity koşulu
            severity_condition = ""
            if severity:
                severity_condition = f"AND p.severity IN ({','.join(map(str, severity))})"
            
            # Scan name koşulu
            scan_name_condition = ""
            if scan_name:
                scan_name_condition = f"AND s.name LIKE '%{scan_name}%'"
            
            # Vulnerability name koşulu
            vulnerability_name_condition = ""
            if vulnerability_name:
                vulnerability_name_condition = f"AND p.name LIKE '%{vulnerability_name}%'"

            # IP adresi koşulu
            ip_address_condition = ""
            if ip_address:
                ip_address_condition = f"AND h.host_ip LIKE '%{ip_address}%'"

            # Port koşulu
            port_condition = parse_port_input(port)

            # Özet bilgi sorgusu
            summary_query = f"""
            SELECT 
                s.name AS scan_name,
                f.name AS folder_name,
                MAX(FROM_UNIXTIME(sr.scan_start)) AS last_scan_date,
                COUNT(DISTINCT h.host_ip) AS total_hosts,
                SUM(CASE WHEN p.severity = 4 THEN 1 ELSE 0 END) AS total_critical,
                SUM(CASE WHEN p.severity = 3 THEN 1 ELSE 0 END) AS total_high,
                SUM(CASE WHEN p.severity = 2 THEN 1 ELSE 0 END) AS total_medium,
                SUM(CASE WHEN p.severity = 1 THEN 1 ELSE 0 END) AS total_low,
                SUM(CASE WHEN p.severity = 0 THEN 1 ELSE 0 END) AS total_info
            FROM 
                scan s
            LEFT JOIN 
                folder f ON s.folder_id = f.folder_id
            JOIN 
                scan_run sr ON s.scan_id = sr.scan_id
            JOIN
                host h ON sr.scan_run_id = h.scan_run_id
            LEFT JOIN 
                host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
            LEFT JOIN 
                plugin p ON hv.plugin_id = p.plugin_id
            LEFT JOIN
                vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
            WHERE 
                sr.scan_run_id = (
                    SELECT MAX(scan_run_id) 
                    FROM scan_run 
                    WHERE scan_id = s.scan_id
                )
            {severity_condition}
            {scan_name_condition}
            {vulnerability_name_condition}
            {ip_address_condition}
            {port_condition}
            GROUP BY 
                s.name, f.name
            """
            
            # Severity seçimine göre sıralama ekliyoruz
            if severity:
                if 4 in severity:
                    summary_query += " ORDER BY total_critical DESC"
                elif 3 in severity:
                    summary_query += " ORDER BY total_high DESC"
                elif 2 in severity:
                    summary_query += " ORDER BY total_medium DESC"
                elif 1 in severity:
                    summary_query += " ORDER BY total_low DESC"
                elif 0 in severity:
                    summary_query += " ORDER BY total_info DESC"
            else:
                summary_query += " ORDER BY last_scan_date DESC"
            
            cursor.execute(summary_query)
            summary_data = cursor.fetchall()

            # En çok görülen 10 zafiyet sorgusu
            top_vulnerabilities_query = f"""
            SELECT 
                f.name AS folder_name,
                s.name AS scan_name,
                COALESCE(p.name, 'Bilinmeyen Zafiyet') AS vulnerability_name,
                p.severity,
                COUNT(DISTINCT hv.host_vuln_id) as count
            FROM 
                scan s
            JOIN 
                scan_run sr ON s.scan_id = sr.scan_id
            JOIN
                host h ON sr.scan_run_id = h.scan_run_id
            LEFT JOIN 
                host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
            LEFT JOIN 
                plugin p ON hv.plugin_id = p.plugin_id
            JOIN
                folder f ON s.folder_id = f.folder_id
            LEFT JOIN
                vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
            WHERE 
                sr.scan_run_id = (
                    SELECT MAX(scan_run_id) 
                    FROM scan_run 
                    WHERE scan_id = s.scan_id
                )
            {severity_condition} {scan_name_condition} {vulnerability_name_condition} {ip_address_condition} {port_condition}
            GROUP BY 
                f.name, s.name, p.plugin_id, p.name, p.severity
            ORDER BY 
                count DESC
            LIMIT 10
            """
            
            cursor.execute(top_vulnerabilities_query)
            top_vulnerabilities_data = cursor.fetchall()

            # Mevcut taramaları çekmek için yeni bir sorgu ekleyelim
            scan_list_query = """
            SELECT DISTINCT s.name
            FROM scan s
            JOIN scan_run sr ON s.scan_id = sr.scan_id
            ORDER BY s.name
            """
            cursor.execute(scan_list_query)
            scan_list = [row['name'] for row in cursor.fetchall()]

            # Diğer sorgular (vulnerability_data, detailed_vulnerability_data, total_vulnerabilities_data, top_ports_data, ip_ports_data)
            # Bu sorguları da benzer şekilde ekleyin

    return summary_data, None, None, top_vulnerabilities_data, None, scan_list, None, None

# Diğer veritabanı fonksiyonları buraya eklenebilir
def get_detailed_vulnerability_data(severity=None, scan_name=None, vulnerability_name=None, ip_address=None, port=None):
    with get_db_connection() as connection:
        with connection.cursor() as cursor:
            # Detaylı zafiyet listesi sorgusu
            detailed_query = f"""
            SELECT 
                s.name AS scan_name,
                h.host_ip,
                h.host_fqdn,
                p.name AS vulnerability_name,
                p.severity,
                p.plugin_family,
                vo.port,
                p.cvss3_base_score,
                FROM_UNIXTIME(sr.scan_start) AS scan_date
            FROM 
                scan s
            JOIN 
                scan_run sr ON s.scan_id = sr.scan_id
            JOIN
                host h ON sr.scan_run_id = h.scan_run_id
            JOIN 
                host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
            JOIN 
                plugin p ON hv.plugin_id = p.plugin_id
            LEFT JOIN
                vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
            WHERE 
                sr.scan_run_id = (
                    SELECT MAX(scan_run_id) 
                    FROM scan_run 
                    WHERE scan_id = s.scan_id
                )
            {severity_condition}
            {scan_name_condition}
            {vulnerability_name_condition}
            {ip_address_condition}
            {port_condition}
            ORDER BY 
                p.severity DESC, s.name, h.host_ip
            """
            
            cursor.execute(detailed_query)
            detailed_vulnerability_data = cursor.fetchall()

    return detailed_vulnerability_data

def get_ip_ports_data(ip_address):
    with get_db_connection() as connection:
        with connection.cursor() as cursor:
            ip_ports_query = f"""
            SELECT DISTINCT vo.port
            FROM host h
            JOIN host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
            JOIN vuln_output vo ON hv.host_vuln_id = vo.host_vuln_id
            WHERE h.host_ip = '{ip_address}'
            ORDER BY vo.port
            """
            
            cursor.execute(ip_ports_query)
            ip_ports_data = cursor.fetchall()

    return ip_ports_data

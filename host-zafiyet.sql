SELECT 
    h.host_ip,
    h.host_fqdn,
    s.name AS scan_name,
    f.name AS folder_name,
    FROM_UNIXTIME(sr.scan_start) AS last_scan_date,
    COUNT(DISTINCT CASE WHEN p.severity = 4 THEN hv.host_vuln_id END) AS critical_count,
    COUNT(DISTINCT CASE WHEN p.severity = 3 THEN hv.host_vuln_id END) AS high_count,
    COUNT(DISTINCT CASE WHEN p.severity = 2 THEN hv.host_vuln_id END) AS medium_count,
    COUNT(DISTINCT CASE WHEN p.severity = 1 THEN hv.host_vuln_id END) AS low_count,
    COUNT(DISTINCT CASE WHEN p.severity = 0 THEN hv.host_vuln_id END) AS info_count,
    COUNT(DISTINCT hv.host_vuln_id) AS total_vulnerabilities
FROM 
    host h
JOIN 
    scan_run sr ON h.scan_run_id = sr.scan_run_id
JOIN 
    scan s ON sr.scan_id = s.scan_id
JOIN 
    folder f ON s.folder_id = f.folder_id
LEFT JOIN 
    host_vuln hv ON h.nessus_host_id = hv.nessus_host_id AND h.scan_run_id = hv.scan_run_id
LEFT JOIN 
    plugin p ON hv.plugin_id = p.plugin_id
WHERE 
    sr.scan_run_id = (
        SELECT MAX(scan_run_id) 
        FROM scan_run 
        WHERE scan_id = s.scan_id
    )
GROUP BY 
    h.host_ip, h.host_fqdn, s.name, f.name, sr.scan_start
ORDER BY 
    sr.scan_start DESC, total_vulnerabilities DESC;

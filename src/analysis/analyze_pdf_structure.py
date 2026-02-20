import fitz  # PyMuPDF
import re
from collections import Counter
from pathlib import Path

def analyze_pdf_structure(pdf_path):
    """
    Analyze the PDF structure to understand how vulnerability data is organized.
    """
    doc = fitz.open(pdf_path)
    print(f"Total pages: {len(doc)}\n")
    
    all_text = ""
    for page_num, page in enumerate(doc):
        all_text += page.get_text()
    
    # Sample first 5000 characters to see structure
    print("=" * 80)
    print("FIRST 5000 CHARACTERS (to understand document format):")
    print("=" * 80)
    print(all_text[:5000])
    print("\n")
    
    # Look for severity keywords
    print("=" * 80)
    print("SEVERITY PATTERNS FOUND:")
    print("=" * 80)
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'None']
    for severity in severities:
        count = len(re.findall(r'\b' + severity + r'\b', all_text))
        print(f"{severity}: {count} occurrences")
    print()
    
    # Look for CVE patterns
    print("=" * 80)
    print("CVE PATTERNS:")
    print("=" * 80)
    cve_pattern = r'CVE-\d{4}-\d{4,5}'
    cves = re.findall(cve_pattern, all_text)
    print(f"Total CVE references: {len(cves)}")
    print(f"Unique CVEs: {len(set(cves))}")
    print(f"Examples: {list(set(cves))[:10]}")
    print()
    
    # Look for IP patterns
    print("=" * 80)
    print("IP ADDRESS PATTERNS:")
    print("=" * 80)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, all_text)
    print(f"Total IP references: {len(ips)}")
    print(f"Unique IPs: {len(set(ips))}")
    print(f"Examples: {list(set(ips))[:10]}")
    print()
    
    # Look for OID patterns (NVT identifiers)
    print("=" * 80)
    print("OID PATTERNS (NVT identifiers):")
    print("=" * 80)
    oid_pattern = r'\d+\.\d+\.\d+(?:\.\d+)*'
    oids = re.findall(oid_pattern, all_text)
    # Filter out likely false positives (too short versions, timestamps)
    oids = [oid for oid in oids if len(oid) > 10]
    print(f"Total OID references: {len(oids)}")
    print(f"Unique OIDs: {len(set(oids))}")
    print(f"Examples: {list(set(oids))[:10]}")
    print()
    
    # Look for hostname patterns
    print("=" * 80)
    print("HOSTNAME/DOMAIN PATTERNS:")
    print("=" * 80)
    hostname_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    hostnames = re.findall(hostname_pattern, all_text.lower())
    print(f"Total hostname references: {len(hostnames)}")
    print(f"Unique hostnames: {len(set(hostnames))}")
    print(f"Examples: {list(set(hostnames))[:10]}")
    print()
    
    # Look for MAC address patterns
    print("=" * 80)
    print("MAC ADDRESS PATTERNS:")
    print("=" * 80)
    mac_pattern = r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})'
    macs = re.findall(mac_pattern, all_text)
    print(f"Total MAC references: {len(macs)}")
    print(f"Unique MACs: {len(set(macs))}")
    print(f"Examples: {list(set(macs))[:10]}")
    print()
    
    # Look for CVSS patterns
    print("=" * 80)
    print("CVSS SCORE PATTERNS:")
    print("=" * 80)
    cvss_pattern = r'CVSS[:\s]+(\d+\.\d+)'
    cvss_scores = re.findall(cvss_pattern, all_text)
    print(f"Total CVSS scores found: {len(cvss_scores)}")
    if cvss_scores:
        print(f"CVSS scores: {sorted(set(float(s) for s in cvss_scores))}")
    print()
    
    # Look for port patterns
    print("=" * 80)
    print("PORT PATTERNS (Port: <number>):")
    print("=" * 80)
    port_pattern = r'[Pp]ort[:\s]+(\d+)'
    ports = re.findall(port_pattern, all_text)
    print(f"Total port references: {len(ports)}")
    print(f"Unique ports: {len(set(ports))}")
    print(f"Top 20 ports: {Counter(ports).most_common(20)}")
    print()
    
    # Look for service patterns
    print("=" * 80)
    print("SERVICE PATTERNS:")
    print("=" * 80)
    service_keywords = ['ssh', 'ftp', 'http', 'https', 'smtp', 'snmp', 'dns', 'ldap', 'kerberos', 'ntp']
    for service in service_keywords:
        count = len(re.findall(r'\b' + service + r'\b', all_text, re.IGNORECASE))
        if count > 0:
            print(f"{service.upper()}: {count} occurrences")
    print()
    
    # Look for section headers
    print("=" * 80)
    print("SECTION HEADERS/DELIMITERS:")
    print("=" * 80)
    lines = all_text.split('\n')
    header_candidates = [line for line in lines if len(line) > 5 and len(line) < 100 and line.isupper()]
    print(f"Lines that appear to be headers (all uppercase): {len(header_candidates)}")
    print("Examples of headers:")
    for header in header_candidates[:20]:
        print(f"  - {header[:80]}")
    print()
    
    # Sample a vulnerability entry
    print("=" * 80)
    print("SAMPLE VULNERABILITY ENTRY (500 chars after CVE-2024):")
    print("=" * 80)
    sample_match = re.search(r'CVE-\d{4}-\d{4,5}.{0,500}', all_text)
    if sample_match:
        print(sample_match.group(0))
    print()
    
    # Look for table-like structures
    print("=" * 80)
    print("TABLE-LIKE STRUCTURES:")
    print("=" * 80)
    # Look for rows with pipes or aligned columns
    pipe_lines = [line for line in lines if '|' in line]
    dash_table_lines = [line for line in lines if '-' * 5 in line and len(line) > 20]
    print(f"Lines with pipes (|): {len(pipe_lines)}")
    if pipe_lines:
        print(f"Example pipe-separated lines (first 3):")
        for line in pipe_lines[:3]:
            print(f"  {line[:100]}")
    print(f"\nLines with dash tables (---): {len(dash_table_lines)}")
    if dash_table_lines:
        print(f"Example dash table lines (first 3):")
        for line in dash_table_lines[:3]:
            print(f"  {line[:100]}")
    print()
    
    doc.close()

if __name__ == "__main__":
    pdf_path = Path("data/raw/Vulnerability Scan Report (By Device).pdf")
    if pdf_path.exists():
        analyze_pdf_structure(str(pdf_path))
    else:
        print(f"PDF not found at {pdf_path}")
        print(f"Current directory: {Path.cwd()}")
        print(f"Files in data/raw/: {list(Path('data/raw/').glob('*'))}")

import whois
import requests
import socket
import re

def is_ip(text):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", text)

def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return f"Geolocation: {data.get('city')}, {data.get('region')}, {data.get('country')}. Org: {data.get('org')}."
    except Exception:
        pass
    return "Geolocation: Unknown."

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        registrar = w.registrar or "Unknown"
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return f"Registrar: {registrar}. Created: {creation_date}."
    except Exception:
        return "Whois: Lookup failed."

def enrich_ioc(ioc):
    """
    Analyzes the IOC and returns a context string.
    """
    enrichment = []
    
    # Simple heuristic to clean IOC (remove http/https)
    clean_ioc = ioc.replace("http://", "").replace("https://", "").split("/")[0]

    if is_ip(clean_ioc):
        enrichment.append(f"[Hunter] IP detected: {clean_ioc}")
        enrichment.append(get_ip_info(clean_ioc))
    elif "." in clean_ioc and not " " in clean_ioc:
        enrichment.append(f"[Hunter] Domain/URL detected: {clean_ioc}")
        enrichment.append(get_whois_info(clean_ioc))
        
        # Resolve IP
        try:
            ip = socket.gethostbyname(clean_ioc)
            enrichment.append(f"Resolved IP: {ip}")
            enrichment.append(get_ip_info(ip))
        except:
            enrichment.append("DNS Resolution: Failed")
    
    if not enrichment:
         return "No network enrichment available."
         
    return " ".join(enrichment)

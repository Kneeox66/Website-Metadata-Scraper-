import requests
import socket
import whois
from ipwhois import IPWhois
import dns.resolver
from dns.exception import DNSException
from colorama import Fore, Style, init

init(autoreset=True)

def get_ip_geo_location(domain):
    try:
        ip = socket.gethostbyname(domain)
        ip_info = IPWhois(ip)
        result = ip_info.lookup_rdap()
        return result
    except Exception as e:
        return f"Error getting IP geolocation: {str(e)}"

def get_dns_info(domain):
    dns_info = {}
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        dns_info['A Records'] = [ip.address for ip in a_records]
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_info['MX Records'] = [mx.exchange.to_text() for mx in mx_records]
        except DNSException:
            dns_info['MX Records'] = "No MX records found"
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            dns_info['CNAME Records'] = [cname.target.to_text() for cname in cname_records]
        except DNSException:
            dns_info['CNAME Records'] = "No CNAME records found"
        return dns_info
    except DNSException as e:
        return f"Error retrieving DNS records: {str(e)}"

def get_website_metadata(url):
    try:
        response = requests.get(url)
        headers = response.headers
        title = None
        if 'html' in response.headers['Content-Type']:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else 'No title found'
        expires_header = headers.get('Expires', 'No Expires header')
        domain = url.replace("http://", "").replace("https://", "").split('/')[0]
        geo_location = get_ip_geo_location(domain)
        dns_info = get_dns_info(domain)
        ports = [80, 443]
        metadata = {
            "URL": url,
            "Title": title,
            "Expires Header": expires_header,
            "IP Geo Location": geo_location,
            "HTTP Headers": headers,
            "DNS Info": dns_info,
            "Common Ports": ports,
        }
        return metadata
    except Exception as e:
        return f"Error scraping website: {str(e)}"

if __name__ == "__main__":
    url = input(Fore.RED + Style.BRIGHT + "\nEnter the website URL (e.g., http://example.com): ").strip()
    metadata = get_website_metadata(url)
    if isinstance(metadata, dict):
        print(Fore.RED + Style.BRIGHT + "\n" + "="*80)
        print(Fore.RED + Style.BRIGHT + "                         WEBSITE METADATA                         ")
        print(Fore.RED + Style.BRIGHT + "="*80)
        for key, value in metadata.items():
            print(Fore.RED + Style.BRIGHT + f"\n{key}:\n{'-'*80}\n{value}")
        print(Fore.RED + Style.BRIGHT + "\n" + "="*80)
    else:
        print(Fore.RED + Style.BRIGHT + metadata)

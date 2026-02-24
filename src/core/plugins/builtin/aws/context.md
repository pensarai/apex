# AWS Security Testing Context

The `aws` CLI is available. Use it for infrastructure reconnaissance alongside standard HTTP-based testing.

## Identifying AWS-Hosted Targets

Look for these indicators:
- **HTTP headers:** `x-amz-*`, `x-amzn-*`, `Server: AmazonS3`, `Server: awselb/2.0`
- **DNS:** CNAME to `*.amazonaws.com`, `*.cloudfront.net`, `*.elasticbeanstalk.com`
- **SSL certs:** Issued to `*.amazonaws.com` or AWS ACM certificates

```bash
# Fingerprint AWS hosting
curl -sI https://TARGET | grep -i 'x-amz\|x-amzn\|server.*amazon'
dig +short CNAME TARGET
```

## AWS CLI Reconnaissance

### Identity & Account Context

```bash
# Verify credentials and identity
aws sts get-caller-identity

# Get account aliases
aws iam list-account-aliases
```

### S3 Bucket Enumeration

```bash
# List all buckets in the account
aws s3 ls

# List contents of a bucket
aws s3 ls s3://BUCKET/ --recursive --human-readable

# Check bucket ACL
aws s3api get-bucket-acl --bucket BUCKET

# Check bucket policy
aws s3api get-bucket-policy --bucket BUCKET --output text | python3 -m json.tool

# Check public access block settings
aws s3api get-public-access-block --bucket BUCKET

# Test for public listing (no auth needed)
curl -s "https://BUCKET.s3.amazonaws.com/" | head -50
```

Brute-force common bucket names:
```bash
for suffix in "" "-dev" "-staging" "-prod" "-backup" "-logs" "-assets" "-uploads" "-data" "-internal"; do
  bucket="COMPANY${suffix}"
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com/")
  echo "${bucket}: ${status}"
done
```

### EC2 & Network Security

```bash
# Find overly permissive security groups (0.0.0.0/0 inbound)
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName,IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]].[FromPort,ToPort,IpProtocol]]' \
  --output table

# List all security groups with details
aws ec2 describe-security-groups --output json

# List EC2 instances and their public IPs
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,PrivateIpAddress,State.Name,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Find publicly exposed instances
aws ec2 describe-instances \
  --filters "Name=ip-address,Values=*" \
  --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress]' \
  --output table
```

### IAM Enumeration

```bash
# List IAM users
aws iam list-users --output table

# List IAM roles (look for overly permissive trust policies)
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table

# Get policy details for a role
aws iam list-attached-role-policies --role-name ROLE_NAME
aws iam list-role-policies --role-name ROLE_NAME

# Check for access keys
aws iam list-access-keys --user-name USERNAME
```

### Lambda Functions

```bash
# List Lambda functions
aws lambda list-functions \
  --query 'Functions[*].[FunctionName,Runtime,Handler,Environment.Variables]' \
  --output json

# Get function configuration (may contain env var secrets)
aws lambda get-function-configuration --function-name FUNCTION_NAME

# Get function URL config (check for AuthType: NONE)
aws lambda get-function-url-config --function-name FUNCTION_NAME 2>&1

# List event source mappings
aws lambda list-event-source-mappings
```

### API Gateway

```bash
# List REST APIs
aws apigateway get-rest-apis --output json

# List API stages (look for test/debug stages)
aws apigateway get-stages --rest-api-id API_ID

# Get API resources and methods
aws apigateway get-resources --rest-api-id API_ID --output json
```

### CloudFront

```bash
# List distributions
aws cloudfront list-distributions \
  --query 'DistributionList.Items[*].[Id,DomainName,Origins.Items[*].DomainName,Status]' \
  --output table
```

### Secrets Manager & SSM

```bash
# List secrets (names only — useful to understand what's stored)
aws secretsmanager list-secrets --query 'SecretList[*].[Name,Description]' --output table

# List SSM parameters (often contain config/secrets)
aws ssm describe-parameters --query 'Parameters[*].[Name,Type,Description]' --output table
```

## Common Attack Vectors

### SSRF to Instance Metadata Service (IMDS)
If the target has any SSRF, target the metadata endpoint:

**IMDSv1 (no token):** `http://169.254.169.254/latest/meta-data/`
**IMDSv2 (token required):**
```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Key paths:**
- `/latest/meta-data/iam/security-credentials/` — IAM role name
- `/latest/meta-data/iam/security-credentials/<role-name>` — temporary creds
- `/latest/user-data` — startup scripts, often contain secrets

**Bypass patterns:** `http://[::ffff:a9fe:a9fe]/`, `http://0xA9FEA9FE/`, DNS rebinding

### Credential Exposure
- **Key format:** `AKIA[A-Z0-9]{16}` (access key), 40-char base64 (secret)
- Search JS bundles: `curl -s "https://TARGET/static/js/main.*.js" | grep -oE 'AKIA[A-Z0-9]{16}'`
- If found, verify: `AWS_ACCESS_KEY_ID=AKIAXX AWS_SECRET_ACCESS_KEY=XX aws sts get-caller-identity`

### S3 Subdomain Takeover
If a CNAME points to `BUCKET.s3.amazonaws.com` but the bucket is deleted, register it.

![alt text](https://github.com/Hechtov/Photos/blob/master/SkyArk/AWStraceLogo.png "AWStrace")
  
**Analyzes AWS CloudTrail Logs - the module provides new valuable insights from CloudTrail logs.**  
It especially prioritizes risky sensitive IAM actions that potential attackers might use as part of their malicious actions as AWS Shadow Admins.  
The module analyzes the log files and produces informative csv result file with important details on each executed action in the evaluated environment.  
Security teams can use the results files to investigate sensitive actions, discover the entities that took those actions and reveal additional valuable details on each executed and logged action.  

# Quick Start  
SkyArk runs in PowerShell - and uses the free **AWS's PowerShell Module**, you can download "AWS Tools for Windows PowerShell" in advance:  
https://aws.amazon.com/powershell/  
[Direct download link](http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi)  
The tool could also prompt you and automatically install the AWS PowerShell module for you.
  
Open PowerShell in SkyArk folder with running scripts permission:  
"powershell -ExecutionPolicy Bypass -NoProfile"
  
**If you want to use only AWStrace from SkyArk tool:**
```
1. Import-Module .\AWStrace.ps1 -force
```

**Perform AWStrace analysis:**
```
2. Download-CloudTrailLogFiles -AccessKeyID [AccessKeyID]  -SecretKey [SecretAccessKey] -DefaultRegion [AWS-region] -TrailBucketName [CloutTrail-S3bucket] -BucketKeyPrefix [A-Folder-Prefix-To-The-Trail's-Logs]
Example:
Download-CloudTrailLogFiles -AccessKeyID AKIAIKYBE12345HDS -SecretKey pdcWZR6Mdsffsdf9ub3j/dnhxRh1d -DefaultRegion "us-east-1" -TrailBucketName "cloudtrail-bucketname" -BucketKeyPrefix "AWSLogs/412345678910/CloudTrail/us-east-1/2018/03/08"

3. Analyze-CloudTrailLogFiles
```
  
# Permissions for AWStrace - ReadOnly
Read-Only for the CloudTrail's S3 bucket - to download and analyze the log files
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets"
            ],
            "Resource": "arn:aws:s3:::*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": "arn:aws:s3:::cloudtrail-bucketname"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:Get*",
                "s3:List*",
                "s3:Copy*"
            ],
            "Resource": "arn:aws:s3:::cloudtrail-bucketname/*"
        }
    ]
}
```

---

## Linux / Python Version

`awstrace.py` is a Python 3 port of this module that runs on Linux without PowerShell.

### Install

```bash
pip install -r requirements.txt   # boto3 only; run from the SkyArk root
```

Python ≥ 3.9 is required.

### AWS Credentials

`awstrace.py` uses the standard **boto3 credential chain** — no `.env` file is read.
Supply credentials through any of these methods (in priority order):

| Method | How |
|--------|-----|
| Environment variables | `export AWS_ACCESS_KEY_ID=...`  `export AWS_SECRET_ACCESS_KEY=...`  `export AWS_SESSION_TOKEN=...` (optional) |
| AWS CLI named profile | `export AWS_PROFILE=myprofile` or pass `--profile myprofile` |
| `~/.aws/credentials` | Standard credentials file written by `aws configure` |
| IAM instance / task role | Automatically used when running on EC2 / ECS / Lambda |

To load credentials from a `.env` file without printing them:

```bash
set -a && source /path/to/.env && set +a
```

### Run

```bash
# via dispatcher (from SkyArk root)
./run.sh trace download --bucket my-trail-bkt \
                        --prefix AWSLogs/123456789012/CloudTrail/us-west-2/2026/05 \
                        --local-path ./logs
./run.sh trace analyze  --local-path ./logs
./run.sh trace run      --bucket my-trail-bkt --prefix ... --local-path ./logs

# directly
python3 AWStrace/awstrace.py download --bucket my-trail-bkt --prefix ... --local-path ./logs
python3 AWStrace/awstrace.py analyze  --local-path ./logs
```

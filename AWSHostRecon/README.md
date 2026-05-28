# AWSHostRecon - AWS Host Reconnaissance Tool         

**AWSHostRecon is only a draft script that have not yet been finished.**  
**It's just for playing around with the concept. Good luck.**  

Written by: Asaf Hecht (@Hechtov)               
More Updates on Twitter                    

It's time to discover critical AWS information on the target hosts!

HOW TO RUN:  
**Use the command:**
```
From PowerShell:  
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cyberark/SkyArk/master/AWSHostRecon/AWSHostRecon.ps1')
```

---

## Linux / Python Version

`awshostrecon.py` is a Python 3 port of this module that runs natively on Linux.

### Install

```bash
pip install -r requirements.txt   # run from the SkyArk root
```

Python ≥ 3.9 is required.

### Run

```bash
# via dispatcher (from SkyArk root)
./run.sh recon [--quick] [--output recon.json]

# directly
python3 AWSHostRecon/awshostrecon.py --quick --output recon.json
```

> **Note:** `awshostrecon.py` performs local host reconnaissance (env vars, credential
> files, browser history, filesystem search) and does **not** make AWS API calls,
> so no AWS credentials are required.

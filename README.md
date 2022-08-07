# Google Apis OAuth2 Application

---
```text
    This repository handles the creation of fresh 
    JWT to users who willing to use Google APIs    
```
--- 
## How To

#### 1. Clone Repo
```shell
 $ git clone https://github.com/yahav-h/GoogleApisOAuthApplication.git
```

#### 2. Create a Virtual Environment 
```shell
 $ /usr/bin//python3 -m venv venv3
```

#### 3. Dependencies Installation
```shell
 $ ./venv3/bin/python3 -m pip install -r dependencies.txt
```

#### 4. Harvesting Tokens
```shell
  # Using on PRODUCTION database
  $ ./venv3/bin/python3 ./googleapi_Auth.py --farm farm-1 --clusters c1,c2,c3
  # Using on DEV database
  $ ./venv3/bin/python3 ./googleapi_Auth.py --farm farm-1 --clusters c1,c2,c3 --debug 1 
```
---

## Tool Configuration Files
#### Configuration File : `resources/properties.yml`
```yaml
# this configuration file should be edited prior to the execution
database:
  host: "<DATABASE_IP>"
  port: "<DATABASE_PORT>"
  user: "<DATABASE_USERNAME>"
  passwd: "<DATABASE_USER_PASSWORD>"
  dbname: "<DATABASE_NAME>"
security:
  password: "<ADMIN_PASSWORD>"
oauth:
  installed:
    client_id: "<GOOGLE_CLIENT_ID>"
    project_id: "<GOOGLE_PROJECT_ID>"
    auth_uri: "https://accounts.google.com/o/oauth2/auth"
    token_uri: "https://oauth2.googleapis.com/token"
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs"
    client_secret: "<GOOGLE_CLIENT_SECRET>"
    redirect_uris:
      - "http://localhost"
```

#### Configuration File : `resources/mapping.yml`
```yaml
# this configuration file should include the farms, clusters and their associated users
farm-1: 
  c4:
    # please note that each user should be added as follows <USER@EMAIL.COM:GOOGLE_USER_ID>
    - "userX@subdomain.domain.net:1xcytpi0nngox6"
    - "userY@subdomain.domain.net:3664s552f0evwn"
    - "userZ@subdomain.domain.net:2dj1y382169vsk"
```
# googleapis-oauth2-app

***

```text
    This repository handles the creation of fresh 
    JWT to users who willing to use Google APIs    
```
*** 
## How To:
Follow the instructions!


1.  clone the repository
```shell
 $ git clone https://github.com/yahav-h/GoogleApisOAuthApplication.git
```
2. create a new virtual environment
```shell
 $ /usr/bin//python3 -m venv venv
```
3. install all dependencies
```shell
 $ ./venv/bin/python3 -m pip install -r dependencies.txt
```
4. check the script menu
```shell
 $ ./venv/bin/python3 googleapis_Auth.py -h
 
usage: googleapis_Auth.py [-h] -F FARM -C CLUSTERS [-D DEBUG_ENV]

optional arguments:
  -h, --help            show this help message and exit
  --farm FARM
  --clusters CLUSTERS
  --debug DEBUG_ENV
```
***
E.g. script run on DEBUG ENV!
```shell
 $ ./venv/bin/python3 googleapis_Auth.py --farm my-farm-1 --clusters c1,c2,c3,c4 --debug 1
```
E.g. script run on PRODUCTION ENV!
```shell
 $ ./venv/bin/python3 googleapis_Auth.py --farm my-farm-1 --clusters c1,c2,c3,c4
```

### NOTES:
Using `--debug` will trigger a local database, this made for testing changes in the source code.

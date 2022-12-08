from os import getcwd
from os.path import join, dirname, abspath
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from yaml import load, Loader

def loadmapping():
    data = None
    with open(join(getcwd(), 'resources', 'mapping.yml'), 'r') as out_stream:
        data = load(out_stream, Loader)
    return data

def loadproperties():
    data = None
    with open(join(dirname(abspath(__file__)), 'resources', 'properties.yml'), 'r') as out_stream:
        data = load(out_stream, Loader)
    return data

def getdatatbaseinfo(): return loadproperties().get("database")
def getclientconfig(): return loadproperties().get("oauth")
def getsecuritypassword(): return loadproperties().get("security").get("password")

def getwebdriver():
    chrome_options = Options()
    d = DesiredCapabilities.CHROME
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--disable-setuid-sandbox")
    chrome_options.add_argument("--remote-debugging-port=9222")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36")
    chrome_options.add_argument("--headless")
    d['loggingPrefs'] = {'browser': 'ALL'}
    driver_path = ChromeDriverManager().install()
    driver = webdriver.Chrome(executable_path=driver_path, options=chrome_options, desired_capabilities=d)
    driver.delete_all_cookies()
    return driver

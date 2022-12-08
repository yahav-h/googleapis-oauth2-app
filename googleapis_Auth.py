import sys
import time
import urllib
from pickle import dumps
from threading import Thread
from requests_oauthlib import OAuth2Session
from flask import Flask, request
from werkzeug.serving import make_server
import google_auth_oauthlib
from helpers import getwebdriver, getclientconfig, getsecuritypassword, loadmapping
from selenium.webdriver.common.action_chains import ActionChains
from database import get_session, init_debug_db
from dao import TokenUserRecordsDAO
from locators import OAuthUserConsentTags, GoogleConsoleSecurityTags, AdminLoginTags

PORT = 8000
HOST = '0.0.0.0'
SCOPES = ['https://mail.google.com/', 'https://www.googleapis.com/auth/drive']
PASSWORD = getsecuritypassword()
CLIENT_CONFIG = getclientconfig()
REDIRECT_URL = CLIENT_CONFIG.get("installed").get("redirect_uris")[0]
app_id = CLIENT_CONFIG.get("installed").get("client_id")
app_secret = CLIENT_CONFIG.get("installed").get("client_secret")
token_url = CLIENT_CONFIG.get("installed").get("token_uri")
ADMIN_USER_SECURITY_URL = "https://admin.google.com/u/2/ac/users"

ADMIN_USER_PREFIX = "user1@"
logged_in = False
driver = None
admin_driver = None
app = Flask(__name__)
flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_CONFIG, SCOPES)

def extract_params(url):
    code, state, scope = None, None, None
    url = urllib.parse.unquote(url)
    for _ in url.split('&'):
        if 'code' in _:
            code = _.split('=')[-1]
        elif 'state' in _:
            state = _.split('=')[-1]
        elif 'scope' in _:
            scope = _.split('=')[-1].split(',').pop()
    return code, state, scope

if '--debug' in sys.argv and bool(int(sys.argv[sys.argv.index('--debug')+1])):
    init_debug_db()

@app.route("/", methods=["GET"])
def callback():
    """
    a callback which occurs after we finish the User Consent Flow .
    the OAuth2 application will redirect a response with the following
    query parameters:
        - state : State for authority access (used for OAuth2 validation)
        - code  : Code to use for JWT conversion
        - scope : Given Accessibility Scopes

    :return: json={"stored": True} , status_code=200
    """
    code, state, scope = extract_params(request.url)
    # we extract a JWT by using the State, Code and Scopes
    pkl_token = get_token_from_code(code=code, expected_state=state, scopes=scope)
    # searching the user inside the database records
    dao = TokenUserRecordsDAO.query.filter_by(user=user).first()
    # if found we update the JWT
    if dao:
        dao.token = pkl_token
    # is not , we create a new record with the relevant JWT
    else:
        dao = TokenUserRecordsDAO(user=user, token=pkl_token)
    # and adding the new Data Access Object into the database
    try:
        with get_session() as Session:
            Session.add(dao)
    except Exception as e:
        print("[!] Error " + str(e))
    # return a json response
    print("[§] JWT Stored!")
    return {"stored": True}, 200


def get_token_from_code(code, expected_state, scopes):
    # using OAuth2Session object to access OAuth2 Application
    redirect = REDIRECT_URL + ":" + str(PORT)
    aad_auth = OAuth2Session(app_id, state=expected_state, scope=scopes, redirect_uri=redirect)
    print("[*] OAuth2Session Initiated -> %s" % hex(id(aad_auth)))
    print("[*] fetching JWT")
    # fetching new token
    token = aad_auth.fetch_token(token_url, client_secret=app_secret, code=code)
    print("[+] Got JWT -> %s" % token)
    # dumping as bytes using pickle
    return dumps(token)


class ServerThread(Thread):
    """
        ServerThread object is a child of Thread,
        it will work in the background and will serve
        a route "/" to catch the OAuth2 callbacks
    """
    def __init__(self, app):
        super(ServerThread, self).__init__()
        # creating a server
        self.srv = make_server(HOST, PORT, app)
        # keeping the Server Session Context in the Thread Scope
        self.ctx = app.app_context()
        # Pushing the Session Context
        self.ctx.push()

    def run(self):
        # override the `run` method of Thread to serve the server
        print('[*] starting HTTP listener on port 8000')
        self.srv.serve_forever()

    def shutdown(self):
        # shutdown the web server
        print("[!] HTTP listener shutdown")
        self.srv.shutdown()

def cleanup(this_driver):
    global logged_in
    print("[!] Cleanup started for %s" % hex(id(this_driver)))
    # check if this_driver exist
    if this_driver:
        # remove all cookies
        this_driver.delete_all_cookies()
        # close the session
        this_driver.quit()
    logged_in = False

def user_consent_flow(target_user, authorization_url):
    global driver
    # create a WebDriver for user consent flow
    driver = getwebdriver()
    # navigate to the authorization url
    driver.get(authorization_url)
    print("[*] Authorization URL Navigation Successful! ")
    if "Choose an account" in driver.page_source:
        print("choosing an account")
        if driver.find_element(*OAuthUserConsentTags.ACCOUNT_SELECT_BUTTON).is_displayed():
            driver.find_element(*OAuthUserConsentTags.ACCOUNT_SELECT_BUTTON).click()
    time.sleep(5)
    try:
        """
            Complete the user consent flow using Selenium . 
            this is the only method available since Google 
            force us the give User Consent by Logging In via Browser
        """
        if driver.find_element(*OAuthUserConsentTags.EMAIL_FIELD).is_displayed():
            driver.find_element(*OAuthUserConsentTags.EMAIL_FIELD).send_keys(target_user)
            print("[+] set username -> %s" % target_user)
        time.sleep(5)
        if driver.find_element(*OAuthUserConsentTags.NEXT_BUTTON).is_displayed():
            driver.find_element(*OAuthUserConsentTags.NEXT_BUTTON).click()
        time.sleep(5)
        if driver.find_element(*OAuthUserConsentTags.PASSWORD_FIELD).is_displayed():
            driver.find_element(*OAuthUserConsentTags.PASSWORD_FIELD).send_keys(PASSWORD)
            print("[+] set password -> %s" % PASSWORD)
        time.sleep(5)
        if driver.find_element(*OAuthUserConsentTags.NEXT_BUTTON).is_displayed():
            driver.find_element(*OAuthUserConsentTags.NEXT_BUTTON).click()
            print("[+] click on next button")
        time.sleep(5)
        if driver.find_element(*OAuthUserConsentTags.ALLOW_BUTTON).is_displayed():
            driver.find_element(*OAuthUserConsentTags.ALLOW_BUTTON).click()
            print("[+] set allow access -> %s" % True)
        time.sleep(5)
    except Exception as e:
        print(e)
    # catch the current url
    url = driver.current_url
    return url, driver

def get_users(farm=None, clusters=None):
    print("[!] Reading mapping file...")
    print("[!] Using FARM %s" % farm)
    print("[!] Using CLUSTERS %s" % clusters)
    admin_usr = None
    all_users = []
    # load users mapping file
    data = loadmapping()
    # exit if the given farm does not exist
    if not farm or farm not in data:
        print("Must have Farm as argument!")
        print(f"Farm argument should not have spaces!") if ' ' in farm else None
        sys.exit(1)
    # override data with farm object
    data = data.get(farm)
    # split all clusters to a list
    clusters = clusters.split(',')
    # Loop through each cluster in the given clusters
    for cluster in clusters:
        # if cluster does not exist in data, skip
        if cluster not in data:
            print(f"[ERROR] Cluster {cluster} was not found under Farm {farm}!")
            continue
        # extend users list with the associated users undr the cluster object
        all_users.extend(data.get(cluster))
    # loop over the extracted users and find the Admin User
    for i, usr in enumerate(all_users):
        # check it the current user is Admin user
        if ADMIN_USER_PREFIX in usr:
            admin_usr = usr or all_users[i]
            break
    return admin_usr, all_users

def harvest_googleapis_token(given_user):
    global driver, flow
    # Create an entry for InstalledAppFlow to bypass OAuth2 WebApp (using Desktop App)
    print("[*] GoogleFlowObject -> %s" % hex(id(flow)))
    # override the redirection url to http://localhost:8000
    flow.redirect_uri = "%s:%d" % (REDIRECT_URL, PORT)
    print("[*] Set Redirect URL -> %s" % flow.redirect_uri)
    # retrieve authorization url and state
    authorization_url, _ = flow.authorization_url()
    print("[*] Set Authorization URL -> %s" % authorization_url)
    # delegate the current user and authorization url to approve user consent flow
    redirection_url, driver = user_consent_flow(given_user, authorization_url)
    print("[@] REDIRECT -> %s" % redirection_url)
    # cleaning all cookies from the current user session
    cleanup(driver)

def disable_login_challenge(admin_email, google_user):
    global admin_driver, logged_in
    admin_driver = getwebdriver()
    # attempting to navigate into Users Security Page
    # security_url = ADMIN_USER_SECURITY_URL % google_user
    security_url = ADMIN_USER_SECURITY_URL
    admin_driver.get(security_url)
    print("[+] Google Console Security URL  -> %s" % security_url)
    print("[+] trying to bypass Login Challenge using -> %s:%s" % (admin_email, PASSWORD))
    time.sleep(10)
    # check in Admin has authenticated before to prevent time consumption on re-authentication
    if not logged_in:
        try:
            if admin_driver.find_element(*AdminLoginTags.EMAIL_FIELD).is_displayed():
                admin_driver.find_element(*AdminLoginTags.EMAIL_FIELD).send_keys(admin_email)
            time.sleep(5)
            if admin_driver.find_element(*AdminLoginTags.NEXT_BUTTON).is_displayed():
                admin_driver.find_element(*AdminLoginTags.NEXT_BUTTON).click()
            time.sleep(5)
            if admin_driver.find_element(*AdminLoginTags.PASSWORD_FIELD).is_displayed():
                admin_driver.find_element(*AdminLoginTags.PASSWORD_FIELD).send_keys(PASSWORD)
            time.sleep(5)
            if admin_driver.find_element(*AdminLoginTags.NEXT_BUTTON).is_displayed():
                admin_driver.find_element(*AdminLoginTags.NEXT_BUTTON).click()
            logged_in = True
        except Exception as e:
            if admin_driver.find_element(*GoogleConsoleSecurityTags.SCROLL_TARGET).is_displayed():
                logged_in = True
                print("[!] Admin Session is already open")
    else:
        print(f"[*] Admin User {admin_email} is already Logged In!")
    time.sleep(5)
    # click the right user mail
    admin_driver.find_element("xpath", './/div[contains(text(), "%s")]/../../..//a' % user).click()
    time.sleep(5)
    # navigate to the Security View
    admin_driver.find_element(*GoogleConsoleSecurityTags.SECURITY_HEADER).click()
    time.sleep(5)
    # find your scroll object
    scroll_to_elem = admin_driver.find_element(*GoogleConsoleSecurityTags.SCROLL_TARGET)
    # create an Action Based session
    actions = ActionChains(admin_driver)
    # moving browser focus to the scrolling object
    actions.move_to_element(scroll_to_elem).perform()
    time.sleep(5)
    # open the Login challenge section
    admin_driver.find_element(*GoogleConsoleSecurityTags.LOGIN_CHALLENGE_HEADER).click()
    time.sleep(5)
    # disable the Login challenge for the next 10 minutes for that particular user
    admin_driver.find_element(*GoogleConsoleSecurityTags.DISABLE_CHALLENGE_BUTTON).click()
    print("[*] Login Challenge for %s completed successfully" % user)
    cleanup(admin_driver)
    return

def separate_google_id_from(given_user):
    # splits the email and user ID
    """ E.g.  userX@sub.domain.net:ABCD1234 """
    u, uid = given_user.split(":")
    print("[*] USER -> %s" % u)
    print("[*] UID  -> %s" % uid)
    return u, uid


if __name__ == "__main__":
    import os
    import argparse
    os.system("clear")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--user',
        metavar="USER",
        type=str, required=False,
        help="will use a specific user | E.g. --user userX@subdomain.domain.com:null DBUG ..."
    )
    parser.add_argument(
        '--password',
        metavar="PASSWORD",
        type=str, required=False,
        help="will use the PASSWORD of a specific user | E.g. USER ... --password Abc123&*(] DBUG ..."
    )
    parser.add_argument(
        '--farm',
        metavar="FARM",
        type=str, required=False,
        help="will use a specific farm | E.g. --farm farm-1 CLUSTER ..."
    )
    parser.add_argument(
        '--clusters',
        metavar="CLUSTERS",
        type=str, required=False,
        help="will use specific/s cluster/s of a farm | E.g. FARM ... --clusters c1,c2,3 || --clusters c1"
    )
    parser.add_argument(
        '--debug',
        metavar="DEBUG_ENV", type=str,
        required=False, default="0",
        help="will use a DEV instead of PRODUCTION database | E.g. FARM ... CLUSTERS ... --debug 1 || --debug 0"
    )
    args = parser.parse_args()
    # using debug mode to creat a local DB named `debug.db`
    if args.debug and bool(int(args.debug)):
        print('[!] [DEBUG %s]' % bool(int(args.debug)))
        print('[*] We will use LOCALHOST database!')
    else:
        print('[!] [DEBUG %s]' % bool(int(args.debug)))
        print('[*] We will use PRODUCTION database!')
    if args.user:
        admin_user, users = f"{ADMIN_USER_PREFIX}%s" % args.user.split("@")[-1], [args.user]
        if args.password:
            PASSWORD = args.password
    elif args.farm and args.clusters:
        # get all users associated to given FARM + CLUSTER from ./resources/mapping.json
        admin_user, users = get_users(farm=args.farm, clusters=args.clusters)
    if not admin_user:
        print("[*] Check your arguments and mapping file!")
        print("[!] Exiting...")
        sys.exit(1)
    # separates the USER_ID from the email
    # admin_user, admin_user_id = separate_google_id_from(admin_user)
    # Create a Server Thread using Flask API to catch the OAuth2 Callback
    server = ServerThread(app)
    # start the ServerThread
    server.start()
    # Loop through each user in users
    for user in users:
        # created a dedicated WebDriver for Admin User
        # separates the USER_ID from the email
        # user, user_id = separate_google_id_from(user)
        # check it the current user is not an admin type user
        if user != admin_user:
            # disable login challenge by admin privileges from user UserID
            disable_login_challenge(admin_user, user)
        # harvesting google apis token using OAuth2 scenario
        harvest_googleapis_token(user)
    # shutdown the server thread
    server.shutdown()

import time
import urllib
from pickle import dumps, loads
from threading import Thread
from requests_oauthlib import OAuth2Session
from flask import Flask, request
from werkzeug.serving import make_server
import google_auth_oauthlib
from helpers import getwebdriver, getclientconfig, getsecuritypassword, loadmapping, get_logs_dir, ActionChains
from database import get_session, init_debug_db
from dao import UserDataAccessObject
from dto import UserDataTransferObject
from locators import OAuthUserConsentTags, AdminLoginTags, GoogleConsoleSecurityTags, GoogleConsoleUsersTags
from logging.handlers import RotatingFileHandler
from datetime import datetime
import logging


logging.Formatter(logging.BASIC_FORMAT)
logger = logging.getLogger('ServiceLogger')
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(
    filename='%s/runtime.log' % get_logs_dir(),
    maxBytes=8182,
    backupCount=5,
)
logger.addHandler(handler)

PORT = 80
HOST = '0.0.0.0'
SCOPES = ['https://mail.google.com/', 'https://www.googleapis.com/auth/drive']
PASSWORD = getsecuritypassword()
CLIENT_CONFIG = getclientconfig()
REDIRECT_URL = CLIENT_CONFIG.get("installed").get("redirect_uris")[0]
app_id = CLIENT_CONFIG.get("installed").get("client_id")
app_secret = CLIENT_CONFIG.get("installed").get("client_secret")
token_url = CLIENT_CONFIG.get("installed").get("token_uri")
ADMIN_USERS_URL = "https://admin.google.com/u/4/ac/users"
admin_email = "user1@%s"
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


@app.before_first_request
def init_database():
    init_debug_db()
    logger.info("database initialized")


@app.route("/", methods=["GET"])
def callback():
    global email
    """
    a callback which occurs after we finish the User Consent Flow .
    the OAuth2 application will redirect a response with the following
    query parameters:
        - state : State for authority access (used for OAuth2 validation)
        - code  : Code to use for JWT conversion
        - scope : Given Accessibility Scopes

    :return: json={"stored": True} , status_code=200
    """
    # code, state, scope = extract_params(request.url)
    params = request.args
    code = params.get("code")
    state = params.get("state")
    scope = params.get("scope")
    # we extract a JWT by using the State, Code and Scopes
    pkl_token = get_token_from_code(code=code, expected_state=state, scopes=scope)
    # searching the user inside the database records
    dao = UserDataAccessObject.query.filter_by(user=email).first()
    # if found we update the JWT
    if dao:
        dao.token = pkl_token
    # is not , we create a new record with the relevant JWT
    else:
        dao = UserDataAccessObject(user=email, token=pkl_token)
    # and adding the new Data Access Object into the database
    try:
        with get_session() as Session:
            Session.add(dao)
    except Exception as e:
        logger.error("%s | error | %s" % (datetime.now().isoformat(), str(e)))
        return {"stored": False}, 400
    # return a json response
    logger.info("%s | JWT Stored" % datetime.now().isoformat())
    return {"stored": True}, 200


@app.route("/refreshToken", methods=["GET"])
def refresh_token_for_user():
    user_mail = request.args.get("email")
    logger.info("%s | refresh_token_for_user (params: %s)" % (datetime.now().isoformat(), user_mail))
    dao = UserDataAccessObject.query.filter_by(user=user_mail).first()
    if not dao:
        logger.info("%s | no such email in database, return ( {}, 404 )" % datetime.now().isoformat())
        response = {}, 400
        return response
    dto = UserDataTransferObject(uid=dao.id, user=dao.user, token=dao.token)
    dto.token = loads(dto.token)
    now = time.time()
    expire_time = dto.token.get('expires_at') - 300
    if now >= expire_time:
        aad_auth = OAuth2Session(
            app_id, token=dto.token,
            scope=None, redirect_uri=REDIRECT_URL
        )
        refresh_params = {
            'client_id': app_id,
            'client_secret': app_secret
        }
        new_token = aad_auth.refresh_token(token_url, **refresh_params)
        try:
            with get_session() as Session:
                dao.token = dumps(new_token)
                Session.add(dao)
            dto.token = new_token
        except Exception as e:
            print("Error", str(e))
            logger.error("%s" % str(e))
            response = {"stored": False}, 400
            logger.info("%s | not data found -> %s" % (datetime.now().isoformat(), str(response)))
            return response
    response = {"stored": True}, 201
    logger.info("%s | data found -> %s" % (datetime.now().isoformat(), str(response)))
    return response


@app.route("/createToken", methods=["GET"])
def first_time_create_token():
    global admin_driver, driver, email
    email = request.args.get("email")
    logger.info("%s | first_time_create_token (params: %s)" % (datetime.now().isoformat(), email))
    try:
        # Loop through each user in users
        disable_login_challenge(email)
        harvest_googleapis_token(email)
        response = {"stored": True}, 201
        logger.info("%s | data found -> %s" % (datetime.now().isoformat(), str(response)))
        return response
    except Exception as e:
        print("Error", str(e))
        logger.error("%s | %s" % (datetime.now().isoformat(), str(e)))
        response = {"stored": False}, 400
        logger.info("%s | not data found -> %s" % (datetime.now().isoformat(), str(response)))
        return response


@app.route("/users", methods=["GET"])
def get_user_data():
    global driver, flow
    user_mail = request.args.get("email")
    logger.info("%s | get_user_data (params: %s)" % (datetime.now().isoformat(), user_mail))
    dao = UserDataAccessObject.query.filter_by(user=user_mail).first()
    if not dao:
        logger.info("%s | no such email in database, return ( {}, 404 )" % datetime.now().isoformat())
        return {}, 404
    dto = UserDataTransferObject(uid=dao.id, user=dao.user, token=dao.token)
    dto.token = loads(dto.token)
    response = {"id": dto.uid, "user": dto.user, "token": dto.token}, 200
    logger.info("%s | data found -> %s" % (datetime.now().isoformat(), str(response)))
    return response


def get_token_from_code(code, expected_state, scopes):
    # using OAuth2Session object to access OAuth2 Application
    redirect = REDIRECT_URL
    aad_auth = OAuth2Session(app_id, state=expected_state, scope=scopes, redirect_uri=redirect)
    logger.info("%s | OAuth2Session Initiated -> %s" % (datetime.now().isoformat(), hex(id(aad_auth))))
    logger.info("%s | fetching JWT" % datetime.now().isoformat())
    # fetching new token
    token = aad_auth.fetch_token(token_url, client_secret=app_secret, code=code)
    logger.info("%s | Got JWT -> %s" % (datetime.now().isoformat(), token))
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
    # navigate to the authorization url
    driver.get(authorization_url)
    logger.info("%s | Authorization URL Navigation Successful" % datetime.now().isoformat())
    if "Choose an account" in driver.page_source:
        logger.debug("%s | choosing an account page appear" % datetime.now().isoformat())
        if driver.find_element(*OAuthUserConsentTags.ACCOUNT_SELECT_BUTTON).is_displayed():
            driver.find_element(*OAuthUserConsentTags.ACCOUNT_SELECT_BUTTON).click()
    time.sleep(3)
    try:
        """
            Complete the user consent flow using Selenium . 
            this is the only method available since Google 
            force us the give User Consent by Logging In via Browser
        """
        if driver.find_element(*OAuthUserConsentTags.EMAIL_FIELD).is_displayed():
            driver.find_element(*OAuthUserConsentTags.EMAIL_FIELD).send_keys(target_user)
            logger.debug("%s | set username -> %s" % (datetime.now().isoformat(), target_user))
        time.sleep(3)
        if driver.find_element(*OAuthUserConsentTags.NEXT_BUTTON).is_displayed():
            driver.find_element(*OAuthUserConsentTags.NEXT_BUTTON).click()
        time.sleep(3)
        if driver.find_element(*OAuthUserConsentTags.PASSWORD_FIELD).is_displayed():
            driver.find_element(*OAuthUserConsentTags.PASSWORD_FIELD).send_keys(PASSWORD)
            logger.debug("%s | set password -> %s" % (datetime.now().isoformat(), PASSWORD))
        time.sleep(3)
        if driver.find_element(*OAuthUserConsentTags.NEXT_BUTTON).is_displayed():
            driver.find_element(*OAuthUserConsentTags.NEXT_BUTTON).click()
            logger.debug("%s | click on next button" % datetime.now().isoformat())
        time.sleep(3)
        if driver.find_element(*OAuthUserConsentTags.ALLOW_BUTTON).is_displayed():
            driver.find_element(*OAuthUserConsentTags.ALLOW_BUTTON).click()
            logger.info("[+] set allow access -> %s" % True)
        time.sleep(3)
    except Exception as e:
        logger.error("%s | error | %s" % (datetime.now().isoformat(), str(e)))
    # catch the current url
    url = driver.current_url
    return url, driver

def harvest_googleapis_token(given_user):
    global driver, flow
    driver = getwebdriver()
    # Create an entry for InstalledAppFlow to bypass OAuth2 WebApp (using Desktop App)
    logger.info("%s | GoogleFlowObject -> %s" % (datetime.now().isoformat(), hex(id(flow))))
    # override the redirection url to http://localhost
    if ':' in REDIRECT_URL:
        flow.redirect_uri = REDIRECT_URL
    else:
        flow.redirect_uri = "%s:%d/" % (REDIRECT_URL, PORT)
    logger.info("%s | Set Redirect URL -> %s" % (datetime.now().isoformat(), flow.redirect_uri))
    # retrieve authorization url and state
    authorization_url, _ = flow.authorization_url()
    logger.info("%s | Set Authorization URL -> %s" % (datetime.now().isoformat(), authorization_url))
    # delegate the current user and authorization url to approve user consent flow
    redirection_url, driver = user_consent_flow(given_user, authorization_url)
    logger.info("%s | REDIRECT -> %s" % (datetime.now().isoformat(), redirection_url))
    # cleaning all cookies from the current user session
    driver.delete_all_cookies()
    cleanup(driver)
    return

def disable_login_challenge(email):
    global admin_driver, admin_email
    admin_driver = getwebdriver()
    # building admin_email
    admin_email = admin_email % email.split("@")[-1]
    # check in Admin has authenticated before to prevent time consumption on re-authentication
    logger.info("%s | admin_login_flow (params: %s, %s" % (datetime.now().isoformat(), admin_driver, admin_email))
    admin_login_flow(admin_driver=admin_driver, admin_email=admin_email)
    time.sleep(5)
    method, locator = GoogleConsoleUsersTags.GENERIC_USER
    locator = locator % email
    if admin_driver.find_element(*(method, locator)).is_displayed():
        admin_driver.find_element(*(method, locator)).click()
        logger.info("%s | enters into user %s console page" % (datetime.now().isoformat(), email))
    time.sleep(5)
    # enters Security View
    if admin_driver.find_element(*GoogleConsoleUsersTags.SECURITY_HEADER).is_displayed():
        admin_driver.find_element(*GoogleConsoleUsersTags.SECURITY_HEADER).click()
        logger.info("%s | enters into Security View" % datetime.now().isoformat())
    time.sleep(5)
    # find your scroll object
    scroll_to_elem = admin_driver.find_element(*GoogleConsoleSecurityTags.SCROLL_TARGET)
    # create an Action Based session
    actions = ActionChains(admin_driver)
    # moving browser focus to the scrolling object
    actions.move_to_element(scroll_to_elem).perform()
    time.sleep(5)
    # open the Login challenge section
    if admin_driver.find_element(*GoogleConsoleSecurityTags.LOGIN_CHALLENGE_HEADER).is_displayed():
        admin_driver.find_element(*GoogleConsoleSecurityTags.LOGIN_CHALLENGE_HEADER).click()
        logger.info("%s | open login challenge view" % datetime.now().isoformat())
    time.sleep(5)
    # disable the Login challenge for the next 10 minutes for that particular user
    if admin_driver.find_element(*GoogleConsoleSecurityTags.DISABLE_CHALLENGE_BUTTON).is_displayed():
        admin_driver.find_element(*GoogleConsoleSecurityTags.DISABLE_CHALLENGE_BUTTON).click()
        logger.info("%s | disabling login challenge on user %s for 10 minutes" % (datetime.now().isoformat(), email))
    time.sleep(5)
    admin_driver.delete_all_cookies()
    cleanup(admin_driver)
    return

def admin_login_flow(admin_driver, admin_email):
    global logged_in
    # attempting to navigate into Users Security Page
    admin_driver.get(ADMIN_USERS_URL)
    print("[+] Google Console Security URL  -> %s" % ADMIN_USERS_URL)
    print("[+] trying to bypass Login Challenge using -> %s:%s" % (admin_email, PASSWORD))
    time.sleep(10)
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
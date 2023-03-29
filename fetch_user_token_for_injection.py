import time
import base64
import flask
import requests
import helpers
import google_auth_oauthlib
import requests_oauthlib
import datetime
import database
import pickle
import locators


app = flask.Flask(__name__)
email = None
action = None
CLIENT_CONFIG = helpers.getclientconfig()
CLIENT_ID = CLIENT_CONFIG.get("installed").get("client_id")
CLIENT_SECRET = CLIENT_CONFIG.get("installed").get("client_secret")
TOKEN_URI = CLIENT_CONFIG.get("installed").get("token_uri")
REDIRECT_URI = CLIENT_CONFIG.get("installed").get("redirect_uris").pop()
SCOPES = ['https://www.googleapis.com/auth/drive', 'https://mail.google.com/']
flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_CONFIG, SCOPES)

def user_consent_crawler(auth_uri, email):
    driver = helpers.getwebdriver()
    driver.implicitly_wait(5)
    driver.get(auth_uri)
    try:
        if driver.find_element(*locators.OAuthUserConsentTags.ACCOUNT_SELECT_BUTTON).is_displayed():
            driver.find_element(*locators.OAuthUserConsentTags.ACCOUNT_SELECT_BUTTON).click()
    except:
        print("[-] Use another account page does not display")
    try:
        time.sleep(3)
        if driver.find_element(*locators.OAuthUserConsentTags.EMAIL_FIELD).is_displayed():
            driver.find_element(*locators.OAuthUserConsentTags.EMAIL_FIELD).send_keys(email)
        time.sleep(3)
        if driver.find_element(*locators.OAuthUserConsentTags.NEXT_BUTTON).is_displayed():
            driver.find_element(*locators.OAuthUserConsentTags.NEXT_BUTTON).click()
        time.sleep(3)
        if driver.find_element(*locators.OAuthUserConsentTags.PASSWORD_FIELD).is_displayed():
            driver.find_element(*locators.OAuthUserConsentTags.PASSWORD_FIELD).send_keys("AvananGsuite_!@#")
        time.sleep(3)
        if driver.find_element(*locators.OAuthUserConsentTags.NEXT_BUTTON).is_displayed():
            driver.find_element(*locators.OAuthUserConsentTags.NEXT_BUTTON).click()
    except:
        print("[!] Failed to consent user")
    try:
        time.sleep(3)
        if driver.find_element(*locators.OAuthUserConsentTags.ALLOW_BUTTON).is_displayed():
            driver.find_element(*locators.OAuthUserConsentTags.ALLOW_BUTTON).click()
            print("[+] user %s allowed the application")
    except:
        print("[-] Application is already allowed by this user")
    driver.quit()


@app.route('/')
def oauth2callback():
    global email, action, flow
    if not email:
      email = flask.request.args.get("email")
    if 'code' not in flask.request.args:
        # auth_uri = ('https://accounts.google.com/o/oauth2/v2/auth?response_type=code'
        #             '&client_id={}&redirect_uri={}&scope={}').format(CLIENT_ID, REDIRECT_URI, *SCOPE)
        flow.redirect_uri = REDIRECT_URI
        auth_uri, state = flow.authorization_url(scopes=SCOPES, client=CLIENT_ID)
        user_consent_crawler(auth_uri, email)
        return flask.url_for("oauth2callback")
    else:
        auth_code = flask.request.args.get('code')
        data = {'code': auth_code,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'redirect_uri': REDIRECT_URI,
                'grant_type': 'authorization_code'}
        r = requests.post(TOKEN_URI, data=data)
        try:
            jwt = r.json()
            data = pickle.dumps(jwt)
            b64_data = base64.b64encode(data).decode("utf-8")
            print({"data": b64_data}, 200)
            return {"data": b64_data}, 200
        except Exception as e:
            print("Error:", str(e))
            print({"data": None}, 400)
            return {"data": None}, 400


if __name__ == '__main__':
    import uuid
    database.init_debug_db()
    app.secret_key = uuid.uuid4().hex
    app.debug = False
    app.run(host="0.0.0.0", port=80)

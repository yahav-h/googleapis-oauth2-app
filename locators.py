

class OAuthUserConsentTags:
    EMAIL_FIELD = ('xpath', './/*[@type="email"]')
    NEXT_BUTTON = ('xpath', './/div[@data-primary-action-label]//button[@type="button"]/span')
    PASSWORD_FIELD = ('xpath', './/*[@type="password"]')
    ALLOW_BUTTON = ('xpath', './/span[contains(text(), "Allow")]')

class AdminLoginTags:
    EMAIL_FIELD = ("xpath", './/*[contains(@type, "email") or contains(@autocomplete, "username")]')
    NEXT_BUTTON = ("xpath", './/button//span[contains(text(), "Next")]')
    PASSWORD_FIELD = ("xpath", './/input[contains(@type, "password") or contains(@name, "password")]')

class GoogleConsoleSecurityTags:
    SCROLL_TARGET = ("xpath", './/header[contains(text(), "Application-specific password")]')
    LOGIN_CHALLENGE_HEADER = ("xpath", './/header[contains(text(), "Login challenge")]')
    DISABLE_CHALLENGE_BUTTON = ("xpath", './/span[contains(text(), "Turn off for 10 mins")]')

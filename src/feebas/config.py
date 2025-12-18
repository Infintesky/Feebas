PACKAGE_NAME = 'com.hpb.healthhub.sit.rebuild'
TEST_NRIC = "S5500051D"

# HTTP URL Whitelist - Safe URLs that should not trigger security warnings
# Used by: network/network_1.py (NETWORK-1 - Testing Data Encryption on the Network)
HTTP_URL_WHITELIST = [
    "http://schemas.android.com/apk/res/android",
    "http://schemas.android.com/apk/res-auto",
    "http://ns.adobe.com/xap/1.0/",
    "http://www.w3.org/2000/svg",
    "http://localhost/",
]

# Potentially dangerous system actions that could be exploited via implicit intents
# Used by: platform/platform_2.py (PLATFORM-2 - Testing Implicit Intents and WebView Configuration)
DANGEROUS_SYSTEM_ACTIONS = [
    'android.intent.action.VIEW',
    'android.intent.action.SEND',
    'android.intent.action.SENDTO',
    'android.intent.action.SEND_MULTIPLE',
    'android.intent.action.MAIN',
    'android.intent.action.EDIT',
    'android.intent.action.PICK',
    'android.intent.action.GET_CONTENT',
    'android.intent.action.DIAL',
    'android.intent.action.CALL',
    'android.intent.action.WEB_SEARCH',
    'android.intent.action.PROCESS_TEXT'
]
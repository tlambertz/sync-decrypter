# based on https://github.com/mozilla-services/syncserver/blob/master/bin/delete_user_data.py

# protocol description at https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol
# more high level at https://hacks.mozilla.org/2018/11/firefox-sync-privacy/
# sync encr is at https://searchfox.org/mozilla-central/rev/65f9687eb192f8317b4e02b0b791932eff6237cc/services/sync/modules/record.js#145
# https://mozilla-services.readthedocs.io/en/latest/sync/storageformat5.html#record-encryption
# keys can be per-colleciton. They are random.
# stored encrypted in storage/crypto/keys, with syncKeyBundle key.
# this key is derived from kB


# A helper script to dump all user data from a Sync storage server.
#
# You can use this script to explicitly dump stored sync data
# for a user, without having to connect a Firefox profile and
# without having to reset their password. 
#
# Use it like so:
#
#    $> pip2 install hawkauthlib requests PyFxA
#    $> python2 dump.py user@example.com
#
# The script makes a best-effort attempt to sign in to the user's
# account, authenticate to the Firefox Sync Tokenserver, and dump
# the user's stored sync data.  The login process might fail due to
# things like rate-limiting, server-side security measures, or API
# changes in the login process.
#

import sys
import getpass
import hashlib
import argparse
import urlparse
import json

import requests
import hawkauthlib
import fxa.core

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad

DEFAULT_FXA_URI = "https://api.accounts.firefox.com"
DEFAULT_TOKENSERVER_URI = "https://token.services.mozilla.com"
# my own syncserver was at DOMAIN.TLD/mozsync/token, but we have to get identity for base domain!
DEFAULT_TOKENSERVER_URI_BASE = "https://token.services.mozilla.com" 


def getLoginData(args):

    # Sign in to the account.
    c = fxa.core.Client(args.accounts_uri)
    password = getpass.getpass("Password for {}: ".format(args.email))
    stretchpwd = c._get_stretched_password(args.email, password)

    # ----------- COPY IN YOUR HEADERS / JSON CONTENT FROM BURP HERE ---------------- #
    burp0_url = "https://api.accounts.firefox.com:443/v1/account/login" + "?keys=true"
    burp0_headers = {"Connection": "close", "User-Agent": "...", "content-type": "application/json", "Accept": "*/*", "Origin": "https://accounts.firefox.com", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://accounts.firefox.com/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
    burp0_json={"authPW": "...", "email": "...", "metricsContext": {"deviceId": "...", "entrypoint": "mozilla.org-firefox-accounts", "flowBeginTime": ..., "flowId": "...", "utmCampaign": "trailhead", "utmContent": "form-upper", "utmMedium": "referral", "utmSource": "mozilla.org-firefox-accounts"}, "reason": "signin", "resume": "...", "skipCaseError": True, "verificationMethod": "email-otp"}
    r = requests.post(burp0_url, headers=burp0_headers, json=burp0_json)
    session_dump = r.json()
    print session_dump

    #if not session_dump['verified']:
    #    emailcode = getpass.getpass("Email OTP for {}: ".format(args.email))
    #   # TODO: request to "/session/verify_code", 
    #        #url = "/session/verify_code"
    #        #auth = HawkTokenAuth(session_token, "sessionToken", apiclient)
    #        #return apiclient.post(url, body, auth=auth)

    s = fxa.core.Session(
        client=c,
        email=args.email,
        stretchpwd=stretchpwd,
        uid=session_dump["uid"],
        token=session_dump["sessionToken"],
        verified=session_dump["verified"],
        auth_timestamp=session_dump["authAt"],
    )
    try:
        # Verify the session if necessary.
        # TODO: this won't work if the user has enabled two-step auth.
        #status = s.get_email_status()
        #if not status["sessionVerified"]:
        #    code = raw_input("Enter verification link or code: ")
        #    if "?" in code:
        #        # They copy-pasted the full URL.
        #        code_url = urlparse.urlparse(code)
        #        code = urlparse.parse_qs(code_url.query)["code"][0]
        #    s.verify_email_code(code)

        # Prepare authentication details for tokenserver.
        (kA, kB) = s.fetch_keys(session_dump['keyFetchToken'], stretchpwd)

        xcs = hashlib.sha256(kB).hexdigest()[:32]
        auth = s.get_identity_assertion(DEFAULT_TOKENSERVER_URI_BASE, 60*60*24)
        print "KA", kA.encode('hex')
        print "KB", kB.encode('hex')


    finally:
        s.destroy_session()

    return auth, xcs, kA, kB

def main(argv):
    parser = argparse.ArgumentParser(description="Dump Firefox Sync data")
    parser.add_argument("email",
                        help="Email of the account for which to dump data")

    args = parser.parse_args(argv)

    # auth expires once a day!
    auth, xcs, kA, kB = getLoginData(args)

    # you can cache responses here if you want.
    #auth = "AUTH"
    #xcs = "1337"
    #kA = "1337".decode('hex')
    #kB = "1337".decode('hex')
    print "AUTH", auth
    print "XCS", xcs
    print "KA", kA.encode('hex')
    print "KB", kB.encode('hex')

    # Auth to tokenserver, find sync storage node.
    print "Authenticating to tokenserver..."
    token_uri = urlparse.urljoin(DEFAULT_TOKENSERVER_URI, "1.0/sync/1.5")
    r = requests.get(token_uri, headers={
        "Authorization": "BrowserID " + auth,
        "X-Client-State": xcs,
    })
    r.raise_for_status()
    node = r.json()
    print node
    print "Logged in!"


    print "----------------\n"


    print "Collections:"
    print getEndpoint(node, "/info/collections")

    keys = getKeys(node, kB)
    print(keys)

    print "Quota:", getEndpoint(node, "/info/quota")
    print "Usage:", getEndpoint(node, "/info/collection_usage")
    print "Counts:", getEndpoint(node, "/info/collection_counts")
    print "Meta:", getEndpoint(node, "/storage/meta/global")
    print "Bookmarks:", getEndpoint(node, "/storage/bookmarks")
    print "Bookmarks:", getRecord(node, keys, "/storage/bookmarks/iMyDlAfdWXC5")
    print "Crypto:", getEndpoint(node, "/storage/crypto/keys")
    print "Addons:", getEndpoint(node, "/storage/addons")
    print "Keys:", getEndpoint(node, "/storage/keys")
    print "clients:", getEndpoint(node, "/storage/clients")

    custom_payload = '{"hmac":"...","ciphertext":"...","IV":"..."}'
    custom_rec = {"payload": custom_payload}
    tabs = decrypt(custom_rec, keys)

    for i, t in enumerate(tabs['tabs']):
        print i, t['title'] + "\t-\t" + t['urlHistory'][0]

def sendSigned(node, req):
    hawk_id = node["id"].encode("ascii")
    hawk_key = node["key"].encode("ascii")
    hawkauthlib.sign_request(req, hawk_id, hawk_key)
    r = requests.session().send(req)
    r.raise_for_status()
    return r.json()


def getCollections(node):
    api_endpoint = node["api_endpoint"]+"/info/collections"
    req = requests.Request("GET", api_endpoint).prepare()
    return sendSigned(node, req)


# record is raw out of db, keys are tuple of enc,hmac_key
def decrypt(record, keys):
    #print "Decrypting...", record

    record = json.loads(record['payload'])
    enc_key = keys[0]
    hmac_key = keys[1]

    cb64 = record['ciphertext'].encode('utf-8')
    iv = record['IV'].decode('base64')
    hmac = record['hmac'].decode('hex')

    # test if hmac matches
    local_hash = HMAC.new(hmac_key, digestmod=SHA256)
    local_hash.update(cb64)
    local_digest = local_hash.digest()
    assert local_digest == hmac

    # decrypt keybundle
    aes = AES.new(enc_key, AES.MODE_CBC, iv)
    p = aes.decrypt(cb64.decode('base64'))
    try:
        p = unpad(p, 16)
    except:
        print(p)
        print(p.encode('hex'))
        pass
    keys = json.loads(p)
    return keys

def getKeys(node, kB):
    # derive syncKeyBundle from kB
    enc_key, hmac_key = HKDF(kB, 32, None, SHA256, 2, "identity.mozilla.com/picl/v1/oldsync")
    #print(enc_key.encode('hex'), hmac_key.encode('hex'))

    keys = getRecord(node, (enc_key, hmac_key), "/storage/crypto/keys")
    print "storage/crypto/keys: ", keys

    return (keys['default'][0].decode('base64'), keys['default'][1].decode('base64'))


def getRecord(node, keys, api_endpoint):
    record = getEndpoint(node, api_endpoint)
    return decrypt(record, keys)


def getEndpoint(node, api_endpoint):
    req = requests.Request("GET", node["api_endpoint"]+api_endpoint).prepare()
    return sendSigned(node, req)

if __name__ == "__main__":
    main(sys.argv[1:])
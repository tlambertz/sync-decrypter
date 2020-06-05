# Mozilla Firefox Sync Dumper / Decrypter
Hacky script which can dump Mozilla Firefox decryption keys (`kA/kB`), and use them to decrypt contents of the Sync database.

## Background
This morning I lost all the tabs I had open on my firefox on android. This annoyed me, since I keep some 'bookmarks' by just having open tabs. Yeah I know, but it mostly works.

Unlike firefox on the desktop, the mobile version does not keep a sessionstore backup around. Using the 'recently closed tabs' feature I was able to restore the 10 most recent tabs, but no more.

Luckily I am running my own firefox sync server. Unfortunately, the fckd up their database migration, which had to be done by hand ([github issue](https://github.com/mozilla-services/syncserver/pull/193#commitcomment-36884169)), so I have no current tab-backups there. BUT: the database (sqlite in my case) does not delete old entries, even though it has ttl fields. The bso table contains all encrypted entries the sync server posesses. Filtering for collection-id 6 (tabs), I found an entry that looked promising from ~3 months ago. Since all entries in the DB are encrypted, I began digging around where to find the decryption key, so I could view all entries, expired or not.

I had read a bit about the sync architecture before deciding to use it, so I already knew how it worked. Implementing this script proved annoying though, since a lot of tools/docs are outdated and did not quite work anymore.

I found a [python script intended to delete all sync-data](https://github.com/mozilla-services/syncserver/blob/master/bin/delete_user_data.py) and adapted it to my needs.


## Overview
- login to Firefox Accounts with `?keys=true` and dump `kA` and `kB`
- use `kB` to derive `syncKeyBundle`
- use this to decrypt the sync entry in `storage/crypto/keys`
- use the key(s) contained there to decrypt all other entries.

## Login to Firefox Accounts
Firefox uses it's own account infrastructure, which is open-source on [GitHub](https://github.com/mozilla/fxa).

The python script uses PyFxA for logging in, though this does not work anymore since they changed the email login confirmation flow. But even before hitting this verification I was only getting `Security Violation` errors.
Being lazy, I opened Burp (a network proxy), logged in to my account in a browser and sniffed the resulting request/response. Using the burp copy-as-python-requests plugin you can easily copy the whole request including headers into your python code.

Since I need to request keys, I not only sniffed but changed one request:

```
POST https://api.accounts.firefox.com:443/v1/account/login
to
POST https://api.accounts.firefox.com:443/v1/account/login/?keys=true
```


## Sync Decryption

- Sync overview: https://hacks.mozilla.org/2018/11/firefox-sync-privacy/
- protocol description at https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol
- storage encryption: https://mozilla-services.readthedocs.io/en/latest/sync/storageformat5.html#record-encryption
- sync encryption source: https://searchfox.org/mozilla-central/rev/65f9687eb192f8317b4e02b0b791932eff6237cc/services/sync/modules/record.js#145



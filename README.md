# TA-cryptosuite

The Splunk® Support Add-On _Cryptosuite_ is the successor to the deprecated Support Add-On for Hypercrypto (https://github.com/my2ndhead/SA-hypercrypto).

It implements and extends the custom search commands _crypt_ and _hash_ for encrypting/decrypting and hashing fields and events at search time.

* Encrypt/decrypt fields or complete events during search time using RSA or AES-128/192/256-CBC
* Hash fields or complete events during search time using MD5, SHA1, SHA2 (224, 256, 384, 512), SHA3 (224, 256, 384, 512), Blake2
* Manage access to encryption and decryption functionality on a per-user or per-role basis via two shipped roles
* Manage useable encryption/decryption keys on a per-user or per-role basis via the app's configuration screen

Cross-compatible with Python 2 and 3. Tested on Splunk Enterprise 8.0.2.1.

Licensed under http://creativecommons.org/licenses/by-nc-sa/4.0/.

* Authors: Harun Kuessner, formerly also: Simon Balz, Mika Borner, Christoph Dittmann
* Version: 2.0a
* License: Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License [2]

## Installation

1. Just unpack to _$SPLUNK_HOME/etc/apps_ on your Splunk search head and restart the instance. Use the deployer in a distributed environment. Make sure, the app's folder name in _$SPLUNK_HOME/etc/apps_ is _SA-cryptosuite_ (Downloading apps from Github and uploading them to Splunk might result in different folder names).
2. Assign the roles 'can_encrypt' and/or 'can_decrypt' to users/roles who should be able to encrypt/decrypt data using the _crypt_ command. The _hash_ command will automatically be available to all users.
3. Read and follow the requirements below.
4. Optional: Set _python.version=python2_ or _python.version=python3_ in _commands.conf_ if you would like to explicitly specify the Python version to use. Otherwise this will be determined by your instance's global settings.
5. Optional: Change the app's visibility via _Manage\>Apps_ or _app.conf_ if you wish.

### Requirements

In order for the add-on to be fully usable you'll need to create and upload cryptographic keys. Here's how. You can also find some examples and tips in the _examples/_ directory.

1. Generate a valid RSA key pair (optionally with key encryption) and store it in PEM format. Or create a "key file" for AES.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Example RSA key pair creation with currently supported parameters using OpenSSL:
      
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_openssl genrsa [-aes256|-des|-des3 -passout pass:password] -out private.pem \<2048|4096>_

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_openssl rsa -in private.pem -outform PEM -RSAPublicKey_out -out public.pem_
      
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Note that using 1024 bit keys is considered unsafe and therefore not supported by the app.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Example "key file" creation for AES:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Put your key and IV in UTF-8 or Base64 into a plain ASCII file. Key has to go on line 1 and IV on line 2.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Key and IV length have to be 16/24/32 bytes respectively for 128/192/256 AES encryption.

2. Go to the app's configuration dashboard in your preferred browser. Click "Create New Input".

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Name_: Enter the name you would like the your key to be accessible through. E.g. the original key file's name.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Type of Data_: Select "New key".

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Key/Salt_: Copy-paste the contents of your generated key file here. Your key will be stored encrypted in _passwords.conf_.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_RSA key encryption password_: Only required if you are currently configuring an encrypted private RSA key. Supportd key encryption algorithms are AES-256-CBC, DES-CBC and DES-EDE3-CBC.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Authorized roles_: Select which roles you want to grant permissions to use the key. Will be ORed with authorized users. Users/roles will also require the "can_encrypt" and/or "can_decrypt" role in order to use the _crypt_ command in the first place.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Authorized users_: Select which users you want to grant permissions to use the key. Will be ORed with authorized roles. Users/roles will also require the "can_encrypt" and/or "can_decrypt" role in order to use the _crypt_ command in the first place.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**Note**: For a RSA key pair, you'll have to do this twice. Once for the private key and once for the public key.


If you plan on salting your hashes, create and store upload salts like so:

1. Go to the app's configuration dashboard in your preferred browser. Click "Create New Input".

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Name_: Enter the name you would like the your salt to be accessible through.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Type of Data_: Select "New salt".

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Key/Salt_: Enter or copy-paste your salt here. It will be stored encrypted in _passwords.conf_.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_RSA key encryption password_: Leave empty.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Authorized roles_: Select which roles you want to grant permissions to use the salt. Will be ORed with authorized users.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Authorized users_: Select which users you want to grant permissions to use the salt. Will be ORed with authorized roles.


**Note**: Handling keys and salts this way is a security feature, since specifing the key/salt directly in a Splunk search directly would make them visible in the \_internal index.

## Usage

Syntax: 
*crypt mode=<d|e> algorithm=<rsa|aes-128-cbc|aes-192-cbc|aes-256-cbc> key=<key_name> [randpadding=\<true|false>] \<field-list>*

_mode_: Mandatory. Set to _e_ to encrypt, set to _d_ to decrypt the given field list using the provided key.

_algorithm_: Mandatory. Set to the cryptographic algorithm you would like to use for encryption/decryption.

_key_: Mandatory. Set to the name of a key you (or your admin) configured previously.

_randpadding_: Optional, default: _true_. Only valid for _algorithm=rsa_. Specify whether to use random padding or not. Disabling random padding will result in a the same cipher for each unique field value. Otherwise encryption results in a unique cipher even for same field values. Setting randpadding to false is not recommended since it allows certain attacks on the RSA crypto system.

Syntax: 
*hash algorithm=<md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512|blake2b|blake2s> [salt=\<salt_name>] \<field-list>*

_algorithm_: Mandatory. Set to the hashing algorithm you would like to use. SHA3 and Blake2 are only available when using Python 3.

_saltfile_: Optional. Set to the name of a key you (or your admin) configured previously.
   
### Examples

Encrypt the values of the plaintext fields "subject" and "content" of sourcetype "mail" using rsa and the key "public.pem".

&nbsp;&nbsp;&nbsp;_search sourcetype="mail" | crypt mode=e algorithm=rsa key=public.pem subject content_

Encrypt raw events of sourcetype "mail" using AES-256-CBC and collect the results in a summary index.

&nbsp;&nbsp;&nbsp;_search sourcetype="mail" | crypt mode=e algorithm=aes-256-cbc key=secret.txt \_raw | collect index=summary_

Decrypt the content of the already RSA encrypted and summary-indexed field "username" for output in plain text using RSA. The key file "private.pem" is encrypted with AES-256-CBC, so the correspondig password has to be set via the app's set up screen prior to using the key.

&nbsp;&nbsp;&nbsp;_search index=summary sourcetype="server::access" | crypt mode=d algorithm=rsa key=private.pem username | table \_time action username_

Hash a raw event containing some malware threat artifact using sha256.

&nbsp;&nbsp;&nbsp;_search index=threat_intel source=sample.txt | hash algorithm=sha256 \_raw_

### Notes & Restrictions

* Attempts to encrypt or hash _\_time_ will be ignored since Splunk always expects a valid _\_time_ field.
* Wildcards for field names are not supported (yet).
* Currently only AES-256-CBC, DES-CBC and DES-EDE3-CBC are supported for private RSA key file encryption.
* To implement proper key/salt management (without relying on my weak JavaScript skills for a management dashboard) the add-on leverages the comfort Splunk Add-On Builder grants. \
This is why your key/salt configurations are stored as modular input configurations. Don't worry, they are not used as such. A future version of the add-on might implement this better.
   
#### (Important) Security Considerations

* Granting a user or role the role 'can_encrypt' or 'can_decrypt' needed for usage of the crypt command will also grant them the capability 'list_storage_passwords'. \
This enables the technically savvy user to potentially read more secrets via Splunk's REST API than desirable. \
Unfortunately as of now there is no way around this if the encryption/decryption keys and salts used for this app's function should not be stored in plaintext on disk. \
You can argue this way or that. My assumption is that only high-privileged users will use the crypto functionality in the first place, and thus prefferred encrypted keys over potentially exessive permissions.
* The keys and salts you upload are stored encrypted in _passwords.conf_. However to quote a Splunk blog post: "[...] Since the encrypted data and the encryption key are stored on the same machine, cryptographically this is equivalent to obfuscation. While some people might argue that this is very weak encryption, it is the best we can do with storing the encrypted data and encryption key on the same machine and it is definitely better than clear text passwords [...]"[3]
* Disabling random padding when encrypting with RSA is useful in some cases but enables certain attacks to the RSA crypto system. So use randpadding=false with caution.
* The RSA implementation is only capable of processing 255 - 11 bytes of data at once. Fields larger than that have to be split into blocks. This enables certain attacks to the RSA crypto system. Therefore it is recommended to always set randpadding=true when encrypting large fields.
* Using 1024 bit RSA keys is generally considered unsafe and therefore not possible using with the add-on.

* It is not recommended to use MD5 or SHA1 (on passwords) since these hashing algorithms are not seen as safe anymore.
* SHA3 and Blake2 are only available when using Python3 as your environments interpreter.

## TODO / Known Issues

* Major overhaul for Splunk 8 compatibility
* Ensured cross-compatibility for Python 2 and 3
* Implement possibility for AES-128/192/256-CBC field/event encryption & decryption
* Re-implement non-random padding into RSA lib or remove entirely?
* Disable helper inputs by default
* Test with Splunk 7.x
* Enhance performance
* Potentially implement support for wildcards for field names

## History

### v2.0a

* Updated Splunk SDK for Python
* Using custom search command protocol v2 now
* Updated README and docs with soon-to-come changes
* Implemented proper key/salt management on per-user and per-role basis

* Removed keyencryption parameter from crypt command and replaced by automatic detection
* Implemented sanity check for private/public RSA key usage at encryption/decryption attempts

* Ensured Splunk 8 and Python 2/3 cross-compatilibity for hash command
* Hashes will now be written to a new field with the name of the used algorithm
* Renamed saltfile parameter to salt
* Implemented SHA3 and Blake2 support for environments using Python 3

*See https://github.com/my2ndhead/SA-hypercrypto for previous, deprecated versions.*

## Attribution

The crypt command uses a slightly modified version of Sybren A. Stuevel's (sybren@stuvel.eu) RSA implementation in Python [1] which is licensed under the Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0.

## License

**This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.** [2]

This roughly translates to 

* You may freely use, share and adapt this work non-commercially as long as you give appropriate credit. When adapting or sharing, this needs to happen under the same license, changes should be indicated.
* You may freely use this work in a commercial environment as long as the use is not primarily intended for commercial advantage or monetary compensation. YOU MAY NOT SELL THIS WORK. Neither standalone nor within an application bundle.

Please reffer to the full license for completeness and correctness. Feel free to contact me should you plan to use the add-on outside these terms.

## References
[1] https://github.com/sybrenstuvel/python-rsa

[2] http://creativecommons.org/licenses/by-nc-sa/4.0/

[3] https://www.splunk.com/en_us/blog/security/storing-encrypted-credentials.html

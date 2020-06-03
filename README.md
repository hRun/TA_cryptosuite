# TA-cryptosuite

The Splunk® Support Add-On _Cryptosuite_ is the successor to the deprecated Support Add-On for Hypercrypto (https://github.com/my2ndhead/SA-hypercrypto).

It implements and extends the custom search commands _crypt_ and _hash_ for encrypting/decrypting and hashing fields and events at search time.

* Encrypt/decrypt fields or complete events during search time using RSA or AES-128/192/256-CBC
* Hash fields or complete events during search time using md5 / sha1 / sha2 (sha224/sha256/sha384/sha512)
* Manage access to encryption and decryption functionality on a per-user basis via two shipped roles
* Manage useable encryption/decryption keys on a per-user or per-key basis via the app's setup screen

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

In order for the add-on to be fully usable you'll need to create and store (accessibly) cryptographic keys. Here's how:

1. Generate a valid RSA key pair (optionally with key encryption) and store it in PEM format. Or create a "key file" for AES.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Example RSA key pair creation with currently supported parameters using OpenSSL:
      
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_openssl genrsa [-aes256|-des|-des3 -passout pass:password] -out private.pem \<2048|4096>_

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_openssl rsa -in private.pem -outform PEM -RSAPublicKey_out -out public.pem_
      
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Note that using 1024 bit keys is considered unsafe and therefore forbidden.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Example "key file" creation for AES:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Put your key and IV in UTF-8 or Base64 into a plain ASCII file. Key has to go on line 1 and IV on line 2.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Key and IV length have to be 16/24/32 bytes respectively for 128/192/256 AES encryption.

2. Ask your Splunk admin to put the created file(s) into this app's lib directory (_$SPLUNK\_HOME/etc/apps/SA-cryptosuite/lib/keys/_). Ask him to set appropriate system-level file permissions (e.g. _0600_).

3. Optional: If you plan to use an encrypted private RSA key, provide the corresponding password via the app's set up screen _Manage Apps>SA-cryptosuite>Set Up_ in order to be able to use the key. Passwords for encrypted private key files can be set per user and key file and get stored in Splunk's internal password storage. Currently supported algorithms for key encryption are AES-256-CBC, DES-CBC and DES-EDE3-CBC.

If you plan on salting your hashes, create and store (accessibly) salts like so:

1. Generate a file containing a salt for spicing your hashes by putting whatever string you would like to use as salt into a plain ASCII file.

2. Ask your Splunk admin to put the created file(s) into this app's lib directory (_$SPLUNK\_HOME/etc/apps/SA-cryptosuite/lib/salts/_). Ask him to set appropriate system-level file permissions (e.g. _0600_).

**Note**: Handling AES keys and salts this way is a security feature, since specifing the key/salt directly in the search would make them visible in the \_internal index.

## Usage

Syntax: 
*crypt mode=<d|e> algorithm=<rsa|aes-128-cbc|aes-192-cbc|aes-256-cbc> key=<file_name> [randpadding=\<true|false>] \<field-list>*

_mode_: Mandatory. Set to _e_ to encrypt, set to _d_ to decrypt the given field list using the provided key.

_algorithm_: Mandatory. Set to the cryptographic algorithm you would like to use for encryption/decryption.

_key_: Mandatory. Set to the name of the file containing your key and stored under _$SPLUNK\_HOME/etc/apps/SA-cryptosuite/lib/keys/_.

_randpadding_: Optional, default: _true_. Only valid for _algorithm=rsa_. Specify whether to use random padding or not. Disabling random padding will result in a the same cipher for each unique field value. Otherwise encryption results in a unique cipher even for same field values. Setting randpadding to false is not recommended since it allows certain attacks on the RSA crypto system.

Syntax: 
*hash algorithm=<md5|sha1|sha224|sha256|sha384|sha512> [saltfile=\<file_name>] \<field-list>*

_algorithm_: Mandatory. Set to the hashing algorithm you would like to use.

_saltfile_: Optional. Set to the name of a file containing a salt and stored under _$SPLUNK\_HOME/etc/apps/SA-cryptosuite/lib/salts/_.
   
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
* Full password management via the set up screen has not been implemented yet, since Splunk does not provide a way to do so via SimpleXML. So you can not update stored passwords at this point in time. Manage your stored passwords in SA-cryptosuite/local/app.conf.
   
#### Security considerations

* Granting a user or role the role 'can_encrypt' or 'can_decrypt' needed for usage of the crypt command will also grant them the capability 'list_storage_passwords'. \
This enables the technically savvy user to potentially read more secrets via Splunk's REST API than desirable. \
Unfortunately as of now there is no way around this if the encryption/decryption keys used for this app's function should not be stored in plaintext on disk.
* Disabling random padding when encrypting with RSA is useful in some cases but enables certain attacks to the RSA crypto system. So use randpadding=false with caution.
* The RSA implementation is only capable of processing 255 - 11 bytes of data at once. Fields larger than that have to be split into blocks. This enables certain attacks to the RSA crypto system. Therefore it is recommended to always set randpadding=true when encrypting large fields.
* It is not recommended to use MD5 or SHA1 since these hashing algorithms are not seen as safe anymore.
* Using 1024 bit RSA keys is generally considered unsafe and therefore not possible with the add-on.

## TODO / Known Issues

* Major overhaul for Splunk 8 compatibility
* Ensured cross-compatibility for Python 2 and 3
* Implement per-user and per-key key usability
* Implement sanity check for private/public RSA key usage at encryption/decryption attempts
* Implement possibility for AES-128/192/256-CBC field/event encryption & decryption
* Implement possibility for SHA3 hashing of fields/events
* Implement PKCS#1 v2 support
* Only allow keys/salts in lib directory
* Test with Splunk 7.x
* Potentially implement support for wildcards for field names

## History

### v2.0a

* Updated Splunk SDK for Python
* Updated README and docs with soon-to-come changes
* Using Splunk add-on builder now to have a nicer app setup and key management
* Ensured Splunk 8 and Python 2/3 cross-compatilibity for hash command
* Hashes will now be written to a new field with the name of the used algorithm
* Removed keyencryption parameter from crypt command and replace by automatic detection

*See https://github.com/my2ndhead/SA-hypercrypto for previous, deprecated versions.*

## Attribution

The crypt command uses a slightly modified version of Sybren A. Stuevel's (sybren@stuvel.eu) RSA implementation in Python [1] which is licensed under the Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0.

## License

**This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.** [2]

This roughly translates to 

* You may freely use, share and adapt this work non-commercially as long as you give appropriate credit. When adapting or sharing, this needs to happen under the same license, changes should be indicated.
* You may freely use this work in a commercial environment as long as the use is not primarily intended for commercial advantage or monetary compensation. You may not sell this work. Neither standalone nor within an application bundle.

Please reffer to the full license for completeness and correctness.

## References
[1] https://github.com/sybrenstuvel/python-rsa

[2] http://creativecommons.org/licenses/by-nc-sa/4.0/

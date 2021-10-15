# TA_cryptosuite

A Splunk® Add-On providing the custom search commands _cipher_, _crypt_, _encode_, and _hash_ for ciphering/deciphering, encrypting/decrypting, encoding/decoding and hashing fields and events at search time.

* Cipher/decipher fields or complete events during search time using RC4, ROT13, ROT47, XOR
* Encrypt/decrypt fields or complete events during search time using RSA, AES-128/192/256-CBC or AES-128/192/256-OFB
* Encode/decode fields or complete events during search time using Base32, Base58, Base62, Base64, Binary, Decimal, Hex, Octal
* Hash fields or complete events during search time using MD5, SHA1, SHA2 (224, 256, 384, 512), SHA3 (224, 256, 384, 512), Blake2
* Manage access to encryption and decryption functionality on a per-user or per-role basis via two shipped roles
* Manage usable encryption/decryption keys on a per-user or per-role basis via the app's configuration screen

Cross-compatible with Python 2 and 3. Tested on Splunk Enterprise 8.2.1 and 8.1.1 on Windows and Linux (64-bit).

Licensed under http://creativecommons.org/licenses/by-nc-sa/4.0/.

* Authors: Harun Kuessner
* Contributors: Windu Sayles, (formerly also: Simon Balz, Mika Borner, Christoph Dittmann)
* Version: 2.2.3
* License: Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License [5]


## Usage

_cipher_ command syntax: 
*cipher mode=<d|e> algorithm=<rc4|rot13|rot47|xor> key=<key> \<field-list>*

_mode_: Mandatory. Set to _e_ to cipher, set to _d_ to decipher the given field list using the provided key.

_algorithm_: Mandatory. Set to the cryptographic algorithm you would like to use for ciphering/deciphering.

_key_: Mandatory. Specify the key to use. Requirements vary depending on the chosen algorithm.

Cipher results will be output as hex strings (except ROT results where output is ascii). Deciphering (except ROT operations) expects input fields to be hex strings, results will be output in ascii. If the cipher operation fails on a single field or event, this field/event will be skipped and returned as is.


_crypt_ command syntax: 
*crypt mode=<d|e> algorithm=<rsa|aes-cbc|aes-ofb> key=<key_name> \<field-list>*

_mode_: Mandatory. Set to _e_ to encrypt, set to _d_ to decrypt the given field list using the provided key.

_algorithm_: Mandatory. Set to the cryptographic algorithm you would like to use for encryption/decryption.

_key_: Mandatory. Set to the name of a key you (or your admin) configured previously.

Encryption results will be output base64 encoded. Decryption expects input fields to be base64 encoded, results will be output in ascii. For security purposes the whole search will fail if the crypto operation fails on a single field or event. See _Requirements & Configuration_ for key setup.


_encode_ command syntax: 
*encode mode=<to|from> encoding=<base32|base58|base62|base64|base85|binary|decimal|hex|octal> \<field-list>*

_mode_: Mandatory. Set to _to_ for transforming to the specified encoding, set to _from_ to transform from the specified encoding.

_encoding_: Mandatory. Set to the encoding method to apply to the given field list.

If the encoding operation fails on a single field or event, this field/event will be skipped and returned as is.


_hash_ command syntax: 
*hash algorithm=<md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512|blake2b|blake2s> [salt=\<salt_name>] \<field-list>*

_algorithm_: Mandatory. Set to the hashing algorithm you would like to use. SHA3 and Blake2 are only available when using Python 3.

_saltfile_: Optional. Set to the name of a key you (or your admin) configured previously.

For security purposes the whole search will fail if the hash operation fails on a single field or event. See _Requirements & Configuration_ for salt setup.


### Examples

XOR the field "message" with byte "\\x2f".

&nbsp;&nbsp;&nbsp;_search sourcetype="ctf" | cipher algorithm=xor key="2f" message | table \_time alice, bob, message_


Decode the hex contents of "payload" and display readable ascii values in a table.

&nbsp;&nbsp;&nbsp;_search sourcetype="snort" | encode mode=from encoding=hex payload | table \_time src_ip, dest_ip, payload_


Encrypt the values of the plaintext fields "subject" and "content" of sourcetype "mail" using rsa and the key "public.pem".

&nbsp;&nbsp;&nbsp;_search sourcetype="mail" | crypt mode=e algorithm=rsa key=public.pem subject content_

Encrypt raw events of sourcetype "mail" using AES-256-CBC and collect the results in a summary index.

&nbsp;&nbsp;&nbsp;_search sourcetype="mail" | crypt mode=e algorithm=aes-cbc key=secret.txt \_raw | collect index=summary_

Decrypt the content of the already RSA encrypted and summary-indexed field "username" for output in plain text using RSA. The key file "private.pem" is encrypted with AES-256-CBC, so the correspondig password has to be set via the app's set up screen prior to using the key.

&nbsp;&nbsp;&nbsp;_search index=summary sourcetype="server::access" | crypt mode=d algorithm=rsa key=private.pem username | table \_time action username_


Hash a raw event containing some malware threat artifact using sha256.

&nbsp;&nbsp;&nbsp;_search index=threat_intel source=sample.txt | hash algorithm=sha256 \_raw_


## Installation

1. Just unpack to _$SPLUNK_HOME/etc/apps_ on your Splunk search head and restart the instance. Use the deployer in a distributed environment. Make sure, the app's folder name in _$SPLUNK_HOME/etc/apps_ is _TA-cryptosuite_ (Downloading apps from Github and uploading them to Splunk might result in different folder names).
2. Assign the roles 'can_encrypt' and/or 'can_decrypt' to users/roles who should be able to encrypt/decrypt data using the _crypt_ command. The _cipher_, _hash_ and _encode_ commands will automatically be available to all users.
3. Read and follow the requirements & configuration section below.
4. Optional: Set _python.version=python2_ or _python.version=python3_ in _commands.conf_, _inputs.conf_ and _restmap.conf_ if you would like to explicitly specify the Python version to use. Otherwise this will be determined by your instance's global settings.
5. Optional: Change the app's visibility via _Manage\>Apps_ or _app.conf_ if you wish. Configuring new keys/salts relies on an internal dashboard though.


### Requirements & Configuration

In order for the _crypt_ command of this add-on to be fully usable you'll need to create and upload cryptographic keys. Here's how. You can also find some examples and tips in the _examples/_ directory.

1.1. If you plan on using RSA, generate a valid RSA key pair (optionally with key encryption) and store it in PEM format.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Example RSA key pair creation with currently supported parameters using OpenSSL:
      
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_openssl genrsa [-aes256|-des|-des3 -passout pass:password] -out private.pem \<2048|4096>_

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_openssl rsa -in private.pem -outform PEM -RSAPublicKey_out -out public.pem_
      
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Note that using 1024 bit keys is considered unsafe and therefore not supported by the app.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**Important Note:** Use of encrypted private RSA keys is only supported when having the "pycryptodomex" Python package installed (see below)!


1.2. If you plan on using AES, create a "key file".

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Example "key file" creation for AES:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Put your key and IV in UTF-8 into a plain ASCII file. Key has to go on line 1 and IV on line 2.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The IV's length has to be 16 bytes/characters. The key's length has to be 16/24/32 bytes/characters respectively for 128/192/256 AES encryption. For security purposes 256 bit keys are recommended unless performance is important.


2. Go to the app's configuration dashboard in your preferred browser. Click "Create New Input".

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Name_: Enter the name you would like the your key to be accessible through. E.g. the original key file's name.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Type of Data_: Select "New key".

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Key/Salt_: Copy-paste the contents of your generated key file here. Your key will be stored encrypted in _passwords.conf_.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_RSA key encryption password_: Only required if you are currently configuring an encrypted private RSA key. Supported key encryption algorithms are AES-256-CBC, DES-CBC and DES-EDE3-CBC. **Important Note:** Use of encrypted private RSA keys is only supported when having the "pycryptodomex" Python package installed (see below)!

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Authorized roles_: Select which roles you want to grant permissions to use the key. Will be ORed with authorized users. Users/roles will also require the "can_encrypt" and/or "can_decrypt" role in order to use the _crypt_ command in the first place.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Authorized users_: Select which users you want to grant permissions to use the key. Will be ORed with authorized roles. Users/roles will also require the "can_encrypt" and/or "can_decrypt" role in order to use the _crypt_ command in the first place.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**Note**: For a RSA key pair, you'll have to do this twice. Once for the private key and once for the public key.


If you plan on salting your hashes when using the _hash_ command, create and store upload salts like so:

1. Go to the app's configuration dashboard in your preferred browser. Click "Create New Input".

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Name_: Enter the name you would like the your salt to be accessible through.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Type of Data_: Select "New salt".

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Key/Salt_: Enter or copy-paste your salt here. It will be stored encrypted in _passwords.conf_.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_RSA key encryption password_: Leave empty.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Authorized roles_: Select which roles you want to grant permissions to use the salt. Will be ORed with authorized users.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_Authorized users_: Select which users you want to grant permissions to use the salt. Will be ORed with authorized roles.


**Note**: Handling keys and salts this way is a security feature, since specifing the key/salt directly in a Splunk search directly would make them visible in the \_internal index. Keys are not handled like this for the _cipher_ command, as the implemented ciphers are generally not regarded as secure anymore.


**On the use of encrypted private RSA keys and used Python libraries**: By default the add-on uses a pure-Python implementation of the RSA (and AES) algorithm which comes shipped with the add-on for all platforms. This implementation does not support usage of encrypted private RSA keys. Their usage is only possible by installing the "pycryptodomex" Python package to your OS's installation of an instance of Python 3.7.8 or 2.7.17 (see https://www.pycryptodome.org/en/latest/src/installation.html). After the package's successful installation, configure this add-on to make use of the system Python's installed packages via the add-on's configuration page. Unfortunately due to Splunk's built-in Python's poor handling of 3rd party packages, the package cannot be installed to only that instance of Python.


### Notes & Restrictions

* Attempts to modify _\_time_ will be ignored since Splunk always expects a valid _\_time_ field.
* Wildcards for field names are not supported (yet).
* Encryption and decryption of big quantities of data can be ressource intensive operations. Use with caution in old or feeble environments.
* Currently only AES-256-CBC, DES-CBC and DES-EDE3-CBC are supported for private RSA key file encryption.
* To implement proper key/salt management (without relying on my weak JavaScript skills for a management dashboard) the add-on leverages the comfort Splunk Add-On Builder grants. \
This is why your key/salt configurations are stored as modular input configurations. Don't worry, they are not used as such. A future version of the add-on might implement this better.


#### (Important) Security Considerations

* Granting a user or role the role 'can_encrypt' or 'can_decrypt' needed for usage of the crypt command will also grant them the capability 'list_storage_passwords'. \
This enables the technically savvy user to potentially read more secrets via Splunk's REST API than desirable. \
Unfortunately as of now there is no way around this if the encryption/decryption keys and salts used for this app's function should not be stored in plaintext on disk. \
You can argue this way or that. My assumption is that only high-privileged users will use the crypto functionality in the first place, and thus prefferred encrypted keys over potentially exessive permissions.
* The keys and salts you upload are stored encrypted in _passwords.conf_. However to quote a Splunk blog post: "[...] Since the encrypted data and the encryption key are stored on the same machine, cryptographically this is equivalent to obfuscation. While some people might argue that this is very weak encryption, it is the best we can do with storing the encrypted data and encryption key on the same machine and it is definitely better than clear text passwords [...]"[0].

* The used libraries (see _Attribution_) have been chosen due to their compatibility with multiple Python versions and OSes. They might not be the best implementations of the respective algorithms and are certainly not the fastest, but more popular implementations posed compatibility challenges due to relying on platform-specific compiled c modules.
* The used RSA implementation is only capable of processing so many bytes of data at once during encryption, fields larger than that value have to be split into blocks. This might enable certain attacks on the RSA crypto system. To mitigate the chances of a successful attack, random padding (PKCS#1 v2 (OAEP)) is used and can not be disabled in this version of the add-on.
* Using 1024 bit RSA keys is generally considered unsafe and therefore not possible using with the add-on.
* I chose AES-CBC and AES-OFB as the only available modes as they offer the best balance between performance and security for the purposes of this add-on.

* It is not recommended to use MD5 or SHA1 for security purposes (e.g. storing password hashes) since these hashing algorithms are not regarded as safe anymore.
* It is not recommended to use the ciphers provided through the _cipher_ command for security purposes (e.g. storing safely encrypted data) since these algorithms are not regarded as safe anymore.
* SHA3 and Blake2 are only available when using Python3 as your environment's interpreter.


## TODO / Roadmap / Known Issues

### v2.3 plan

* Better error handling
* Increase performance
* Add further ciphers (RC2, RC4-Drop, ...) and potentially arguments to control cipher parameters
* Add further encodings (Punycode, ...) and potentially arguments to control encoding parameters
* Disable helper inputs by default
* Potentially implement support for wildcards for field names


## History

### v2.2.3

* Fullfilling requirements for Splunk Cloud vetting (shoutout and thank you to Windu Sayles for the support)

### v2.2.2

* Implemented support for Base58 and Base62 encoding/decoding

### v2.2.1

* Repackaged using Splunk Add-On Builder v4.0.0
* Updated Splunk Python SDK to v1.6.16

### v2.2

* Implemented _cipher_ command to cipher/decipher fields or complete events during search time using RC4, ROT13, ROT47, ROX
* Implemented _encode_ command to encode/decode fields or complete events during search time using Base32, Base64, Binary, Decimal, Hex, Octal
* Improved documentation
* Updated Splunk Python SDK to v1.6.15, removing a bug which can cause Splunk instances to hang

### v2.1

* Tested and documented support for encrypted private RSA keys

### v2.1b

* Replaced "cryptography" with "pycryptodomex" as compatibility is better

### v2.1a

* Re-implemented support for encrypted private RSA keys through the "cryptography" Python package
* Accounting for Splunk sometimes randomly removing \\n or spaces for no apparent reason when saving keys/salts
* Updated Splunk Python SDK

### v2.0.1b

* Fixed support for distributed environments

### v2.0b

* Ensured and tested Splunk 8 compatibility
* Ensured and tested Python2/3 cross-compatibility for crypt command
* Ensured and tested Python2/3 cross-compatibility for hash command
* Added a logo

### v2.0a

* Updated Splunk SDK for Python
* Using custom search command protocol v2 now
* Updated README and docs with soon-to-come changes
* Implemented proper key/salt management on per-user and per-role basis
* Added licenses to used Python modules and gave credit

* Removed keyencryption parameter from crypt command and replaced by automatic detection
* Removed randpadding parameter and support for non-random padding
* Implemented basic review checks for private/public RSA key usage during encryption/decryption attempts
* Implemented PKCS#1 v2 (OAEP) support
* Implemented possibility for AES-128/192/256-CBC/OFB field/event encryption & decryption
* AES-CBC and AES-OFB are now the only parameter values and modes for AES encryption/decryption

* Ensured Splunk 8 and Python 2/3 cross-compatilibity for hash command
* Hashes will now be written to a new field with the name of the used algorithm
* Renamed saltfile parameter to salt
* Implemented SHA3 and Blake2 support for environments using Python 3

*See https://github.com/my2ndhead/SA-hypercrypto for previous, deprecated versions.*


## Attributions

The add-on relies on the Splunk Add-On builder[1], developed by Splunk and licensed under the Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0.

The _crypt_ command uses a slightly modified version of Sybren A. Stuevel's (https://stuvel.eu/) pure-Python RSA implementation [2] which is licensed under the Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0. This module itself relies on Ilya Etingof's pyasn1 Python module [2.2] which is licensed under the BSD 2-Clause License, https://spdx.org/licenses/BSD-2-Clause.html. Changes include the PKCS#1 v2 (OAEP) support suggested and implemented by Inada Naoki (https://twitter.com/methane) [2.3] which is licensed under the Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0 as well.

The _crypt_ command also uses Richard Moore's (http://www.ricmoo.com/) pure-Python AES implementation [3] which is licensed under the MIT License, https://opensource.org/licenses/MIT.

When including a system wide Python installation's package library, the add-on will make use of Python's "pycryptodomex" package [4] which is partially in the public domain and partially released under the BSD 2-Clause license https://www.pycryptodome.org/en/latest/src/license.html.

The _encode_ command uses a pure-Python Base58 implementation based on David Keijser's code [5] which is licensed under the MIT License, https://opensource.org/licenses/MIT.

The _encode_ command uses a pure-Python Base62 implementation based on Sumin Byeon's code [6] which is licensed under the BSD 2-Clause Simplified License, https://spdx.org/licenses/BSD-2-Clause.html.


## License

**This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.** [7]

This roughly translates to 

* You may freely use, share and adapt this work non-commercially as long as you give appropriate credit. When adapting or sharing, this needs to happen under the same license, changes should be indicated.
* You may freely use this work in a commercial environment as long as the use is not primarily intended for commercial advantage or monetary compensation. YOU MAY NOT SELL THIS WORK. Neither standalone nor within an application bundle.

As this paragraph is not a substitute for the license, please refer to _References_ for completeness and correctness. 

Feel free to contact me should you plan to use the add-on outside these terms.


## References

[0] https://www.splunk.com/en_us/blog/security/storing-encrypted-credentials.html

[1] https://splunkbase.splunk.com/app/2962

[2] https://github.com/sybrenstuvel/python-rsa

[2.2] https://github.com/etingof/pyasn1

[2.3] https://github.com/sybrenstuvel/python-rsa/pull/126 and https://github.com/methane/python-rsa/tree/rsa_oaep

[3] https://github.com/ricmoo/pyaes

[4] https://pypi.org/project/pycryptodomex/

[5] https://github.com/suminb/base62

[6] https://github.com/keis/base58

[7] http://creativecommons.org/licenses/by-nc-sa/4.0/

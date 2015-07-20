# Support Add-on for Hypercrypto
- **Authors**:		Simon Balz <simon@balz.me>, Mika Borner <mika.borner@gmail.com>, Christoph Dittmann <mulibu.flyingk@gmail.com>, Harun Kuessner <h.kuessner@posteo.de>
- **Description**:	A Splunk> Support Add-On introducing the 'crypt' command for encrypting fields using RSA and decrypting RSA encrypted fields.
- **Version**: 		1.4

## Introduction
The Support Add-on for Hypercrypto provides a custom search commands which enables the user to encrypt and decrypt during search time using RSA.

## Features
 - Encrypt fields during search time using RSA
 - Decrypt fields during search time using RSA  
 - Manage the usage of encryption and decryption via two new roles
 - Manage the decryption of specific fields on a per user basis using encrypted private key files and providing only authorized users with the corresponding password.
 - The purpose is to allow only a specific set of users to view certain information due to legal restrictions, privacy policies, etc.

## Additional Notes for Apptitude App Contest
- The app uses only portable code and is tested thoroughly on *nix systems.
- The app will be used within customer projects, and improved according to customer and community needs. Development of the app will happen in public. Bugs/Issues and improvement requests can be opened on the project's Github page (<https://github.com/my2ndhead/SA-hypercrypto/issues>).

## Release Notes
- **v1.4**  /   2015-07-20
  - Bugfixes and final release for Apptitude2 submission
- **v1.3**	/ 	2015-07-15
	- Implemented support for encrypting fields larger than 245 bytes

## Installation and Usage

### Installation
1. Download the [latest](https://github.com/my2ndhead/SA-hypercrypto/archive/master.zip) add-on
2. Unpack and upload the add-on to the search head
   IMPORTANT: Make sure, the App's folder name in $SPLUNK_HOME/etc/apps is SA-hyperbaseline (Downloading apps from git and uploading them to Splunk will result in wrong folder names)
3. Restart Splunk
4. Provide users or roles with the roles 'can_encrypt' and/or 'can_decrypt' needed for using the crypt command.
5. Generate a valid RSA key pair and store it in PEM format.
   Example using OpenSSL:
     openssl genrsa [-aes256|-des|-des3 -passout pass:password] -out private.pem <2048|4096>
     openssl rsa -in private.pem -outform PEM -RSAPublicKey_out -out public.pem
   Note that using 1024 bit keys is considered unsafe and therefore forbidden.
6. Optional:
   If you plan to use an encrypted private key provide a corresponding password
   via the app's set up screen 'Manage Apps -> SA-hypercrypto -> Set Up'.
   Passwords for encrypted private key files can be set per user and key file and get stored in Splunk's internal password storage.

**Note**: This procedure is a security feature, since specifing the password directly in the search would make it visible in the _internal index.

### Usage
- Syntax
 crypt mode=<d|e> key=<filepath> [keyencryption=<true|false> |              \
       randpadding=<boolean>] <fieldlist>

 where
 mode=e specifies encryption for the given field list using the provided key.
 mode=d specifies decryption for the given field list using the provided key.

 When setting the optional parameter randpadding to false, random padding during field encryption is disabled resulting in a unique cipher for each unique field value. Otherwise encryption results in a unique cipher per event.
 Setting randpadding to false is not recommended since it allows certain attacks on the RSA crypto system.

 When using an encrypted private key for field decryption, set the optional parameter 'keyencryption' to true. The password to use will be drawn from Splunk's password storage.
 Passwords can be set per user and key file in the app's set up screen.
 Currently supported algorithms for key encryption are AES256-CBC, DES-CBC and DES-EDE3-CBC.  

### Examples
Decrypt the content of the already RSA encrypted field username for
output in plain text using the key file lib/keys/private.pem.
The key file is encrypted with AES256-CBC, so set keyencryption to true. The correspondig password has to be set via the app's set up screen prior to using the key.

search sourcetype="server::access" | crypt mode=d key=lib/keys/private.pem
keyencryption=true username | table _time action username

Encrypt the values of the fields subject and content of sourcetype mail stored in plain text.

search sourcetype="mail" | crypt mode=e key=lib/keys/public.pem subject content

Encrypt raw events of sourcetype mail and collect the results in a summary index.

search sourcetype="mail" | crypt mode=e key=lib/keys/public.pem _raw | collect index=summary

## Known Issues
- Attempts to encrypt _time will be ignored since Splunk expects a valid _time
 field.
- Wildcards for field names are not supported.
- Currently only PKCS#1 v1.5 encryption is implemented, support for PKCS#1 v2
 will follow.
- Password management via the set up screen has not been implemented yet, since Splunk does not provide a way to do so via SimpleXML. So you can not update stored passwords at this point in time. Manage your stored passwords in SA-hypercrypto/local/app.conf.
- Currently only AES-256-CBC, DES-CBC and DES-EDE3-CBC are supported for private key file encryption.
=======
- Because of limitations of the Splunk Password Keystore, a user needs the "admin_all_objects" -capability to access his key. We recommend to only assign the capability for a limited time. A future release of Splunk or Hyperthreat will work around this issue.

### Security considerations
 - Disabling random padding is useful in some cases but enables certain attacks to the RSA crypto system. So use randpadding=false with caution.
 - The RSA implementation is only capable of processing 255 - 11 bytes of data at once. Fields larger than that have to be split. This enables certain attacks to the RSA crypto system. Therefore it is reccomended to always set randpadding=t when encrypting large fields.

### Notes
 - Tested with Splunk 6.2.x and Splunk 6.3 beta
 - The crypt command uses a slightly modified version of Sybren A. Stuevel's  \
   <sybren@stuvel.eu> RSA implementation in python which is licensed under    \
   the under the Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0.
 


##############################################################################
#---   Also introducing the 'hash' command for hashing fields using the   ---#
#---  common hashing algorithms MD5, SHA1, SHA224, SHA256, SHA384, SHA51  ---#
##############################################################################
=======
# Appendix

## Hash command

### Introduction
The Support Add-on for Hypercrypto also provides a custom search command 'hash' for hashing fields using the common hashing algorithms MD5, SHA1, SHA224, SHA256, SHA384, SHA51

### Key features

 - Hash fields during search time using MD5, SHA1, SHA224, SHA256, SHA384 or  \
   SHA51

 - The purpose is to mask fields, map fields to short and unique values and   \
   to expand the app's possible application by supporting the crypt command.

### Set Up

 - Place SA-hypercrypto under $SPLUNK_HOME/etc/apps/
 - Optional:
   Generate a file containing a salt for spicing your hashes.

### Usage

 - Syntax
   hash algorithm=<md5|sha1|sha224|sha256|sha384|sha512>                      \
        [saltfile=<file_path>] <field-list>

   When setting the optional parameter saltfile, the content of the specified \
   file gets applied as a salt to the field values to hash.

### Restrictions

 - Attempts to hash _time will be ignored since Splunk expects a valid _time field.
 - Wildcards for field names are not supported.

### Notes

 - It is not recommended to use MD5 or SHA1 since these hashing algorithms    \
   are not regarded as safe anymore.
 - You can always use Splunk's secret file $SPLUNK_HOME/etc/auth/splunk.secret
   as salt.
 - Tested with Splunk 6.2.x and Splunk 6.3 beta

## License
- **This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.** [1]
- **Commercial Use, Excerpt from CC BY-NC-SA 4.0:**
  - "A commercial use is one primarily intended for commercial advantage or monetary compensation."
- **In case of Support Add-on for Hypercrypto this translates to:**
  - You may use Support Add-on for Hyperbaseline in commercial environments for handling in-house Splunk alerts
  - You may use Support Add-on for Hypercrypto as part of your consulting or integration work, if you're considered to be working on behalf of your customer. The customer will be the licensee of Support Add-on for Hypercrypto and must comply according to the license terms
  - You are not allowed to sell Support Add-on for Hypercrypto as a standalone product or within an application bundle
  - If you want to use Support Add-on for Hypercrypto outside of these license terms, please contact us and we will find a solution

## References
[1] http://creativecommons.org/licenses/by-nc-sa/4.0/

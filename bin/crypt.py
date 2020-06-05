#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "crypt" used 
    for encrypting and decrypting fields during search time using RSA or AES.
    
    Author: Harun Kuessner
    Version: 2.0a
    License: http://creativecommons.org/licenses/by-nc-sa/4.0/
"""

from __future__ import absolute_import
from __future__ import print_function

#from cryptography.hazmat.backends   import default_backend
#from cryptography.hazmat.primitives import serialization

#from Crypto.PublicKey import RSA
#from Crypto.Random import get_random_bytes
#from Crypto.Cipher import AES, PKCS1_OAEP

#from rsa._compat     import b
#from xml.dom         import minidom
#from xml.dom.minidom import Node

import base64
#import binascii
#import M2Crypto
import json
import sys
import rsa

import splunklib.client as client
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class cryptCommand(StreamingCommand):
    """ 
    ##Syntax

    crypt mode=<d|e> algorithm=<rsa|aes-128-cbc|aes-192-cbc|aes-256-cbc> key=<file_name> [randpadding=<bool>] <field-list>

    ##Description
    
    Values of fields provided by `field-list` are encrypted or decrypted with
    the key provided by `key` and the algorithm specified by `algorithm` depending on the mode set by `mode`.
    
    Currently supported cryptographic algorithms are RSA and AES-128/192/256-CBC.
    
    Encrypted private RSA keys are supported if encrypted with AES256-CBC, DES-CBC or DES-EDE3-CBC.
    
    The optional parameter `randpadding` is only valid when using RSA. Set to false, to disable usage of 
    random padding during field encryption, resulting in the same cipher for same field value. 
    Otherwise encryption results in a unique cipher even for same field values. Set randpadding to false 
    with caution since it allows certain attacks on the RSA crypto system.

    ##Requirements

    Properly deployed key files and properly configured permissions to use these key files.
    See README.md.

    ##Examples

    Encrypt the values of the plaintext fields "subject" and "content" of sourcetype "mail" using rsa and the key "public.pem".
    
    search sourcetype="mail" | crypt mode=e algorithm=rsa key=public.pem subject content
    
    Encrypt raw events of sourcetype "mail" using AES-256-CBC and collect the results in a summary index.
    
    search sourcetype="mail" | crypt mode=e algorithm=aes-256-cbc key=secret.txt _raw | collect index=summary
    
    Decrypt the content of the already RSA encrypted and summary-indexed field "username" for output in plain text using RSA. 
    The key file "private.pem" is encrypted with AES-256-CBC, so the correspondig password has to be set via the app's set up screen prior to using the key.
    
    search index=summary sourcetype="server::access" | crypt mode=d algorithm=rsa key=private.pem username | table _time action username
    """



    mode = Option(
        doc='''
        **Syntax:** **mode=***<d|e>*
        **Description:** d for decryption or e for encryption''',
        require=True)

    algorithm = Option(
        doc='''
        **Syntax:** **algorithm=***<rsa|aes-128-cbc|aes-192-cbc|aes-256-cbc>*
        **Description:** cryptographic algorithm to use''',
        require=True)    

    key = Option(
        doc='''
        **Syntax:** **key=***<file_name>*
        **Description:** name of the file containing the cryptographic key to use''',
        require=True)      

    randpadding = Option(
        doc='''
        **Syntax:** **randpadding=***<bool>*
        **Description:** use random padding while encrypting with RSA or not''',
        require=False, validate=validators.Boolean())   



    ## Helper to check if a user is privileged to do what he is trying to do
    #
    def validate_user(self, service):
        auth_roles = []
        auth_users = []
        user       = self._metadata.searchinfo.username
        roles      = []

        try:
            auth_roles = service.confs['inputs']['crypto_settings://{0}'.format(self.key)]['authorized_roles'].split('~')
        except AttributeError:
            pass
        try:
            auth_users = service.confs['inputs']['crypto_settings://{0}'.format(self.key)]['authorized_users'].split('~')
        except AttributeError:
            pass

        for role in service.users[self._metadata.searchinfo.username]['role_entities']:
            roles.append(role.name)
            for imported_role in role.imported_roles:
                roles.append(imported_role)

        if self.mode == 'e' and not 'can_encrypt' in roles:
            raise RuntimeWarning('User "{0}" is not authorized to perform field encryption.'.format(user))
        if self.mode == 'd' and not 'can_decrypt' in roles:
            raise RuntimeWarning('User "{0}" is not authorized to perform field decryption.'.format(user))

        if user in auth_users:
            return True
        else:
            for role in roles:
                if role in auth_roles:
                    return True

        return False



    ## Helper to load keys and run basic sanity checks
    #
    def load_key(self, service):
        stored_key = service.storage_passwords.list(count=-1, search='data/inputs/crypto_settings:'.format(self.key))
        key_dict   = ""

        for chunk in stored_key:
            key_dict += chunk.clear_password if 'data/inputs/crypto_settings:{0}'.format(self.key) in chunk.name else ""
        key_dict = json.loads(key_dict.split('``splunk_cred_sep``', 1)[0])

        if self.algorithm == 'rsa':
            if not key_dict['key_salt'].startswith('-----BEGIN RSA '):
                raise RuntimeWarning('Currently only RSA keys in PEM format are supported. Please specify a valid key file.')

            # Load RSA public key
            if self.mode == 'e':
                if not ' PUBLIC KEY-----' in key_dict['key_salt']:
                    raise RuntimeWarning('Currently only public RSA keys in PEM format are supported. Please specify a valid public key file.')
                if len(key_dict['key_salt'].strip('\n').split('-----')[-3]) < 220:
                    raise RuntimeWarning('1024 bit RSA keys are generally considered insecure and are therefore unsupported. Please use a larger key.')

                try:
                    key = key_dict['key_salt'][:30] + key_dict['key_salt'][30:-28:].replace(' ', '\n') + key_dict['key_salt'][-28:] + "\n"
                    return rsa.key.PublicKey.load_pkcs1(key.encode('utf-8'), 'PEM')
                    #return serialization.load_pem_public_key(key_dict['key_salt'], backend=default_backend())
                except Exception as e:
                    raise RuntimeWarning('Failed to load specified public key: {0}.'.format(e))

            # Load RSA private key
            else:
                if not ' PRIVATE KEY-----' in key_dict['key_salt']:
                    raise RuntimeWarning('Currently only private RSA keys in PEM format are supported. Please specify a valid private key file.')
                if len(key_dict['key_salt'].strip('\n').split('-----')[-3]) < 824:
                    raise RuntimeWarning('1024 bit RSA keys are generally considered insecure and are therefore unsupported. Please use a larger key.')

                try:
                    if 'DEK-Info:' in key_dict['key_salt'] and 'rsa_key_encryption_password' not in key_dict:
                        raise RuntimeWarning('No password was configured for encrypted private key. Please configure one before using this key.')
                    if 'DEK-Info:' in key_dict['key_salt']:
                        pass
                        # TODO
                        # RSA module does not support encrypted keys....
                        #return M2Crypto.RSA.load_key(key_dict['key_salt'], key_dict['rsa_key_encryption_password'] if 'rsa_key_encryption_password' in key_dict else None)
                    else:
                        try:
                            key = key_dict['key_salt'][:31] + key_dict['key_salt'][31:-29:].replace(' ', '\n') + key_dict['key_salt'][-29:] + "\n"
                            return rsa.key.PrivateKey.load_pkcs1(key.encode('utf-8'), 'PEM')
                            #return serialization.load_pem_public_key(key_dict['key_salt'], backend=default_backend())
                        except Exception as e:
                            raise RuntimeWarning('Failed to load specified public key: {0}.'.format(e))
                    #return serialization.load_pem_private_key(key_dict['key_salt'], 
                    #                                          password=key_dict['rsa_key_encryption_password'] if 'rsa_key_encryption_password' in key_dict else None, 
                    #                                          backend=default_backend())
                except Exception as e:
                    raise RuntimeWarning('Failed to load specified private key: {0}'.format(e))

        # Load AES key and IV
        elif self.algorithm in ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc']:
            # TODO
            pass
        else:
            raise RuntimeWarning('Invalid or unsupported algorithm specified: {0}.'.format(self.algorithm))



    ## Helpers for encryption and decryption
    #
    def rsa_encrypt(self, fieldname, field, key): 
        # Split fields bigger than 256-11 bytes
        if len(field) > 245:
            chunk = ""
            for i in range(0, len(field), 245):
                try:                          
                    # Use random padding or not for RSA encryption
                    if self.randpadding in [None, True]:
                        chunk += base64.encodestring(rsa.encrypt(field[i:i+245].encode('utf-8'), key)).decode("utf-8")
                    else:
                        # TODO Re-implement non-random padding into RSA lib or remove non-random padding support
                        chunk += base64.encodestring(rsa.encrypt_rand_padding(field[i:i+245], key)).decode("utf-8")
                except Exception as e:
                    raise RuntimeWarning('Encryption failed for field "{0}". Reason: {1}'.format(fieldname, e))
            return chunk

        # Otherwise encrypt straight forward
        else:
            try:
                # Use random padding or not for RSA encryption
                if self.randpadding in [None, True]:
                    return base64.encodestring(rsa.encrypt(field.encode('utf-8'), key)).decode("utf-8")
                else:
                    # TODO Re-implement non-random padding into RSA lib or remove non-random padding support
                    return base64.encodestring(rsa.encrypt_zero_padding(field, key)).decode("utf-8")
            except Exception as e:
                raise RuntimeWarning('Encryption failed for field "{0}". Reason: {1}'.format(fieldname, e))   

    def rsa_decrypt(self, fieldname, field, key):
        # Rejoin split fields (fields bigger than 256-11 bytes)
        if len(field.replace('\n', '')) > 344:
            clear = ""
            for chunk in field.split('=='):
                if len(chunk) <= 1:
                    continue
                chunk = chunk.replace('\n', '') + '=='
                try:
                    clear += rsa.decrypt(base64.decodestring(chunk.encode('utf-8')), key).decode("utf-8")
                    #chunk += key.private_decrypt(base64.decodestring(chunk), M2Crypto.RSA.pkcs1_padding)
                except Exception as e:
                    raise RuntimeWarning('Decryption failed for field "{0}". Reason: {1}'.format(fieldname, e))
            return clear

        # Otherwise decrypt straight forward
        else:
            try:
                return rsa.decrypt(base64.decodestring(field.replace('\n', '').encode('utf-8')), key).decode("utf-8")
                #return key.private_decrypt(base64.decodestring(field), M2Crypto.RSA.pkcs1_padding)
            except Exception as e:
                raise RuntimeWarning('Decryption failed for field "{0}". Reason: {1}'.format(fieldname, e))

    def aes_encrypt(self, fieldname, field, key):
        # TODO
        pass
    def aes_decrypt(self, fieldname, field, key):
        # TODO
        pass



    ## Sort of "__main__"
    #
    def stream(self, events):     
        # Bind to Splunk session and initialize variables
        service = client.Service(token=self.metadata.searchinfo.session_key)
        
        # Check if configuration exists for specified key
        try:
            service.confs['inputs']['crypto_settings://{0}'.format(self.key)]
        except:
            raise RuntimeWarning('Specified key file "{0}" does not exist. Please check the spelling of your specified key name or your configured keys.'.format(self.key))

        # ENCRYPTION
        #
        if self.mode == 'e':
            # Continue if user is authorized for encryption and key usage
            if self.validate_user(service):
                # Load key and do sanity checks
                key = self.load_key(service)
        
                # Perform field encryption
                for event in events:
                    for fieldname in self.fieldnames:
                        # Always skip _time
                        if fieldname=='_time':
                            continue
                            
                        if self.algorithm == 'rsa':
                            event[fieldname] = self.rsa_encrypt(fieldname, event[fieldname], key)
                        elif self.algorithm in ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc']:
                            event[fieldname] = self.aes_encrypt(fieldname, event[fieldname], key)
                        else:
                            raise RuntimeWarning('Invalid or unsupported algorithm specified: {0}.'.format(self.algorithm))
                    yield event
            else:
                raise RuntimeWarning('User "{0}" is not authorized to use the specified encryption key.'.format(self._metadata.searchinfo.username))

        # DECRYPTION
        #
        elif self.mode == 'd':
            # Continue if user is authorized for decryption and key usage
            if self.validate_user(service):
                # Load key and do sanity checks
                key = self.load_key(service)

                # Perform field decryption
                for event in events:
                    for fieldname in self.fieldnames:
                        if fieldname=='_time':
                            continue
                        
                        if self.algorithm == 'rsa':
                            event[fieldname] = self.rsa_decrypt(fieldname, event[fieldname], key)
                        elif self.algorithm in ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc']:
                            event[fieldname] = self.aes_decrypt(fieldname, event[fieldname], key)
                        else:
                            raise RuntimeWarning('Invalid or unsupported algorithm specified: {0}.'.format(self.algorithm))
                    yield event
            else:
                raise RuntimeWarning('User "{0}" is not authorized to use the specified decryption key.'.format(self._metadata.searchinfo.username))

        else:
            raise ValueError('Invalid mode "{0}" used. Allowed values are "e" and "d".'.format(self.mode))

dispatch(cryptCommand, sys.argv, sys.stdin, sys.stdout, __name__)

#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "crypt" used 
    for encrypting and decrypting fields during search time using RSA or AES.
    
    Author: Harun Kuessner
    Version: 2.1a
    License: http://creativecommons.org/licenses/by-nc-sa/4.0/
"""

from __future__ import absolute_import
from __future__ import print_function

import base64
import json
import sys

try:
    sys.path.append('/path/to/os-wide/python3.7/site-packages')
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    module = True
except (ImportError, ModuleNotFoundError) as e:
    import pyaes
    import rsa
    module = False

import splunklib.client as client
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators

@Configuration()
class cryptCommand(EventingCommand):
    """ 
    ##Syntax

    crypt mode=<d|e> algorithm=<rsa|aes-cbc|aes-ofb> key=<file_name> <field-list>

    ##Description
    
    Values of fields provided by `field-list` are encrypted or decrypted with
    the key provided by `key` and the algorithm specified by `algorithm` depending on the mode set by `mode`.
    
    Currently supported cryptographic algorithms are RSA and AES-CBC, AES-OFB (with 128/192/256 bit keys).
    
    Encrypted private RSA keys are supported if encrypted with AES256-CBC, DES-CBC or DES-EDE3-CBC.

    ##Requirements

    Properly deployed key files and properly configured permissions to use these key files.
    See README.md.

    ##Examples

    Encrypt the values of the plaintext fields "subject" and "content" of sourcetype "mail" using rsa and the key "public.pem".
    
    search sourcetype="mail" | crypt mode=e algorithm=rsa key=public.pem subject content
    
    Encrypt raw events of sourcetype "mail" using AES-256-CBC and collect the results in a summary index.
    
    search sourcetype="mail" | crypt mode=e algorithm=aes-cbc key=secret.txt _raw | collect index=summary
    
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



    ## Helper to check if a user is privileged to do what he is trying to do
    #
    def validate_user(self, service):
        user, roles, auth_users, auth_roles = self._metadata.searchinfo.username, [], [], []

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
        key_dict   = ''.join([chunk.clear_password if 'data/inputs/crypto_settings:{0}'.format(self.key) in chunk.name else '' for chunk in stored_key])

        if not key_dict.startswith('{'):
            key_dict = json.loads(''.join(key_dict.split('``splunk_cred_sep``', 1)[::-1]).split('``splunk_cred_sep``')[-1])
        else:
            key_dict = json.loads(key_dict.split('``splunk_cred_sep``', 1)[0])

        if self.algorithm == 'rsa':
            if not key_dict['key_salt'].startswith('-----BEGIN RSA '):
                raise RuntimeWarning('Currently only RSA keys in PEM format are supported. Please specify a valid key file.')

            # Load RSA public key
            if self.mode == 'e':
                if not ' PUBLIC KEY-----' in key_dict['key_salt']:
                    raise RuntimeWarning('Only public RSA keys in PEM format are supported. Please specify a valid public key file.')
                if len(key_dict['key_salt'].strip('\n').split('-----')[-3]) < 220:
                    raise RuntimeWarning('1024 bit RSA keys are generally considered insecure and are therefore unsupported. Please use a larger key.')

                try:
                    key = "-----BEGIN RSA PUBLIC KEY-----\n"
                    for i in range(0, len(''.join(key_dict['key_salt'].split('-----')[2])), 64):
                        key +='{}\n'.format(''.join(key_dict['key_salt'].split('-----')[2])[i:i+64])
                    key += "-----END RSA PUBLIC KEY-----"
                    if module:
                        return serialization.load_pem_public_key(key.encode('utf-8'), backend=None), None
                    else:
                        return rsa.key.PublicKey.load_pkcs1(key.encode('utf-8'), 'PEM'), None
                except Exception as e:
                    raise RuntimeWarning('Failed to load specified public key: {0}.'.format(e))

            # Load RSA private key
            else:
                if not ' PRIVATE KEY-----' in key_dict['key_salt']:
                    raise RuntimeWarning('Only private RSA keys in PEM format are supported. Please specify a valid private key file.')
                if len(key_dict['key_salt'].strip('\n').split('-----')[-3]) < 824:
                    raise RuntimeWarning('1024 bit RSA keys are generally considered insecure and are therefore unsupported. Please use a larger key.')

                try:
                    if 'DEK-Info:' in key_dict['key_salt'] and 'rsa_key_encryption_password' not in key_dict:
                        raise RuntimeWarning('No password was configured for encrypted private key. Please configure one before using this key.')
                    elif 'DEK-Info:' in key_dict['key_salt'] and not module:
                        raise RuntimeWarning('Use of encrypted private RSA keys is only supported if the "cryptography" python package is installed and configured via the app\'s setup screen.')
                    elif 'DEK-Info:' in key_dict['key_salt'] and module:
                        key = ' '.join(key_dict['key_salt'].split(' ')[0:4]) + '\n' + ' '.join(key_dict['key_salt'].split(' ')[4:6]) + '\n' + ' '.join(key_dict['key_salt'].split(' ')[6:8]) + '\n\n'
                        for i in range(0, len(''.join(key_dict['key_salt'].split('-----')[2].split(' ')[5::])), 64):
                            key +='{}\n'.format(''.join(key_dict['key_salt'].split('-----')[2].split(' ')[5::])[i:i+64])
                        key += "-----END RSA PRIVATE KEY-----"
                        return serialization.load_pem_private_key(key.encode('utf-8'), password=key_dict['rsa_key_encryption_password'].encode('utf-8'), backend=None), None
                    else:
                        key = "-----BEGIN RSA PRIVATE KEY-----\n"
                        for i in range(0, len(''.join(key_dict['key_salt'].split('-----')[2])), 64):
                            key +='{}\n'.format(''.join(key_dict['key_salt'].split('-----')[2])[i:i+64])
                        key += "-----END RSA PRIVATE KEY-----"
                        if module:
                            return serialization.load_pem_private_key(key.encode('utf-8'), password=None, backend=None), None
                        else:
                            return rsa.key.PrivateKey.load_pkcs1(key.encode('utf-8'), 'PEM'), None
                except Exception as e:
                    raise RuntimeWarning('Failed to load specified private key: {0}'.format(e), key)

        # Load AES key and IV
        elif self.algorithm in ['aes-cbc', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc', 'aes-ofb', 'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb']:
            key, iv = "", ""
            key_dict['key_salt'].strip(' \r\n')

            try:
                if len(key_dict['key_salt']) in [48, 49, 50]:
                    key = key_dict['key_salt'][0:32]
                    iv  = key_dict['key_salt'][-16::]
                elif len(key_dict['key_salt']) in [40, 41, 42]:
                    key = key_dict['key_salt'][0:24]
                    iv  = key_dict['key_salt'][-16::]
                elif len(key_dict['key_salt']) in [32, 33, 34]:
                    key = key_dict['key_salt'][0:16]
                    iv  = key_dict['key_salt'][-16::]
                else:
                    raise RuntimeWarning('Key and/or IV do not have the correct length. Key must be 16, 24 or 32 bytes. IV must be 16 bytes.')
                return key, iv
            except Exception as e:
                raise RuntimeWarning('Failed to load AES key and/or IV: {0}.'.format(e))

        else:
            raise RuntimeWarning('Invalid or unsupported algorithm specified: {0}.'.format(self.algorithm))



    ## Helpers for encryption and decryption
    #
    def rsa_encrypt(self, fieldname, field, key, iv=None): 
        # Split fields bigger than 214 bytes
        if (module and len(field) > 189) or len(field) > 214:
            try:
                if module:
                    return ''.join([base64.encodestring(key.encrypt(field[i:i+189].encode('utf-8'), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode('utf-8') for i in range(0, len(field), 189)])
                else:
                    return ''.join([base64.encodestring(rsa.OAEP_encrypt(field[i:i+214].encode('utf-8'), key)).decode('utf-8') for i in range(0, len(field), 214)])
            except Exception as e:
                    raise RuntimeWarning('Encryption failed for field "{0}". Reason: {1}'.format(fieldname, e))
        # Otherwise encrypt straight forward
        else:
            try:
                if module:
                    return base64.encodestring(key.encrypt(field.encode('utf-8'), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode('utf-8')
                else:
                    return base64.encodestring(rsa.OAEP_encrypt(field.encode('utf-8'), key)).decode('utf-8')
            except Exception as e:
                raise RuntimeWarning('Encryption failed for field "{0}". Reason: {1}'.format(fieldname, e))   

    def rsa_decrypt(self, fieldname, field, key, iv=None):
        # Rejoin fields split into blocks during encryption
        if len(field.replace('\n', '')) > 344:
            try:
                if module:
                    return ''.join([key.decrypt(base64.decodestring(''.join([chunk.replace('\n', ''), '==']).encode('utf-8')), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode('utf-8') for chunk in field.split('==') if len(chunk)>1])
                else:
                    return ''.join([rsa.OAEP_decrypt(base64.decodestring(''.join([chunk.replace('\n', ''), '==']).encode('utf-8')), key).decode('utf-8') for chunk in field.split('==') if len(chunk)>1])
            except Exception as e:
                raise RuntimeWarning('Decryption failed for field "{0}". Reason: {1}'.format(fieldname, e))
        # Otherwise decrypt straight forward
        else:
            try:
                if module:
                    return key.decrypt(base64.decodestring(field.replace('\n', '').encode('utf-8')), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode('utf-8')
                else:
                    return rsa.OAEP_decrypt(base64.decodestring(field.replace('\n', '').encode('utf-8')), key).decode('utf-8')
            except Exception as e:
                raise RuntimeWarning('Decryption failed for field "{0}". Reason: {1}'.format(fieldname, e))

    def aes_encrypt(self, fieldname, field, key, iv):
        # AES-CBC
        if self.algorithm in ['aes-cbc', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc']:
            try:
                if module:
                    cipher      = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv.encode('utf-8')))
                    encryptor   = cipher.encryptor()
                    cipher_text = encryptor.update(field.encode('utf-8')) + encryptor.finalize()
                else:
                    encryptor    = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key.encode('utf-8'), iv=iv.encode('utf-8')))
                    cipher_text  = encryptor.feed(field.encode('utf-8'))
                    cipher_text += encryptor.feed()
                return base64.encodestring(cipher_text).decode('utf-8')
            except Exception as e:
                raise RuntimeWarning('Encryption failed for field "{0}". Reason: {1}'.format(fieldname, e))

        # AES-OFB
        elif self.algorithm in ['aes-ofb', 'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb']:
            try:
                if module:
                    cipher      = Cipher(algorithms.AES(key.encode('utf-8')), modes.OFB(iv.encode('utf-8')))
                    encryptor   = cipher.encryptor()
                    cipher_text = encryptor.update(field.encode('utf-8')) + encryptor.finalize()
                    return base64.encodestring(cipher_text).decode('utf-8')
                else:
                    aes = pyaes.AESModeOfOperationOFB(key.encode('utf-8'), iv=iv.encode('utf-8'))
                    return base64.encodestring(aes.encrypt(field.encode('utf-8'))).decode('utf-8')
            except Exception as e:
                raise RuntimeWarning('Encryption failed for field "{0}". Reason: {1}'.format(fieldname, e))

        else:
            raise RuntimeWarning('Invalid or unsupported algorithm specified: {0}.'.format(self.algorithm))

    def aes_decrypt(self, fieldname, field, key, iv):
        # AES-CBC
        if self.algorithm in ['aes-cbc', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc']:
            try:
                if module:
                    cipher      = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv.encode('utf-8')))
                    decryptor   = cipher.decryptor()
                    plain_text  = decryptor.update(base64.decodestring(field.encode('utf-8'))) + decryptor.finalize()
                    return plain_text.decode('utf-8')
                else:
                    decryptor   = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key.encode('utf-8'), iv=iv.encode('utf-8')))
                    plain_text  = decryptor.feed(base64.decodestring(field.encode('utf-8')))
                    plain_text += decryptor.feed()
                    return plain_text.decode('utf-8')
            except Exception as e:
                raise RuntimeWarning('Encryption failed for field "{0}". Reason: {1}'.format(fieldname, e))

        # AES-OFB
        elif self.algorithm in ['aes-ofb', 'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb']:
            try:
                if module:
                    cipher      = Cipher(algorithms.AES(key.encode('utf-8')), modes.OFB(iv.encode('utf-8')))
                    decryptor   = cipher.decryptor()
                    plain_text  = decryptor.update(base64.decodestring(field.encode('utf-8'))) + decryptor.finalize()
                    return plain_text.decode('utf-8')
                else:
                    aes = pyaes.AESModeOfOperationOFB(key.encode('utf-8'), iv=iv.encode('utf-8'))
                    return aes.decrypt(base64.decodestring(field.encode('utf-8'))).decode('utf-8')
            except Exception as e:
                raise RuntimeWarning('Decryption failed for field "{0}". Reason: {1}'.format(fieldname, e))

        else:
            raise RuntimeWarning('Invalid or unsupported algorithm specified: {0}.'.format(self.algorithm))



    ## Sort of "__main__"
    #
    def transform(self, events):     
        # Bind to Splunk session and initialize variables
        service = client.Service(token=self.metadata.searchinfo.session_key)

        # Check if configuration exists for specified key
        try:
            service.confs['inputs']['crypto_settings://{0}'.format(self.key)]
        except:
            raise RuntimeWarning('Specified key file "{0}" does not exist. Please check the spelling of your specified key name or your configured keys.'.format(self.key))

        # TODO: Check and test if itertools might be useable at some point
        # TODO: Check out decorator caching
        # TODO: Do code profiling to find bottlenecks

        # ENCRYPTION
        #
        if self.mode == 'e':
            # Continue if user is authorized for encryption and key usage
            if self.validate_user(service):
                # Set encryption method
                if self.algorithm == 'rsa':
                    _encrypt = self.rsa_encrypt
                elif self.algorithm in ['aes-cbc', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc', 'aes-ofb', 'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb']:
                    _encrypt = self.aes_encrypt
                else:
                    raise RuntimeWarning('Invalid or unsupported algorithm specified: {0}.'.format(self.algorithm))

                # Load key and do sanity checks
                key, iv = self.load_key(service)

                # Perform field encryption
                for event in events:
                    for fieldname in self.fieldnames:
                        # Always skip _time
                        if fieldname=='_time':
                            continue
                        event[fieldname] = _encrypt(fieldname, event[fieldname], key, iv)
                    yield event
            else:
                raise RuntimeWarning('User "{0}" is not authorized to use the specified encryption key.'.format(self._metadata.searchinfo.username))

        # DECRYPTION
        #
        elif self.mode == 'd':
            # Continue if user is authorized for decryption and key usage
            if self.validate_user(service):
                # Set decryption mode
                if self.algorithm == 'rsa':
                    _decrypt = self.rsa_decrypt
                elif self.algorithm in ['aes-cbc', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc', 'aes-ofb', 'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb']:
                    _decrypt = self.aes_decrypt
                else:
                    raise RuntimeWarning('Invalid or unsupported algorithm specified: {0}.'.format(self.algorithm))

                # Load key and do sanity checks
                key, iv = self.load_key(service)

                # Perform field decryption
                for event in events:
                    for fieldname in self.fieldnames:
                        if fieldname=='_time':
                            continue
                        event[fieldname] = _decrypt(fieldname, event[fieldname], key, iv)
                    yield event
            else:
                raise RuntimeWarning('User "{0}" is not authorized to use the specified decryption key.'.format(self._metadata.searchinfo.username))

        else:
            raise ValueError('Invalid mode "{0}" used. Allowed values are "e" and "d".'.format(self.mode))

dispatch(cryptCommand, sys.argv, sys.stdin, sys.stdout, __name__)

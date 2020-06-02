#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "crypt" used 
    for encrypting and decrypting fields during search time using RSA or AES.
    
    Author: Harun Kuessner
    Version: 2.0a
    License: http://creativecommons.org/licenses/by-nc-sa/4.0/
"""

from __future__      import absolute_import
from __future__      import print_function
from rsa._compat     import b
from xml.dom         import minidom
from xml.dom.minidom import Node

import base64
import binascii
import M2Crypto
import sys
import re
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
        require=True, validate=validators.File())      

    randpadding = Option(
        doc='''
        **Syntax:** **randpadding=***<bool>*
        **Description:** use random padding while encrypting with RSA or not''',
        require=False, validate=validators.Boolean())   

    def stream(self, records):     
      # Bind to current Splunk session
      #
      service = client.Service(token=self.metadata.searchinfo.session_key)
      
      # Get user objects
      #
      #user = self._metadata.searchinfo.username
      xml_doc            = minidom.parseString(self.input_header["authString"])      
      current_user       = xml_doc.getElementsByTagName('userId')[0].firstChild.nodeValue
      kwargs             = {"sort_key":"realname", "search":str(current_user), "sort_dir":"asc"}
      users              = service.users.list(count=-1,**kwargs)
      user_authorization = 0 

      # Check if a valid PEM file was provided
      #
      file_content = self.key.read()
      file_type = 'PEM'

      if re.match(r'-----BEGIN .* KEY-----', file_content) is None:
          raise RuntimeWarning('Currently only keys in PEM format are supported. Please specify a valid key file.')  

      # Handle encryption
      #
      if re.match(r'e', self.mode) is not None:
          # Check key length
          #
          if len(file_content.rsplit('KEY-----\n')[1].rsplit('\n-----END')[0]) < 256:
              raise RuntimeWarning('Using 1024 bit keys is unsafe and therefore forbidden. Consider generating larger keys.')

          # Check if invoking user is authorized to encrypt data
          #
          for user in users:
              if user.name == current_user:
                  for role in user.role_entities:
                      if re.match(r'can_encrypt', role.name) is not None:
                          user_authorization = 1
                      for imported_role in role.imported_roles:
                          if re.match(r'can_encrypt', imported_role) is not None:
                              user_authorization = 1

          if user_authorization == 1:                  
              # Decode key file's content
              #
              try:
                  enc = rsa.key.PublicKey.load_pkcs1(file_content, file_type)
              except:
                  raise RuntimeWarning('Invalid key file has been provided for encryption.')

              # Perform field encryption
              #
              new_record = ''
              for record in records:
                  for fieldname in self.fieldnames:
                      if fieldname=='_time':
                          continue

                      # Split fields bigger than 256-11 bytes.
                      #
                      if len(record[fieldname]) > 245:
                          for i in xrange(0,len(record[fieldname]),245):
                              try:                          
                                  # Do not use random padding for encryption
                                  #
                                  if re.match(r'False', str(self.randpadding)):                
                                      new_record += base64.encodestring(rsa.encrypt_zero_padding(record[fieldname][i:i+245], enc)) 
                                  # Use random padding for encryption
                                  #
                                  else:                               
                                      new_record += base64.encodestring(rsa.encrypt_rand_padding(record[fieldname][i:i+245], enc))
                              except:
                                  raise RuntimeWarning('Encryption failed for field: %s' % fieldname)                                  
                          record[fieldname] = new_record
                          new_record = ''

                      else:
                          try:
                              # Do not use random padding for encryption
                              #
                              if re.match(r'False', str(self.randpadding)):                          
                                  record[fieldname] = base64.encodestring(rsa.encrypt_zero_padding(record[fieldname], enc))
                              # Use random padding for encryption
                              #
                              else:                         
                                  record[fieldname] = base64.encodestring(rsa.encrypt_rand_padding(record[fieldname], enc))
                          except:
                              raise RuntimeWarning('Encryption failed for field: %s' % fieldname)
                  yield record

          else:
              raise RuntimeWarning('User \'%s\' is not authorized to perform field encryption.' % str(current_user))


      # Handle decryption
      #
      elif re.match(r'd', self.mode) is not None:
          # Check if invoking user is authorized to decrypt data
          #
          for user in users:
              if user.name == current_user:
                  for role in user.role_entities:
                      if re.match(r'can_decrypt', role.name) is not None:
                          user_authorization = 1
                      for imported_role in role.imported_roles:
                          if re.match(r'can_decrypt', imported_role) is not None:
                              user_authorization = 1

          if user_authorization == 1:
              # Handle key file decryption
              #
              if self.keyencryption:       
                  # Get associated password from Splunk's password storage
                  #
                  kwargs = {"sort_key":"realm", "search":str(current_user), "sort_dir":"asc"}
                  storage_passwords = service.storage_passwords.list(count=-1,**kwargs)
                  got_password = 0
                  for storage_password in storage_passwords:
                      if storage_password.realm == self.key.name:
                          got_password = 1
                          password = storage_password.clear_password
                          # Decode encrypted key file's content
                          #
                          read_password = lambda *args: str(password)
                          dec = M2Crypto.RSA.load_key(self.key.name, read_password)
                  if got_password == 0:
                      raise ValueError('No password associated with the specified key file has been set for user \'%s\'.' % str(current_user))

              else:
                  # Decode unencrypted key file's content
                  #
                  try:
                      dec = M2Crypto.RSA.load_key(self.key.name)
                  except:
                      raise RuntimeWarning('Invalid or encrypted key file has been provided for decryption.')

              # Perform field decryption
              #
              new_record = ''
              for record in records:
                  for fieldname in self.fieldnames:
                      if fieldname=='_time':
                          continue

                      # If field was split
                      #
                      if len(record[fieldname]) > 346:
                          for chunk in record[fieldname].split('=\n'):
                              if len(chunk) <= 1:
                                  continue
                              chunk = chunk.replace('\n', '') + '='
                              try:
                                  new_record += dec.private_decrypt(base64.decodestring(chunk), M2Crypto.RSA.pkcs1_padding)
                              except:
                                  raise RuntimeWarning('Decryption failed for field: %s' % fieldname)
                          record[fieldname] = new_record
                          new_record = ''

                      else:
                          try:
                              record[fieldname] = dec.private_decrypt(base64.decodestring(record[fieldname]), M2Crypto.RSA.pkcs1_padding)
                          except:
                              raise RuntimeWarning('Decryption failed for field: %s' % fieldname)
                  yield record

          else:
              raise RuntimeWarning('User \'%s\' is not authorized to perform field decryption.' % str(current_user))

      else:
          raise ValueError('Invalid mode has been set: %s.' % mode)

dispatch(cryptCommand, sys.argv, sys.stdin, sys.stdout, __name__)
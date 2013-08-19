#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginCertInfo.py
# Purpose:      Verifies the target server's certificate validity against
#               Mozilla's trusted root store, and prints relevant fields of the
#               certificate.
#
# Author:       aaron, alban
#
# Copyright:    2012 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

import os
import re
import urllib2
import subprocess
import hashlib
import json
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, constants, \
    X509_V_CODES, SSL_CTX
from utils.SSLyzeSSLConnection import SSLyzeSSLConnection, ClientCertificateError

# Defines for CRL parsing using OpenSSL crl command.
CRL_CACHE_DIR = os.path.join(os.path.dirname(PluginBase.__file__), 'crl')
OPENSSL = "openssl"
OPENSSL_CLR_CMD = " crl -noout -text -inform DER -in "

# Import Trust Stores and EV data (OIDs and fingerprints) during module init.
EV_DB = {}
load_data_path = os.path.join(os.path.dirname(PluginBase.__file__) , 'data')
all_data_files = os.listdir(load_data_path)
ev_files_to_load = []
ca_files_to_load = []
for filename in all_data_files:
    if "_ev_" and ".json" in filename:
        ev_files_to_load.append(filename)

    if ".pem" in filename:
        ca_files_to_load.append(os.path.join(load_data_path, filename))

for filename in ev_files_to_load:
    name = filename.split('_')
    with open(os.path.join(load_data_path, filename)) as json_file:
        json_data = json.load(json_file)
    EV_DB[name[0]] = json_data

class X509CertificateHelper:
    # TODO: Move this somewhere else
    """
    Helper functions for X509 certificate parsing and XML serialization.
    """
    
    def __init__(self, certificate):
        self._cert = certificate

        
    def parse_certificate(self):
        cert_dict = \
            {'version': self._cert.get_version().split('(')[0].strip() ,
             'serialNumber': self._cert.get_serial_number() ,
             'issuer': self._cert.get_issuer_name().get_all_entries() ,
             'validity': {'notBefore': self._cert.get_not_before() ,
                         'notAfter' : self._cert.get_not_after()} ,
             'subject': self._cert.get_subject_name().get_all_entries() ,
             'subjectPublicKeyInfo':{'publicKeyAlgorithm': self._cert.get_pubkey_algorithm() ,
                                     'publicKeySize': str( self._cert.get_pubkey_size()*8) ,
                                     'publicKey': {'modulus': self._cert.get_pubkey_modulus_as_text(),
                                                   'exponent': self._cert.get_pubkey_exponent_as_text()}
                                     },
             'extensions': self._get_all_extensions() ,
             'signatureAlgorithm': self._cert.get_signature_algorithm() ,
             'signatureValue': self._cert.get_signature_as_text() }
        
        return cert_dict
        

    def parse_certificate_to_xml(self):
        cert_dict = self.parse_certificate()
        cert_xml = []
        
        for (key, value) in cert_dict.items():
            for xml_elem in self._keyvalue_pair_to_xml(key, value):
                cert_xml.append(xml_elem)
 
        return cert_xml
            

    def _create_xml_node(self, key, value=''):
        key = key.replace(' ', '').strip() # Remove spaces
        key = key.replace('/', '').strip() # Remove slashes (S/MIME Capabilities)
        
        # Things that would generate invalid XML
        if key[0].isdigit(): # Tags cannot start with a digit
                key = 'oid-' + key 
                
        xml_node = Element(key)
        xml_node.text = value.decode( "utf-8" ).strip()
        return xml_node
    
    
    def _keyvalue_pair_to_xml(self, key, value=''):
        res_xml = []
        
        if type(value) is str: # value is a string
            key_xml = self._create_xml_node(key)
            key_xml.text = value
            res_xml.append(key_xml)
            
        elif value is None: # no value
            res_xml.append(self._create_xml_node(key))
           
        elif type(value) is list: # multiple strings
            for val in value:
                res_xml.append(self._create_xml_node(key, val))
           
        elif type(value) is dict: # value is a list of subnodes
            key_xml = self._create_xml_node(key)
            for subkey in value.keys():
                for subxml in self._keyvalue_pair_to_xml(subkey, value[subkey]):
                    key_xml.append(subxml)
                 
            res_xml.append(key_xml)
            
        return res_xml    


    def _parse_multi_valued_extension(self, extension):
        extension = extension.split(', ')
        # Split the (key,value) pairs
        parsed_ext = {}
        for value in extension:
            value = value.split(':', 1)
            if len(value) == 1:
                parsed_ext[value[0]] = ''
            else:
                if parsed_ext.has_key(value[0]):
                    parsed_ext[value[0]].append(value[1])
                else:
                    parsed_ext[value[0]] = [value[1]]

        return parsed_ext
        
    
    def _parse_authority_information_access(self, auth_ext):
        # Hazardous attempt at parsing an Authority Information Access extension
        auth_ext = auth_ext.strip(' \n').split('\n')
        auth_ext_list = {}
         
        for auth_entry in auth_ext:
            auth_entry = auth_entry.split(' - ')
            entry_name = auth_entry[0].replace(' ', '')

            if not auth_ext_list.has_key(entry_name):
                auth_ext_list[entry_name] = {}
            
            entry_data = auth_entry[1].split(':', 1)
            if auth_ext_list[entry_name].has_key(entry_data[0]):
                auth_ext_list[entry_name][entry_data[0]].append(entry_data[1])
            else:
                auth_ext_list[entry_name] = {entry_data[0]: [entry_data[1]]}
                
        return auth_ext_list
            
              
    def _parse_crl_distribution_points(self, crl_ext):
        # Hazardous attempt at parsing a CRL Distribution Point extension
        crl_ext = crl_ext.strip(' \n').split('\n')
        subcrl = {}

        for distrib_point in crl_ext:
            distrib_point = distrib_point.strip()
            distrib_point = distrib_point.split(':', 1)
            if distrib_point[0] != '':
                if subcrl.has_key(distrib_point[0].strip()):
                    subcrl[distrib_point[0].strip()].append(distrib_point[1].strip())
                else:
                    subcrl[distrib_point[0].strip()] = [(distrib_point[1].strip())]

        return subcrl
        
                
    def _get_all_extensions(self):
        ext_dict = self._cert.get_extension_list().get_all_extensions()

        parsing_functions = {'X509v3 Subject Alternative Name': self._parse_multi_valued_extension,
                             'X509v3 CRL Distribution Points': self._parse_crl_distribution_points,
                             'Authority Information Access': self._parse_authority_information_access,
                             'X509v3 Key Usage': self._parse_multi_valued_extension,
                             'X509v3 Extended Key Usage': self._parse_multi_valued_extension,
                             'X509v3 Certificate Policies' : self._parse_crl_distribution_points,
                             'X509v3 Issuer Alternative Name' : self._parse_crl_distribution_points}
        
        for (ext_key, ext_val) in ext_dict.items():
            # Overwrite the data we have if we know how to parse it
            if ext_key in parsing_functions.keys():
                ext_dict[ext_key] = parsing_functions[ext_key](ext_val)

        return ext_dict
        

class PluginCertInfo(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginCertInfo", description=(''))
    interface.add_command(
        command="certinfo",
        help= "Verifies the target server's certificate validity against "
            "Mozilla's trusted root store, and prints relevant fields of "
            "the certificate. CERTINFO should be 'basic' or 'full'.",
        dest="certinfo")

    interface.add_option(
        option="crl",
        help= "Verify that the certificate ID against the CRL pointed "
             "to by the certificate is accessible and that the certificate "
             "is not revoked.",
        dest=None)


    FIELD_FORMAT = '      {0:<35}{1:<35}'
    
    def process_task(self, target, command, arg):
        if self._shared_settings['verbosity'] > 2:
            print "Processing %s" % target[0]
            
        ctSSL_initialize()
        try: # Get the certificate
            (cert, verify_result) = self._get_cert(target)
        except:
            ctSSL_cleanup()
            raise
        
        # Figure out if/why the verification failed
        untrusted_reason = None
        is_cert_trusted = True
        for ca_name in verify_result:
            if verify_result[ca_name] != 'ok':
                is_cert_trusted = False
                untrusted_reason = ca_name + ' - ' + verify_result[ca_name]
        
        # Results formatting
        cert_parsed = X509CertificateHelper(cert)
        cert_dict = cert_parsed.parse_certificate()

        # Perform CRL checking if the option has been selected.
        if self._shared_settings['crl']:
            self.crl_result = self._check_crl(cert_dict)
        
        # Text output
        cert_txt = []
        if self._shared_settings['certinfo'] == 'basic':
            cert_txt = self._get_basic_text(cert, cert_dict)
        elif self._shared_settings['certinfo'] == 'full':
            cert_txt = [cert.as_text()]
        else:
            pass
            
        fingerprint = cert.get_fingerprint()
        cmd_title = 'Certificate'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]

        # Create text result for any CRL checks done.
        if self._shared_settings['crl']:
            if self.crl_result['verified']:
                crl_result_text = "Certificate not revoked in CRL"
            elif 'uri_error' in self.crl_result:
                crl_result_text = "Problem loading CRL. " + self.crl_result['uri_error']
            else:
                crl_result_text = "Cerificate revoked in CRL at %s. %s" % \
                                  (self.crl_result['revocation'][0], self.crl_result['revocation'][1])
            txt_result.append(self.FIELD_FORMAT.format("CRL verification:", crl_result_text))


        if self._shared_settings['sni']:
            sni_text = 'SNI enabled with virtual domain ' + self._shared_settings['sni']
            txt_result.append(self.FIELD_FORMAT.format("SNI:", sni_text))

        if is_cert_trusted:
            txt_result.append(self.FIELD_FORMAT.format("Trusted or NOT Trusted:", "Trusted"))
        else:
            txt_result.append(self.FIELD_FORMAT.format("Trusted or NOT Trusted:", "NOT Trusted"))

        for ca_name in verify_result:
            if verify_result[ca_name] == 'ok':
                txt_result.append(self.FIELD_FORMAT.format("Validated by Trust Store: ", ca_name))
            else:
                txt_result.append(self.FIELD_FORMAT.format("Not validated by Trust Store: ",
                                                           ca_name + ' - ' + verify_result[ca_name]))

        ev_result = self._is_ev_certificate(cert_dict)

        is_ev = False
        if 'NO_POLICY' in ev_result:
            txt_result.append(self.FIELD_FORMAT.format("X509 Policy in certificate:", 'False'))

        else:
            txt_result.append(self.FIELD_FORMAT.format("X509 Policy in certificate:", 'True'))
            for ev in ev_result:
                if ev_result[ev]:
                    txt_result.append(self.FIELD_FORMAT.format("Policy recognized as EV with:", ev))
                    is_ev = True
        
        is_host_valid = self._is_hostname_valid(cert_dict, target)
        host_txt = 'OK - ' + is_host_valid + ' Matches' if is_host_valid \
                                         else 'MISMATCH'
        
        txt_result.append(self.FIELD_FORMAT.format("Hostname Validation:", host_txt))
        txt_result.append(self.FIELD_FORMAT.format('SHA1 Fingerprint:', fingerprint))
        txt_result.append('')
        txt_result.extend(cert_txt)

        # XML output: always return the full certificate
        host_xml = True if is_host_valid \
                        else False
            
        xml_result = Element(command, argument = arg, title = cmd_title)
        trust_xml_attr = {'isTrustedByAllCAStores' : str(is_cert_trusted),
                          'sha1Fingerprint' : fingerprint,
                          'isExtendedValidation' : str(is_ev),
                          'hasMatchingHostname' : str(host_xml)}
        if untrusted_reason:
            trust_xml_attr['reasonWhyNotTrusted'] = untrusted_reason

        if self._shared_settings['sni']:
            trust_xml_attr['sni'] = self._shared_settings['sni']

        if self._shared_settings['crl']:
            if self.crl_result['verified']:
                trust_xml_attr['crl'] = "verified"
            elif 'uri_error' in self.crl_result:
                trust_xml_attr['crl'] = self.crl_result['uri_error']
            else:
                trust_xml_attr['crl'] = "revoked"
            
        trust_xml = Element('certificate', attrib = trust_xml_attr)
        
        # Add certificate in PEM format
        PEMcert_xml = Element('asPEM')
        PEMcert_xml.text = cert.as_PEM().strip()
        trust_xml.append(PEMcert_xml)
        
        for elem_xml in cert_parsed.parse_certificate_to_xml():
            trust_xml.append(elem_xml)
        xml_result.append(trust_xml)
        
        ctSSL_cleanup()
        return PluginBase.PluginResult(txt_result, xml_result)


    def _is_hostname_valid(self, cert_dict, target):
        (host, ip, port) = target
        
        # Let's try the common name first
        commonName = cert_dict['subject']['commonName'][0]
        if _dnsname_to_pat(commonName).match(host):
            return 'Common Name'
        
        # Check SNI.
        if self._shared_settings['sni']:
            if _dnsname_to_pat(commonName).match(self._shared_settings['sni']):
                return 'SNI'
        
        try: # No luck, let's look at Subject Alternative Names
            alt_names = cert_dict['extensions']['X509v3 Subject Alternative Name']['DNS']
        except KeyError:
            return False
        
        for altname in alt_names:
            if _dnsname_to_pat(altname).match(host):
                return 'Subject Alternative Name'       
        
        return False


    def _check_crl(self, cert):
        self.crl_result = {}
        self.crl_result['verified'] = False

        self.crl_uri = cert['extensions']['X509v3 CRL Distribution Points']['URI'][0]
        self.cert_id = cert['serialNumber']
        
        self.filename_hash_prefix = hashlib.sha1(self.crl_uri).hexdigest()
        self.crl_filename = self.filename_hash_prefix + ".crl"
        self.db_filename = self.filename_hash_prefix + ".db"
        self.err_filename = self.filename_hash_prefix + ".err"
        self.all_crl_files = os.listdir(CRL_CACHE_DIR)
    
        # Check if we have previously failed at retrieving the CRL or if we need to
        # create DB with parsed CRL for the crl_uri before verifying the id.
        if self.err_filename in self.all_crl_files:
            # Load the err file and return the contents as reason.
            with open(CRL_CACHE_DIR + '/' + self.err_filename, 'rb') as self.err_file:
                self.crl_result['uri_error'] = self.err_file.read()
                return self.crl_result
            
        elif self.db_filename not in self.all_crl_files:
            # Try to download the CRL file, save it and then
            # parse the file to create the DB.
            self.crl_der_data = None
            self.target_handler = None
            self.e = None
            try:
                self.target_handler = urllib2.urlopen(self.crl_uri)
                self.crl_der_data = self.target_handler.read()
                self.target_handler.close()
            except urllib2.URLError, self.e:
                # Return early if we couldn't download the CRL file.
                # But first we write HTTP error code and reason to an err file.
                with open(CRL_CACHE_DIR + '/' + self.err_filename, 'wb') as self.err_file:
                    self.err_file.write(str(self.e.code) + ' ' + self.e.reason)
                self.crl_result['uri_error'] = str(self.e.code) + ' ' + self.e.reason
                return self.crl_result

            # Store the received CLR data in DER format as a file.
            with open(CRL_CACHE_DIR + '/' + self.crl_filename, 'wb') as self.crl_file:
                self.crl_file.write(self.crl_der_data)

            # Extract crl data as formatted text using OpenSSL.
            self.openssl_command = OPENSSL + OPENSSL_CLR_CMD +\
                              CRL_CACHE_DIR + "/" + self.crl_filename
            self.crl_text_data = subprocess.Popen(self.openssl_command, shell=True,
                                                  stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT).stdout.read()

            # Create a DB with the IDs, revocation date and possible
            # revocation reason for the extracted data.
            self.crl_db = {}
            self.crl_db['crl_name'] = self.crl_uri.split('/')[-1]
            self.crl_data_lines = self.crl_text_data.split('\n')


            # Parse and create records with ID, date and if present reason.
            # Some hard coded parsing here.
            self.cert_serial = ""
            self.revocation_date = ""
            self.revocation_reason = ""
            self.new_record = False
            self.reason_present = False
            for self.line in self.crl_data_lines:
                self.linestrip = self.line.strip()
                
                if "Serial Number:" in self.linestrip:
                    # Close previous record before creating a new
                    if self.new_record:
                        self.crl_db[self.cert_serial] = (self.revocation_date, self.revocation_reason)
                    self.cert_serial = self.linestrip.split(':')[-1].strip().lower()
                    self.revocation_date = ""
                    self.revocation_reason = ""
                    self.new_record = True

                if "Revocation Date:" in self.linestrip:
                    self.revocation_date = self.linestrip[17:]
            
                if self.reason_present:
                    self.revocation_reason = self.linestrip.split(':')[-1].strip()
                    self.reason_present = False

                if "X509v3 CRL Reason Code:" in self.linestrip:
                    # The next row is assumed to contain the reason.
                    self.reason_present = True
            # Add final record
            self.crl_db[self.cert_serial] = (self.revocation_date, self.revocation_reason)
        
            # Store the DB as a JSON blob.
            self.crl_db_json = json.dumps(self.crl_db)
            with open(CRL_CACHE_DIR + '/' + self.db_filename, 'wb') as self.db_file:
                                        self.db_file.write(self.crl_db_json)

        else:
            # Load the database from the file.
            with open(CRL_CACHE_DIR + '/' + self.db_filename, 'rb') as self.db_file:
                self.crl_db_json = self.db_file.read()
            self.crl_db = json.loads(self.crl_db_json)

        # Finally check if the give ID is in the CRL.
        if self.cert_id.lower() in self.crl_db:
            self.crl_result['revocation'] = self.crl_db[self.cert_id.lower()]
        else:
            self.crl_result['verified'] = True

        return self.crl_result
        
    
    def _is_ev_certificate(self, cert_dict):
        ev_result = {}
        policy = None
        try:
            policy = cert_dict['extensions']['X509v3 Certificate Policies']['Policy']
        except:
            pass

        if policy:
            for ev_name in EV_DB:
                ev_match = False
                ev_result[ev_name] = ev_match
                tmp_ev_db = EV_DB[ev_name]
                for db in tmp_ev_db:
                    tmp_db = tmp_ev_db[db]
                    if policy[0] == tmp_db['oid']:
                        if self._shared_settings['verbosity'] > 1:
                            print "Matched OID: %s" % tmp_db['oid']
                            print "Fingerprint: %s" % tmp_db['fingerprint']
                            print "Info: %s" % tmp_db['info']
                            print
                        ev_match = True
                ev_result[ev_name] = ev_match
        else:
            ev_result['NO_POLICY'] = True

        return ev_result
        
    
    def _get_basic_text(self, cert,  cert_dict):      
        basic_txt = [ \
        self.FIELD_FORMAT.format("Common Name:", cert_dict['subject']['commonName'][0] ),
        self.FIELD_FORMAT.format("Issuer:", cert.get_issuer_name().get_as_text()),
        self.FIELD_FORMAT.format("Serial Number:", cert_dict['serialNumber']),
        self.FIELD_FORMAT.format("Not Before:", cert_dict['validity']['notBefore']),
        self.FIELD_FORMAT.format("Not After:", cert_dict['validity']['notAfter']),
        self.FIELD_FORMAT.format("Signature Algorithm:", cert_dict['signatureAlgorithm']),
        self.FIELD_FORMAT.format("Key Size:", cert_dict['subjectPublicKeyInfo']['publicKeySize'])]
        
        try:
            alt_name = cert.get_extension_list().get_extension('X509v3 Subject Alternative Name')
            basic_txt.append (self.FIELD_FORMAT.format('X509v3 Subject Alternative Name:', alt_name))
        except KeyError:
            pass
        
        return basic_txt


    def _get_fingerprint(self, cert):
        nb = cert.get_fingerprint()
        val_txt = self.FIELD_FORMAT.format('SHA1 Fingerprint:', nb)
        val_xml = Element('fingerprint', algorithm='sha1')
        val_xml.text = nb
        return ([val_txt], [val_xml])    


    def _get_cert(self, target):
        """
        Connects to the target server and returns the server's certificate
        Also performs verification against Trust Stores. One SSL context
        for each Trust Store.
        """
        verify_result = {}
        for ca_file in ca_files_to_load:
            ca_name = (ca_file.split('/')[-1]).split('.')[0]
            ssl_ctx = SSL_CTX.SSL_CTX('tlsv1') # sslv23 hello will fail for specific servers such as post.craigslist.org
            ssl_ctx.load_verify_locations(ca_file)
            
            ssl_ctx.set_verify(constants.SSL_VERIFY_NONE) # We'll use get_verify_result()
            ssl_connect = SSLyzeSSLConnection(self._shared_settings, target,ssl_ctx,
                                          hello_workaround=True)

            if self._shared_settings['verbosity'] > 2:
                print "Shared settings:"
                print self._shared_settings

            try: # Perform the SSL handshake
                ssl_connect.connect()
                cert = ssl_connect._ssl.get_peer_certificate()
                tmp_verify_result = ssl_connect._ssl.get_verify_result()
            
            except ClientCertificateError: # The server asked for a client cert
                # We can get the server cert anyway
                cert = ssl_connect._ssl.get_peer_certificate()
                tmp_verify_result = ssl_connect._ssl.get_verify_result()            
            
            finally:
                ssl_connect.close()

            verify_result[ca_name] = X509_V_CODES.X509_V_CODES[tmp_verify_result]

        return (cert, verify_result)


def _dnsname_to_pat(dn):
    """
    Generates a regexp for the given name, to be used for hostname validation
    Taken from http://pypi.python.org/pypi/backports.ssl_match_hostname/3.2a3
    """
    pats = []
    for frag in dn.split(r'.'):
        if frag == '*':
            # When '*' is a fragment by itself, it matches a non-empty dotless
            # fragment.
            pats.append('[^.]+')
        else:
            # Otherwise, '*' matches any dotless fragment.
            frag = re.escape(frag)
            pats.append(frag.replace(r'\*', '[^.]*'))
    return re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)

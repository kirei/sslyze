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
import hashlib
import json
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, constants, \
    X509_V_CODES, SSL_CTX
from utils.SSLyzeSSLConnection import SSLyzeSSLConnection, ClientCertificateError
from utils.CertParser import X509CertificateHelper, _dnsname_to_pat
from utils.ExternalCommand import ExternalCommand

# Defines for CRL parsing using OpenSSL crl command.
OPENSSL = "openssl"
OPENSSL_CLR_CMD = " crl -noout -text -inform DER -in "
CRL_CACHE_DIR = os.path.join(os.path.dirname(PluginBase.__file__), 'crl')
OCSP_CACHE_DIR = os.path.join(os.path.dirname(PluginBase.__file__), 'ocsp')
CHECK_OCSP_PATH = os.path.join(os.path.dirname(PluginBase.__file__), '../utils/scripts')


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
    
    interface.add_option(
        option="ocsp",
        help= "Verify the certificate against the OCSP responder the "
              "certificate points to.",
        dest=None)

    FIELD_FORMAT = '      {0:<35}{1:<35}'
    
    def process_task(self, target, command, arg):
        if self._shared_settings['verbosity'] > 2:
            print "Processing %s" % target[0]

        (host, ip, port) = target
            
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

        # Perform OCSP checking if the option has been selected.
        if self._shared_settings['ocsp']:
            self.ocsp_result = self._check_ocsp(cert_dict)            
        
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
            if self.crl_result['NO_CRL']:
                crl_result_text = "No CRL URI in certificate"
            elif self.crl_result['verified']:
                crl_result_text = "Certificate not revoked in CRL"
            elif 'uri_error' in self.crl_result:
                crl_result_text = "Problem loading CRL. " + self.crl_result['uri_error']
            else:
                crl_result_text = "Cerificate revoked in CRL at %s. %s" % \
                                  (self.crl_result['revocation'][0], self.crl_result['revocation'][1])
            txt_result.append(self.FIELD_FORMAT.format("CRL verification:", crl_result_text))


        # Text result for SNI.
        if self._shared_settings['sni']:
            if self._shared_settings['sni'] == 'auto':
                sni_text = 'SNI enabled with virtual domain ' + host
            else:
                sni_text = 'SNI enabled with virtual domain ' + self._shared_settings['sni']
            txt_result.append(self.FIELD_FORMAT.format("SNI:", sni_text))

        if is_cert_trusted:
            txt_result.append(self.FIELD_FORMAT.format("Trusted or NOT Trusted:", "Trusted"))
        else:
            txt_result.append(self.FIELD_FORMAT.format("Trusted or NOT Trusted:", "NOT Trusted"))


        if self._shared_settings['ocsp']:
            if not self.ocsp_result['OCSP_PRESENT']:
                ocsp_result_text = "No OCSP Responder in certificate"
            else:
                if self.ocsp_result['verified']:
                    ocsp_result_text = "Certificate not revoked"

                elif self.ocsp_result['revoked']:
                    ocsp_result_text = "Cerificate revoked. "

                elif self.ocsp_result['error']:
                    ocsp_result_text = "Error querying OCSP responder. "
                    
                elif 'uri_error' in self.ocsp_result:
                    ocsp_result_text = "Problem loading OCSP Issuer CA. " + self.ocsp_result['uri_error']
                else:
                    ocsp_result_text = "Unknown problem performing OCSP verification. "
            txt_result.append(self.FIELD_FORMAT.format("OCSP verification:", ocsp_result_text))

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
            if self._shared_settings['sni'] == 'auto':
                trust_xml_attr['sni'] = host
            else:
                trust_xml_attr['sni'] = self._shared_settings['sni']

        if self._shared_settings['crl']:
            if self.crl_result['NO_CRL']:
                trust_xml_attr['crl'] = "no crl extension"
            elif 'uri_error' in self.crl_result:
                trust_xml_attr['crl'] = self.crl_result['uri_error']
            elif self.crl_result['verified']:
                trust_xml_attr['crl'] = "verified"
            else:
                trust_xml_attr['crl'] = "revoked"

        if self._shared_settings['ocsp']:
            if self.ocsp_result['revoked']:
                trust_xml_attr['ocsp'] = "certificate revoked"
            elif self.ocsp_result['error']:
                trust_xml_attr['ocsp'] = "error querying responder"
            elif self.ocsp_result['verified']:
                trust_xml_attr['ocsp'] = "verified"
            elif 'uri_error' in self.ocsp_result:
                trust_xml_attr['ocsp'] = self.ocsp_result['uri_error']
            elif not self.ocsp_result['OCSP_PRESENT']:
                trust_xml_attr['ocsp'] = "no ocsp in cert"
            else:
                trust_xml_attr['ocsp'] = "Unhandled problem with ocsp"
            
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


# FORMATTING FUNCTIONS
    def _is_hostname_valid(self, cert_dict, target):
        (host, ip, port) = target
        commonName = cert_dict['subject']['commonName'][0]
        
        # Check SNI first
        if self._shared_settings['sni']:
            if self._shared_settings['sni'] == 'auto':
                self.sni_name = host
            else:
                self.sni_name = self._shared_settings['sni']

            if self._shared_settings['verbosity'] > 1:
                print "SNI debug"
                print "---------"
                print "host: %s" % host
                print "SNI name given: %s" % self.sni_name
                print ""
                
            if _dnsname_to_pat(commonName).match(self.sni_name):
                return 'SNI CN ' + self.sni_name
            else:
                # Check if any AltName matces SNI.
                try:
                    alt_names = cert_dict['extensions']['X509v3 Subject Alternative Name']['DNS']
                except KeyError:
                    return False
        
                for altname in alt_names:
                    if _dnsname_to_pat(altname).match(self.sni_name):
                        return 'SNI SAN ' + altname
                return False

        else:
            # Not SNI - Let's try the common name first
            if _dnsname_to_pat(commonName).match(host):
                return 'Common Name ' + commonName
            else:
                try:
                    alt_names = cert_dict['extensions']['X509v3 Subject Alternative Name']['DNS']
                except KeyError:
                    return False
                
                for altname in alt_names:
                    if _dnsname_to_pat(altname).match(host):
                        return 'Subject Alternative Name ' + altname       
                return False


    def _check_crl(self, cert):
        self.crl_result = {}
        self.crl_result['verified'] = False
        self.crl_result['NO_CRL'] = False
        self.crl_uri = None
        try:
            self.crl_uri = cert['extensions']['X509v3 CRL Distribution Points']['URI'][0]
        except:
            self.crl_result['NO_CRL'] = True
            return self.crl_result

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
            self.my_cmd = ExternalCommand(self.openssl_command)
            (self.status, self.crl_text_data, self.error) = self.my_cmd.run(timeout=25)

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

        
    def _check_ocsp(self, cert):
        self.ocsp_result = {}
        self.ocsp_result['OCSP_PRESENT'] = False
        self.ocsp_result['verified'] = False
        self.ocsp_result['error'] = False
        self.ocsp_result['revoked'] = False
        try:
            self.ocsp_responder = cert['extensions']['Authority Information Access']['OCSP']['URI'][0]
        except:
            self.ocsp_result['error'] = True
            return self.ocsp_result
            
        self.ocsp_result['OCSP_PRESENT'] = True

        try:
            self.ca_issuer = cert['extensions']['Authority Information Access']['CAIssuers']['URI'][0]
        except:
            self.ocsp_result['uri_error'] = "No CAIssuers field in certificate."
            return self.ocsp_result
            
        self.cert_id = cert['serialNumber']
        self.ocsp_filename_hash_prefix = hashlib.sha1(self.ca_issuer).hexdigest()
        self.ocsp_crt_filename = self.ocsp_filename_hash_prefix + ".crt"
        self.ocsp_pem_filename = self.ocsp_filename_hash_prefix + ".pem"
        self.ocsp_err_filename = self.ocsp_filename_hash_prefix + ".err"
        self.all_ocsp_files = os.listdir(OCSP_CACHE_DIR)

        if self.ocsp_err_filename in self.all_ocsp_files:
            with open(OCSP_CACHE_DIR + '/' + self.ocsp_err_filename, 'rb') as self.ocsp_err_file:
                self.ocsp_result['uri_error'] = self.ocsp_err_file.read()
                return self.ocsp_result

        elif self.ocsp_pem_filename not in self.all_ocsp_files:
            # Create PEM file in OCSP cache.
            self.ocsp_der_data = None
            self.ocsp_target_handler = None
            self.ocsp_e = None
            try:
                self.ocsp_target_handler = urllib2.urlopen(self.ca_issuer)
                self.ocsp_der_data = self.ocsp_target_handler.read()
                self.ocsp_target_handler.close()
            except urllib2.URLError, self.ocsp_e:
                with open(OCSP_CACHE_DIR + '/' + self.ocsp_err_filename, 'wb') as self.ocsp_err_file:
                    self.ocsp_err_file.write(str(self.ocsp_e.code) + ' ' + self.ocsp_e.reason)
                self.ocsp_result['uri_error'] = str(self.ocsp_e.code) + ' ' + self.ocsp_e.reason
                return self.ocsp_result

            with open(OCSP_CACHE_DIR + '/' + self.ocsp_crt_filename, 'wb') as self.ocsp_crt_file:
                self.ocsp_crt_file.write(self.ocsp_der_data)

            self.openssl_der_pem_cmd = OPENSSL + " x509" + " -inform DER" + " -in " + \
                                       OCSP_CACHE_DIR + "/" + self.ocsp_crt_filename +\
                                       " -outform PEM" + " -out " +\
                                       OCSP_CACHE_DIR + "/" + self.ocsp_pem_filename
            self.my_cmd = ExternalCommand(self.openssl_der_pem_cmd)
            (self.status, self.data, self.error) = self.my_cmd.run(timeout=25)

        # PEM file present. We can now proceed to validate the cert
        # against the OCSP responder.
        self.check_ocsp_cmd = CHECK_OCSP_PATH + "/check-ocsp.sh " + self.ocsp_responder +\
                              " " + OCSP_CACHE_DIR + "/" + self.ocsp_pem_filename +\
                                       " " + self.cert_id

        self.my_cmd = ExternalCommand(self.check_ocsp_cmd)
        (self.status, self.ocsp_response_data, self.error) = self.my_cmd.run(timeout=25)

        self.ocsp_result['response'] = self.ocsp_response_data.split('\n')
        if "good" in self.ocsp_response_data:
            self.ocsp_result['verified'] = True
        elif "revoked" in self.ocsp_response_data:
            self.ocsp_result['revoked'] = True
        elif "Error" in self.ocsp_response_data or self.status != 0:
            self.ocsp_result['error'] = True
            
        return self.ocsp_result
    

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
            ssl_connect = SSLyzeSSLConnection(self._shared_settings, target, ssl_ctx,
                                              hello_workaround=True)

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


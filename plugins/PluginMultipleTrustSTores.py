#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginMultipleTrustStores.py
# Purpose:      Verifies the target server's certificate validity against
#               several trust stores.
#               certificate. Based on the PluginCertInfo plugin.
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
from xml.etree.ElementTree import Element
from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, constants, \
    X509_V_CODES, SSL_CTX
from utils.SSLyzeSSLConnection import SSLyzeSSLConnection, ClientCertificateError
from utils.CertParser import X509CertificateHelper, _dnsname_to_pat


# Import Trust Stores during module init.
load_data_path = os.path.join(os.path.dirname(PluginBase.__file__) , 'data')
all_data_files = os.listdir(load_data_path)
ca_files_to_load = []
for filename in all_data_files:
    if ".pem" in filename:
        ca_files_to_load.append(os.path.join(load_data_path, filename))
        

class PluginMultipleTrustStores(PluginBase.PluginBase):
    interface = PluginBase.PluginInterface(title="PluginMultipleTrustStores", description=(''))
    interface.add_command(
        command="truststores",
        help= "Verifies the target server's certificate validity against "
            "a number of trust stores such as Mozilla's trusted root store.",
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
            
        fingerprint = cert.get_fingerprint()
        cmd_title = 'Trust Stores'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]

        for ca_name in verify_result:
            if verify_result[ca_name] == 'ok':
                txt_result.append(self.FIELD_FORMAT.format("Validated by Trust Store: ", ca_name))
            else:
                txt_result.append(self.FIELD_FORMAT.format("Not validated by Trust Store: ",
                                                           ca_name + ' - ' + verify_result[ca_name]))

        # XML output.
        xml_result = Element(command, argument = arg, title = cmd_title)
        trust_xml_attr = {'isTrustedByAllCAStores' : str(is_cert_trusted)}
            
        trust_xml = Element('trust_stores', attrib = trust_xml_attr)
        
        for elem_xml in cert_parsed.parse_certificate_to_xml():
            trust_xml.append(elem_xml)
        xml_result.append(trust_xml)
        
        ctSSL_cleanup()
        return PluginBase.PluginResult(txt_result, xml_result)


    def _get_cert(self, target):
        """
        Connects to the target server and returns the server's certificate
        Also performs verification against Trust Stores. One SSL context
        for each Trust Store.
        """
        verify_result = {}
        for ca_file in ca_files_to_load:
            ca_name = (ca_file.split('/')[-1]).split('.')[0]
            # sslv23 hello will fail for specific servers such as post.craigslist.org
            ssl_ctx = SSL_CTX.SSL_CTX('tlsv1')
            ssl_ctx.load_verify_locations(ca_file)
            
            ssl_ctx.set_verify(constants.SSL_VERIFY_NONE)
            ssl_connect = SSLyzeSSLConnection(self._shared_settings, target,ssl_ctx,
                                          hello_workaround=True)

            if self._shared_settings['verbosity'] > 2:
                print "Shared settings:"
                print self._shared_settings

            try:
                # Perform the SSL handshake
                ssl_connect.connect()
                cert = ssl_connect._ssl.get_peer_certificate()
                tmp_verify_result = ssl_connect._ssl.get_verify_result()
            
            except ClientCertificateError:
                # The server asked for a client cert
                # We can get the server cert anyway
                cert = ssl_connect._ssl.get_peer_certificate()
                tmp_verify_result = ssl_connect._ssl.get_verify_result()            
            
            finally:
                ssl_connect.close()

            verify_result[ca_name] = X509_V_CODES.X509_V_CODES[tmp_verify_result]

        return (cert, verify_result)

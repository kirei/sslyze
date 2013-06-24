#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:         PluginHTTPvsHTTPS.py
# Purpose:      Compare the content received from the server over
#               HTTP vs HTTPS.
#
#               Currently the checking is expected to be done separately using
#               https-everywhere-checker.
#               https://github.com/hiviah/https-everywhere-checker
#
#               This Plugin simply checks that it can connect to the server
#               via HTTP and HTTPS. If that is possible, the plugin generates
#               a customized rule for the server.
#
# Author:       joachims
#
# Copyright:    2013 SSLyze developers
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

from xml.etree.ElementTree import Element
import httplib
from plugins import PluginBase


class PluginHTTPvsHTTPS(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginHTTPvsHTTPS", description=(''))
    interface.add_command(
        command="httpvshttps",
        help="Generate rules to https everywhere checker to compare the content "
             "provided by the server via HTTP vs HTTPS.",
        dest=None)

    def process_task(self, target, command, args):

        output_format = '        {0:<25} {1}'

        hsts_supported = False
        hsts_timeout = ""
        (host, addr, port) = target
        connection = httplib.HTTPSConnection(host)
        try:
            connection.connect()
            connection.request("HEAD", "/", headers={"Connection": "close"})
            response = connection.getresponse()
            headers = response.getheaders()
            for (field, data) in headers:
                if field == 'strict-transport-security':
                    hsts_supported = True
                    hsts_timeout = data

        except httplib.HTTPException as ex:
            print "Error: %s" % ex

        finally:
            connection.close()

        # Text output
        cmd_title = 'HTTPvsHTTPS'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        if hsts_supported:
            txt_result.append(output_format.format("Supported:", hsts_timeout))
        else:
            txt_result.append(output_format.format("Not supported.", ""))

        # XML output
        xml_hsts_attr = {'hsts_header_found': str(hsts_supported)}
        if hsts_supported:
            xml_hsts_attr['hsts_header'] = hsts_timeout
        xml_hsts = Element('hsts', attrib = xml_hsts_attr)

        xml_result = Element(self.__class__.__name__, command = command,
                             title = cmd_title)
        xml_result.append(xml_hsts)

        return PluginBase.PluginResult(txt_result, xml_result)


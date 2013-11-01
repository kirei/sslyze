#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:         PluginHSTS.py
# Purpose:      Checks if the server supports RFC 6797 HTTP Strict Transport
#               Security by checking if the server responds with the
#               Strict-Transport-Security field in the header.
#
#               Note: There is currently no support for hsts pinning.
#
#               This plugin is based on the plugin written by Tom Samstag
#               (tecknicaltom) and reworked, integrated and adapted to the
#               new sslyze plugin API by Joachim Strömbergson.
#
# Author:       tecknicaltom, joachims
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

import os
from xml.etree.ElementTree import Element
import httplib
from plugins import PluginBase
from utils.ExternalCommand import ExternalCommand


class PluginHSTS(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginHSTS", description=(''))
    interface.add_command(
        command="hsts",
        help="Verifies the support of a server for HTTP Strict Transport Security "
             "(HSTS) by collecting any Strict-Transport-Security field present in "
             "the response from the server.",
        dest=None)

    def process_task(self, target, command, args):

        output_format = '        {0:<25} {1}'

        hsts_supported = False
        hsts_timeout = ""
        (host, addr, port) = target

        # Create Curl command to get header from host.
        curl_command = 'curl -I ' + 'https://' + host
        my_cmd = ExternalCommand(curl_command)
        (status, data, error) = my_cmd.run(timeout=25)

        if self._shared_settings['verbosity'] > 1:
            print "Result from Curl HSTS header command:"
            print "status: %s" % status
            print "data:"
            print data
            print

        # Parse the header data for HSTS parameter.
        for row in data.splitlines():
            if 'strict-transport-security' in row.lower():
                hsts_supported = True
                if 'max-age' in row.lower():
                    hsts_timeout = row.lower().split(':')[1]

        # Text output
        cmd_title = 'HSTS'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        if status != 0:
            txt_result.append(output_format.format("Timeout while querying server:", ""))
        elif hsts_supported:
            txt_result.append(output_format.format("Supported:", hsts_timeout))
        else:
            txt_result.append(output_format.format("Not supported.", ""))

        # XML output
        if status != 0:
            xml_hsts_attr = {'hsts_error': str(True)}
        else:
            xml_hsts_attr = {'hsts_header_found': str(hsts_supported)}
        if hsts_supported:
            xml_hsts_attr['hsts_header'] = hsts_timeout
        xml_hsts = Element('hsts', attrib = xml_hsts_attr)

        xml_result = Element(self.__class__.__name__, command = command,
                             title = cmd_title)
        xml_result.append(xml_hsts)

        return PluginBase.PluginResult(txt_result, xml_result)


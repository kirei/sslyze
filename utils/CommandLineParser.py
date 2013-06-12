#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         CommandLineParser.py
# Purpose:      Command line parsing utilities for SSLyze.
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

from optparse import OptionParser, OptionGroup
import platform

from ServersConnectivityTester import SSLServerTester, InvalidTargetError


class CommandLineParsingError(Exception):
    
    PARSING_ERROR_FORMAT = '  Command line error: {0}\n  Use -h for help.'
    
    def get_error_msg(self):
        return self.PARSING_ERROR_FORMAT.format(self)


class CommandLineParser():
    
    # Defines what --regular means
    REGULAR_CMD = ['sslv2', 'sslv3', 'tlsv1', 'reneg', 'resum', 'certinfo', 
                      'http_get', 'hide_rejected_ciphers', 'compression', 
                      'tlsv1_1', 'tlsv1_2']
    SSLYZE_USAGE = 'usage: %prog [options] target1.com target2.com:443 etc...'
    
    
    def __init__(self, available_plugins, sslyze_version, timeout):
        """
        Generates SSLyze's command line parser.
        """

        self._parser = OptionParser(version=sslyze_version,
                                    usage=self.SSLYZE_USAGE)
    
        # Add generic command line options to the parser
        self._add_default_options(timeout)
    
        # Add plugin-specific options to the parser
        self._add_plugin_options(available_plugins)
    
        # Add the --regular command line parameter as a shortcut if possible
        regular_help = 'Regular HTTPS scan; shortcut for'
        for cmd in self.REGULAR_CMD:
            regular_help += ' --' + cmd
            if (self._parser.has_option('--' + cmd) == False):
                return
        
        self._parser.add_option('--regular', action="store_true", dest=None,
                    help=regular_help)
                
        
    def parse_command_line(self):
        """
        Parses the command line used to launch SSLyze.
        """
    
        (args_command_list, args_target_list) = self._parser.parse_args()
    
        # Handle the --targets_in command line and fill args_target_list
        if args_command_list.targets_in:
            if args_target_list:
                raise CommandLineParsingError("Cannot use --targets_list and specify targets within the command line.")
                
            try: # Read targets from a file
                with open(args_command_list.targets_in) as f:
                    for target in f.readlines():
                        if target.strip(): # Ignore empty lines
                            if not target.startswith('#'): # Ignore comment lines
                                args_target_list.append(target.strip())
            except IOError:
                raise CommandLineParsingError("Can't read targets from input file '%s'." %  args_command_list.targets_in)
    
        if args_target_list == []:
            raise CommandLineParsingError('No targets to scan.')
    
        # Handle the --regular command line parameter as a shortcut
        if self._parser.has_option('--regular'):
            if getattr(args_command_list, 'regular'):
                setattr(args_command_list, 'regular', False)
                for cmd in self.REGULAR_CMD:
                    setattr(args_command_list, cmd, True)
                setattr(args_command_list, 'certinfo', 'basic') # Special case
                
        # Create the shared_settings object from looking at the command line
        shared_settings = self._process_parsing_results(args_command_list)
        
        return (args_command_list, args_target_list, shared_settings)


    def _add_default_options(self, timeout):
        """
        Adds default command line options to the parser.
        """
        
        # Client certificate options
        clientcert_group = OptionGroup(self._parser, 
            'Client certificate support', '')
        clientcert_group.add_option(
            '--cert',
            help='Client certificate filename.',
            dest='cert')
        clientcert_group.add_option(
            '--certform',
            help= 'Client certificate format. DER or PEM (default).',
            dest='certform',
            default='PEM')
        clientcert_group.add_option(
            '--key',
            help= 'Client private key filename.',
            dest='key')
        clientcert_group.add_option(
            '--keyform',
            help= 'Client private key format. DER or PEM (default).',
            dest='keyform',
            default='PEM')
        clientcert_group.add_option(
            '--pass',
            help= 'Client private key passphrase.',
            dest='keypass')
        self._parser.add_option_group(clientcert_group)
    
        # XML output
        self._parser.add_option(
            '--xml_out',
            help= ('Writes the scan results as an XML document to the file XML_FILE.'),
            dest='xml_file',
            default=None)
    
        # Read targets from input file
        self._parser.add_option(
            '--targets_in',
            help= ('Reads the list of targets to scan from the file TARGETS_IN. It should contain one host:port per line.'),
            dest='targets_in',
            default=None)
    
        # Timeout
        self._parser.add_option(
            '--timeout',
            help= (
                'Sets the timeout value in seconds used for every socket '
                'connection made to the target server(s). Default is 5s.'),
            type='int',
            dest='timeout',
            default=timeout)

    
        # Verbosity
        self._parser.add_option(
            '--verbosity',
            help= (
                'Increases the verbosity of the program.'
                'Usable values in the range 0..3. Default is 0.'),
            type='int',
            dest='verbosity',
            default=0)
    
        
        # HTTP CONNECT Proxy
        self._parser.add_option(
            '--https_tunnel',
            help= (
                'Sets an HTTP CONNECT proxy to tunnel SSL traffic to the target '
                'server(s). HTTP_TUNNEL should be \'host:port\'. ' 
                'Requires Python 2.7'),
            dest='https_tunnel',
            default=None)
        
        # STARTTLS
        self._parser.add_option(
            '--starttls',
            help= (
                'Identifies the target server(s) as a SMTP or an XMPP server(s) '
                'and scans the server(s) using STARTTLS. '
                'STARTTLS should be \'smtp\' or \'xmpp\'.'),
            dest='starttls',
            default=None)
    
        self._parser.add_option(
            '--xmpp_to',
            help= (
                'Optional setting for STARTTLS XMPP. '
                ' XMPP_TO should be the hostname to be put in the \'to\' attribute '
                'of the XMPP stream. Default is the server\'s hostname.'),
            dest='xmpp_to',
            default=None)
        
        # Server Name Indication
        self._parser.add_option(
            '--sni',
            help= (
                'Use Server Name Indication to specify the hostname to connect to.'
                ' Will only affect TLS 1.0+ connections.'),
            dest='sni',
            default=None)

    def _add_plugin_options(self, available_plugins):
        """
        Recovers the list of command line options implemented by the available
        plugins and adds them to the command line parser.
        """
        
        for plugin_class in available_plugins:
            plugin_desc = plugin_class.get_interface()
    
            # Add the current plugin's commands to the parser
            group = OptionGroup(self._parser, plugin_desc.title,\
                                plugin_desc.description)
            for cmd in plugin_desc.get_commands():
                    group.add_option(cmd)

            # Add the current plugin's options to the parser
            for option in plugin_desc.get_options():
                    group.add_option(option)

            self._parser.add_option_group(group)


    def _process_parsing_results(self, args_command_list):
        """
        Performs various sanity checks on the command line that was used to 
        launch SSLyze.
        Returns the shared_settings object to be fed to plugins.
        """
        
        shared_settings = {}
        # Sanity checks on the client cert options
        if bool(args_command_list.cert) ^ bool(args_command_list.key):
            raise CommandLineParsingError('No private key or certificate file were given. See --cert and --key.')
        
        # Let's try to open the cert and key files
        if args_command_list.cert:
            try:
                open(args_command_list.cert,"r")
            except:
                raise CommandLineParsingError('Could not open the client certificate file "' + str(args_command_list.cert) + '".')

        if args_command_list.key:    
            try:
                open(args_command_list.key,"r")
            except:
                raise CommandLineParsingError('Could not open the client private key file "' + str(args_command_list.key) + '"')
    
        # Parse client cert options
        if args_command_list.certform not in ['DER', 'PEM']:
            raise CommandLineParsingError('--certform should be DER or PEM.')
    
        if args_command_list.keyform not in ['DER', 'PEM']:
            raise CommandLineParsingError('--keyform should be DER or PEM.')
    
            
        # HTTP CONNECT proxy
        if args_command_list.https_tunnel:
            if '2.7.' not in platform.python_version(): # Python 2.7 only
                raise CommandLineParsingError(
                    '--https_tunnel requires Python 2.7.X. '
                    'Current version is ' + platform.python_version() + '.')
                
            try: # Need to parse the proxy host:port string now
                proxy_test = SSLServerTester(args_command_list.https_tunnel)
                shared_settings['https_tunnel_host'] = proxy_test.get_target()[0]
                shared_settings['https_tunnel_port'] = proxy_test.get_target()[2]
            except InvalidTargetError:
                raise CommandLineParsingError(
                    'Not a valid host/port for --https_tunnel'
                    ', discarding all tasks.')
                
        else:
            shared_settings['https_tunnel_host'] = None
            shared_settings['https_tunnel_port'] = None
            
        # STARTTLS
        if args_command_list.starttls not in [None,'smtp','xmpp']:
            raise CommandLineParsingError(
                '--starttls should be \'smtp\' or \'xmpp\'.')
        
        if args_command_list.starttls and args_command_list.https_tunnel:
            raise CommandLineParsingError(
                'Cannot have --https_tunnel and --starttls at the same time.')   
        
        # All good, let's save the data    
        for key, value in args_command_list.__dict__.iteritems():
            shared_settings[key] = value
    
        return shared_settings


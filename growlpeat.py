#!/usr/bin/env python

"""growlpeat - Growl repeater. Listens for Growl notifications and re-broadcasts them to a list of Growl clients.

<http://github.com/joshdick/growlpeat>

+-------------+
| INFORMATION |
+-------------+

This script can be used in place of Growl's built-in "Forward notifications to other computers" feature to ensure
that a Growl notification can be consistently repeated to a group of computers running Growl clients, regardless of
the power/network state of any of the computers in the group. This is desirable over relying on any single computer
in the group to do forwarding.

growlpeat is known to work with Python 2.6.6 and later.

For more information about Growl, visit <http://growl.info>.

+-------+
| USAGE |
+-------+

growlpeat expects a configuration file, growlpeat.properties, to be present in the same directory as growlpeat.
Please make a copy of the included growlpeat.properties.dist file and name it growlpeat.properties.
Then, edit growlpeat.properties accordingly - the file contains explanations for each setting.

After that, simply execute growlpeat.py from the command line. growlpeat will start listening for Growl registration/
notification messages. If a received message uses the configured password, it will be re-broadcasted to each of the
configured Growl clients.

In order for growlpeat to function, you must configure your Growl-enabled applications to register to the computer
that growlpeat is running on, using the configured password. Whenever you add new Growl clients to growlpeat.properties
(including the initial time), you must re-register your Growl-enabled applications with growlpeat so that all of your
Growl clients become aware of the registration.

+----------------------+
| LICENSE / OTHER INFO |
+----------------------+

growlpeat is based on regrowl 0.6.2 by Rui Carmo <http://the.taoofmac.com>, which appears to no longer be maintained.
regrowl was released under a BSD license. Hence, growlpeat is as well.
regrowl's web site no longer exists, but Google's cached version is available here:
http://webcache.googleusercontent.com/search?q=cache:5XaGmCjdM90J:the.taoofmac.com/space/projects/ReGrowl+regrowl&cd=1&hl=en&ct=clnk&gl=us

---

Copyright 2010 Josh Dick
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
      of conditions and the following disclaimer in the documentation and/or other materials
      provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""

__version__ = '1.1'
__author__ = 'Josh Dick <joshdick.net>'
__email__ = 'josh@joshdick.net'
__copyright__ = '(C) 2010, Josh Dick'
__license__ = 'Simplified BSD'

from SocketServer import *
from socket import AF_INET, SOCK_DGRAM, socket
from hashlib import md5
import struct, time, sys

GROWL_UDP_PORT = 9887
GROWLPEAT_PASSWORD = None
GROWL_CLIENTS = []

class GrowlPacket:
  """Performs basic decoding of a Growl UDP packet"""

  def __init__(self, data, clientPassword = None):
    """Initializes and validates the packet"""
    self.valid = False
    self.data = data

    if self.type() != 'UNSUPPORTED':

      # The last 16 bytes of a supported Growl packet are an md5 checksum
      # of the rest of the packet data concatenated with the password.
      # Verfiy that the received packet has a checksum computed using growlpeat's password.
      uncheckedData = self.data[:-16]
      checksum = md5()
      checksum.update(uncheckedData) # A checksum of the packet data (without the original checksum),
      checksum.update(GROWLPEAT_PASSWORD) # Concatenated with growlpeat's internal password...
      if checksum.digest() == self.data[-16:]: # ...Should match the original checksum.
        self.valid = True # This packet is now known to be a valid Growl packet that was specifically sent to growlpeat
        if clientPassword == None: return # Don't bother recomputing a checksum if no Growl client password was specified
        #TODO: If no password was specified, rewrite the packet to use corresponding Growl NOAUTH types?
        # Now, rewrite the packet with a checksum that uses the password that the destination Growl client is expecting.
        checksum = md5()
        checksum.update(uncheckedData)
        checksum.update(clientPassword)
        self.data = self.data[:-16] + checksum.digest()

  def type(self):
    """Returns the packet type"""
    typeByte = self.data[1]
    if typeByte == '\x00':
      return 'REGISTER'
    elif typeByte == '\x01':
      return 'NOTIFY'
    else:
      return 'UNSUPPORTED'

  def info(self):
    """Returns a subset of packet information"""
    if self.type() == 'NOTIFY':
      nlen = struct.unpack("!H",str(self.data[4:6]))[0]
      tlen = struct.unpack("!H",str(self.data[6:8]))[0]
      dlen = struct.unpack("!H",str(self.data[8:10]))[0]
      alen = struct.unpack("!H",str(self.data[10:12]))[0]
      return struct.unpack(("%ds%ds%ds%ds") % (nlen, tlen, dlen, alen), self.data[12:len(self.data)-16])
    else:
      length = struct.unpack("!H",str(self.data[2:4]))[0]
      return self.data[6:7+length]


class GrowlRelay(UDPServer):
  """Growl notification relay"""
  allow_reuse_address = True

  def __init__(self):
    """Initializes the relay"""
    UDPServer.__init__(self,('localhost', GROWL_UDP_PORT), _RequestHandler)


class _RequestHandler(DatagramRequestHandler):
  """Processes and logs each incoming notification packet"""

  # Borrowed from BaseHTTPServer for logging
  monthname = [None, 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                     'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

  def log_date_time_string(self):
     """Returns the current time formatted for logging"""
     now = time.time()
     year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
     s = "%02d/%3s/%04d %02d:%02d:%02d" % (
        day, self.monthname[month], year, hh, mm, ss)
     return s

  def handle(self):
    """Handles each request"""
    receivedPacket = GrowlPacket(self.rfile.read())
    outcome = 'DISCARDED'
    if receivedPacket.valid:
        outcome = 'REPEATED'
        for (host, clientPassword) in GROWL_CLIENTS:
            clientPacket = GrowlPacket(receivedPacket.data, clientPassword)
            s = socket(AF_INET, SOCK_DGRAM)
            s.sendto(clientPacket.data, (host, GROWL_UDP_PORT))
            s.close()

    # Log the request and outcome
    print "%s - - [%s] %s %s %d %s" % (self.client_address[0],
      self.log_date_time_string(), receivedPacket.type(), receivedPacket.info(), len(receivedPacket.data), outcome)


class GrowlpeatConfig:
  """Reads, validates and stores growlpeat configuration information"""

  def __init__(self, filename):
    self.config_filename = filename

  def read(self):
    """Attempts to read growlpeat configuration information from a simple property file"""
    try:
      configFile = open(self.config_filename, 'rU')
      for line in configFile:
        if not line.startswith('#') and line.count('=') > 0:
           configProperty = line.split('=', 1) # Split around the first equals sign, preserve others.
           # Allow for whitespace around the equals sign.
           configProperty[0] = configProperty[0].strip()
           configProperty[1] = configProperty[1].strip()
           if configProperty[0] == 'growlpeat.client':
             clientInfo = configProperty[1]
             if clientInfo.count(':') > 0:
               client = clientInfo.split(':', 1) # Split around the first colon, preserve others.
               host = client[0]
               if host != '': # A blank host is invalid.
                 # Try connecting to the client to see if it's valid. If so, add it to the global clients list.
                 try:
                   s = socket(AF_INET, SOCK_DGRAM)
                   s.connect((host, GROWL_UDP_PORT))
                   s.close()
                   global GROWL_CLIENTS
                   GROWL_CLIENTS.append(client)
                 except:
                   print 'WARNING: Ignoring properly configured Growl client [{0}]: its hostname can not be resolved.'.format(host)
           elif configProperty[0] == 'growlpeat.password':
             global GROWLPEAT_PASSWORD
             GROWLPEAT_PASSWORD = configProperty[1]
      configFile.close()
    except IOError as (errno, strerror):
      print 'Error reading growlpeat configuration file {0}: [I/O error({1}): {2}]'.format(self.config_filename, errno, strerror)
      sys.exit(1)

  def validate(self):
    """Validates this growlpeat configuraion and terminates growlpeat if the configuration is invalid"""
    if GROWLPEAT_PASSWORD == None:
      print 'growlpeat configuration file {0} is missing the growlpeat.password property.'.format(self.config_filename)
      print 'Please add a line to {0} with the following format:'.format(self.config_filename)
      print 'growlpeat.password = your_password_here'
      sys.exit(1)

    numClients = len(GROWL_CLIENTS)

    if numClients == 0:
      print 'growlpeat configuration file {0} contains no valid growl clients.'.format(self.config_filename)
      print 'Please add at least one line to {0} with the following format:'.format(self.config_filename)
      print 'growlpeat.client = growl_client_address:growl_client_password'
      sys.exit(1)

    suffix ='s.' if numClients > 1 else '.'
    print 'Read configuration file {0} - found {1} Growl client{2}'.format(self.config_filename, numClients, suffix)


if __name__ == '__main__':

  config = GrowlpeatConfig('growlpeat.properties')
  config.read() # Read in the configuration from the property file.
  config.validate() # Make sure the configuration is valid before proceeding.

  relay = GrowlRelay()

  try:
    relay.serve_forever()
  except KeyboardInterrupt:
    print "\nCaught keyboard interrupt...bailing out."

#!/usr/bin/env python

"""growlpeat - Growl repeater. Listens for Growl notifications and re-broadcasts them to a list of Growl clients.

This script can be used in place of Growl's built-in "Forward notifications to other computers" so that a Growl
message can be consistently repeated to a group of computers regardless of the power/network state of any of the
computers in the group. This is desirable over relying on any single computer in the group to do forwarding.

See the "*** CONFIGURATION ***" section to learn how to configure and use growlpeat.

For more information about Growl, visit <http://growl.info>.

growlpeat is based on regrowl 0.6.2 by Rui Carmo <http://the.taoofmac.com>, which appears to no longer be maintained.
regrowl was released under a BSD license. Hence, growlpeat is as well.
regrowl's web site no longer exists, but Google's cached version is available here:
http://webcache.googleusercontent.com/search?q=cache:5XaGmCjdM90J:the.taoofmac.com/space/projects/ReGrowl+regrowl&cd=1&hl=en&ct=clnk&gl=us
"""
__version__ = '1.0'
__author__ = 'Josh Dick <joshdick.net>'
__email__ = 'josh@joshdick.net'
__copyright__ = '(C) 2010, Josh Dick'
__license__ = 'BSD'

from SocketServer import *
from socket import AF_INET, SOCK_DGRAM, socket
import struct, time, pprint, hashlib

# *** CONFIGURATION ***
# Growl-enabled programs should be configured to send Growl messages to the
# machine that growlpeat runs on, using the password stored in GROWLPEAT_PASSWORD.
# Growl registrations directed at growlpeat will be correctly rewritten and repeated to all Growl clients,
# so whenever you update the GROWL_CLIENTS list, simply re-register your growl-enabled program to growlpeat
# to update growlpeat's registration on each Growl client.
#TODO: Factor this configuration out to an external file?
GROWL_UDP_PORT = 9887
# The list of Growl clients to repeat to. Format: [('192.168.1.101', 'password'), ('12.34.56.78', 'other_password')] etc etc
GROWL_CLIENTS = [('192.168.1.5', 's3gf4u1t'), ('192.168.1.134', 's3gf4u1t')]
# The password that Growl-enabled programs should send to growlpeat
GROWLPEAT_PASSWORD = 'password'

class GrowlPacket:
  """Performs basic decoding of a Growl UDP packet"""

  def __init__(self, data, password = None):
    """Initializes and validates the packet"""
    self.valid = False
    self.data = data

    if self.type() != 'UNSUPPORTED':

      # The last 16 bytes of a supported Growl packet are an md5 checksum
      # of the rest of the packet data concatenated with the password.
      # Verfiy that the received packet has a checksum computed using GROWLPEAT_PASSWORD.
      uncheckedData = self.data[:-16]
      checksum = hashlib.md5()
      checksum.update(uncheckedData) # A checksum of the packet data (without the original checksum),
      checksum.update(GROWLPEAT_PASSWORD) # Concatenated with growlpeat's internal password...
      if checksum.digest() == self.data[-16:]: # ...Should match the original checksum.
        self.valid = True # This packet is now known to be a valid Growl packet that was specifically sent to growlpeat
        if password == None: return # Don't bother recomputing a checksum if no password was specified
        #TODO: If no password was specified, rewrite the packet to use corresponding Growl NOAUTH types?
        # Now, rewrite the packet with a checksum that uses the password that the destination Growl client is expecting.
        checksum = hashlib.md5()
        checksum.update(uncheckedData)
        checksum.update(password)
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
    p = GrowlPacket(self.rfile.read())
    outcome = 'DISCARDED'
    if p.valid:
        outcome = 'REPEATED'
        for (host, password) in GROWL_CLIENTS:
            p = GrowlPacket(p.data, password)
            s = socket(AF_INET, SOCK_DGRAM)
            s.sendto(p.data, (host, GROWL_UDP_PORT))
            s.close()

    # Log the request and outcome
    print "%s - - [%s] %s %s %d %s" % (self.client_address[0],
      self.log_date_time_string(), p.type(), p.info(), len(p.data), outcome)


if __name__ == '__main__':
  r = GrowlRelay()
  try:
    r.serve_forever()
  except KeyboardInterrupt:
    print "\nCaught keyboard interrupt...bailing out."

#!/usr/bin/env python
#
# OSPF Multicast Sniffer and graphviz graph generator 
# 
# Starts sniffing for OSPF traffic, processes
# LS Update messages and generates a graphviz network graph.
# To convert to image file, use:
#   ospf-to-graphviz.py mynetwork.dot
#   dot -Tpng mynetwork.dot >mynetwork.png
#
# Based on initial code by Ferdy Riphagen:
# http://code.activestate.com/recipes/576664-ospf-multicast-sniffer/
#

import socket
import sys
import datetime
import netaddr
import pcap
import dpkt
import struct 
import binascii

resolve_router_hostnames = False

OSPF_TYPE = ["Invalid","Hello","DBD","LSR","LSU","LSA"]




def mkNetInt(r):
  if len(r)==1:
    return ord(r[0])
  else:
    return ord(r[0])*256 + mkNetInt(r[1:])


def safeIPAddr(ip):
  return str(ip).replace('.', '_')


def destNW(ip, networks):
  for nw in networks:
    if (ip & networks[nw].netmask) == nw:
      return nw
  return None


class OSPF_LSA_Header(object):
  def __init__(self, data):
    self.age = mkNetInt(data[0:2])
    self.options = ord(data[2])
    self.type = ord(data[3])
    self.lsid = netaddr.IPAddress(socket.inet_ntoa(data[4:8]))
    self.advrouter = netaddr.IPAddress(socket.inet_ntoa(data[8:12]))
    self.seq = mkNetInt(data[12:16])


class OSPF_LSA_Router(OSPF_LSA_Header):
  class Link(object):
    linkTypes = { 1: 'p2p to router', 2: 'transit n/w', 3: 'stub n/w', 4: 'virtual link' }
    def __init__(self, data):
      self.id = netaddr.IPAddress(socket.inet_ntoa(data[0:4]))
      self.data = netaddr.IPAddress(socket.inet_ntoa(data[4:8]))
      self.type = ord(data[8])
      self.metric = mkNetInt(data[10:12])
    def __str__(self):
      return '%s (%d): %s [%s], %d' % (self.linkTypes[self.type], self.type, self.id, self.data, self.metric)

  def __init__(self, data):
    OSPF_LSA_Header.__init__(self, data)
    self.links=[]
    l = data[24:]
    while len(l) > 0:
      self.links.append(self.Link(l[0:12]))
      l = l[12:]

  def __str__(self):
    return ', '.join([str(self.lsid), str(self.advrouter), '\n[ '+'\n  '.join([str(l) for l in self.links])+'\n]'])


class OSPF_LSA_Network(OSPF_LSA_Header):
  def __init__(self, data):
    OSPF_LSA_Header.__init__(self, data)
    self.netmask = netaddr.IPAddress(socket.inet_ntoa(data[20:24]))
    data = data[24:]
    self.attached = []
    while len(data) > 0:
      self.attached.append(netaddr.IPAddress(socket.inet_ntoa(data[0:4])))
      data = data[4:]

  def __str__(self):
    return ', '.join([str(self.lsid), str(self.advrouter), str(self.netmask), '{'+', '.join([str(a) for a in self.attached])+'}'])

class OSPF_LSA_External(OSPF_LSA_Header):
  def __init__(self, data):
    OSPF_LSA_Header.__init__(self, data)
    self.netmask = netaddr.IPAddress(socket.inet_ntoa(data[20:24]))
    self.metric = mkNetInt(data[24:28]) & 0x00ffffff
    

class OSPF_LS_Update(object):
  lsTypes = { 1: ('Router-LSAs', OSPF_LSA_Router), 2: ('Network-LSAs', OSPF_LSA_Network), 5: ('AS-external-LSAs', OSPF_LSA_External) }
  def __init__(self, data):
    self.routerID = netaddr.IPAddress(socket.inet_ntoa(data[4:8]))
    self.areaID = netaddr.IPAddress(socket.inet_ntoa(data[8:12]))
    self.lsa = []

    numLSAs = mkNetInt(data[24:28])
    lsas = data[28:]
    for i in range(numLSAs):
      lsaLen = mkNetInt(lsas[18:20])
      lsType = ord(lsas[3])
      if lsType in self.lsTypes:
        self.lsa.append(self.lsTypes[lsType][1](lsas[0:lsaLen]))
      lsas=lsas[lsaLen:]


class NetworkModel(object):
  def __init__(self):
    self.extnetworks={}
    self.networks={}
    self.routers={}
    self.changed = False

  def injectLSA(self, lsa):
    if lsa.type == 2:
      network = lsa.lsid & lsa.netmask
      if not self.networks.has_key(network) or lsa.seq > self.networks[network].seq:
        self.networks[network] = lsa
        self.changed = True
#        print "Network Update: ", lsa
      else:
        print "N/W lsa is old", lsa
    elif lsa.type == 1:
      if not self.routers.has_key(lsa.lsid) or lsa.seq > self.routers[lsa.lsid].seq:
        self.routers[lsa.lsid] = lsa
        self.changed = True
#        print "Router Update: ", lsa
      else:
        print "Router lsa is old", lsa
    elif lsa.type == 5:
      network = lsa.lsid & lsa.netmask
      if not self.extnetworks.has_key(lsa.advrouter):
        self.extnetworks[lsa.advrouter] = {}
      if not self.extnetworks[lsa.advrouter].has_key(network) or lsa.seq > self.extnetworks[lsa.advrouter][network].seq:
        self.extnetworks[lsa.advrouter][network] = lsa
        self.changed = True
#        print "Extern update: ", lsa
      else:
        print "Extern LSA is old"
    else:
      print "Unknown LSA!", lsa.type

  def generateGraph(self):
    out = []
    out.append('graph ospf_nw {')
    out.append('  layout=fdp;')
    out.append('  label="Generated: %s";' % str(datetime.datetime.utcnow()))
    out.append('  node [shape="box",style="rounded"];')

    nodes = set()
    links = []

    p2pnw = {}
    p2plink = {}

    for r in self.routers:
      out.append('  subgraph cluster_%s {' % safeIPAddr(r))

      label = r
      if resolve_router_hostnames:
        try:
          label = '%s\\n(%s)' % (socket.gethostbyaddr(str(r))[0].split('.')[0], r)
        except:
          print 'Could not get hostname for router %s' % r

      out.append('    label = "%s";' % label)
      rnodes = set()
      for iface in self.routers[r].links:
        if iface.type == 2:  # transit n/w
          rnodes.add('    N%s [label="%s"];' % (safeIPAddr(iface.data), iface.data ))
        elif iface.type == 1:  # p2p n/w
          rnodes.add('    N%s [label="%s"];' % (safeIPAddr(iface.data), iface.data ))
          p2pnw[str(iface.data)] = str(r)
          p2plink['%s_%s' % (iface.id, r)] = str(iface.data)
      out += list(rnodes)
      out.append('  }')

    for nw in self.networks:
      out.append('  nw_%s [shape="plaintext",label="%s/%s"];' % (safeIPAddr(nw), nw, self.networks[nw].netmask.bin.count('1') ))

    for r in self.routers:
      for iface in self.routers[r].links:
        if iface.type == 2:  # transit n/w
          links.append('  N%s -- nw_%s [label="%s"];' % (safeIPAddr(iface.data), safeIPAddr(destNW(iface.data, self.networks)), iface.metric))
        elif iface.type == 3:  # stub n/w
          if (str(iface.id) not in p2pnw) or (str(p2pnw[str(iface.id)]) == str(r)) or ('%s_%s' % (p2pnw[str(iface.id)], r) not in p2plink):
            nodes.add('  stub_%s [shape="doubleoctagon",label="%s/%s"];' % (safeIPAddr(iface.id), iface.id, iface.data.bin.count('1')))
            links.append('  cluster_%s -- stub_%s [label="%s"];' % (safeIPAddr(r), safeIPAddr(iface.id), iface.metric))
          else:
            remoteid = p2pnw[str(iface.id)]
            p2psorted = sorted([remoteid, str(r)])
            p2plocalip = p2plink['%s_%s' % (remoteid, r)]
            nodes.add('  ptp_%s_%s [shape="plaintext",label="Tunnel"];' % (safeIPAddr(p2psorted[0]), safeIPAddr(p2psorted[1])))
            links.append('  N%s -- ptp_%s_%s [label="%s"];' % (safeIPAddr(p2plocalip), safeIPAddr(p2psorted[0]), safeIPAddr(p2psorted[1]), iface.metric))

      if r in self.extnetworks:
        for extnet in self.extnetworks[r]:
          nodes.add('  extnet_%s [shape="octagon",label="%s/%s"];' % (safeIPAddr(extnet), extnet, self.extnetworks[r][extnet].netmask.bin.count('1')))
          links.append('  cluster_%s -- extnet_%s [label="%s"];' % (safeIPAddr(r), safeIPAddr(extnet), self.extnetworks[r][extnet].metric))

    out += list(nodes) + links

    out.append('}')
    out.append('')
    self.changed = False
    return '\n'.join(out)

nw = NetworkModel()

def processPacket(data):
  z=OSPF_LS_Update(data)
  for l in z.lsa:
    nw.injectLSA(l)

  if nw.changed:
    if graphFile:
      f=open(graphFile, 'w')
      f.write(nw.generateGraph())
      f.close()
    else:
      print nw.generateGraph()
#    print "Router Debug:"
#    for i in nw.routers:
#      print i, nw.routers[i]
#    print '-'*30
#    print "Network Debug:"
#    for i in nw.networks:
#      print i, nw.networks[i]
#    print '-'*30

graphFile = None

if __name__ == '__main__':

  if len(sys.argv) == 2:
    graphFile = sys.argv[1]

  print "Output file:", graphFile

  
  sock = pcap.pcap(name=None, promisc=True, immediate=True)
  sock.setfilter("proto 89")
  print "Listener started"
  try:
    for timestamp, data in sock:
      eth=dpkt.ethernet.Ethernet(data)
      ip=eth.data
      if not isinstance(ip.data, dpkt.ospf.OSPF):
        print "Invalid OSPF Packet"
        continue 
      ospf = ip.data
      # Only process actual update packets
      if OSPF_TYPE[ospf.type] == "LSU":    
        print timestamp, "src: ", socket.inet_ntoa(ip.src), "\tRouter: ", str(netaddr.IPAddress(ospf.router)), "\tArea: ", ospf.area, "\tType: ", OSPF_TYPE[ospf.type]
        processPacket(data[34:])
#      else 
#        print timestamp, "src: ", socket.inet_ntoa(ip.src), "\tRouter: ", str(netaddr.IPAddress(ospf.router)), "\tArea: ", ospf.area, "\tType: ", OSPF_TYPE[ospf.type]
  except KeyboardInterrupt:
    sys.exit()  


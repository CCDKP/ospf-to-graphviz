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

from socket import gethostbyaddr, inet_ntoa
import sys
import datetime
import netaddr
import pcap
import dpkt
import argparse
#from binascii import hexlify

resolve_router_hostnames = False

OSPFTypes = {1: 'Hello',
             2: 'DBD',
             3: 'LSR',
             4: 'LSU',
             5: 'LSAck'}


def bytesToInt(r):
    if len(r)==1:
        return ord(r[0])
    else:
        return ord(r[0])*256 + bytesToInt(r[1:])


def safeIPAddr(ip):
    return str(ip).replace('.', '_')


def destNW(ip, networks):
    for nw in networks:
        if (ip & networks[nw].netmask) == nw:
            return nw
    return None


"""
    OSPF LSA Packet header (IP header removed)
    +--------+--------+--------+--------+
    | Byte 1 | Byte 2 | Byte 3 | Byte 4 |
    +--------+--------+--------+--------+
   0|      LS age     | Options|  Type  |
    +--------+--------+--------+--------+
   4|           Link State ID           |
    +--------+--------+--------+--------+
   8|         Advertising Router        |
    +--------+--------+--------+--------+
  12|          Sequence Number          |
    +--------+--------+--------+--------+
  16|  LS  Checksum   |  Total  Length  |
    +--------+--------+--------+--------+
  20|        Type-dependent data...     |
"""
class OSPF_LSA_Header(object):
    def __init__(self, data):
        self.age = bytesToInt(data[0:2])
        self.options = ord(data[2])
        self.type = ord(data[3])
        self.lsid = netaddr.IPAddress(inet_ntoa(data[4:8]))
        self.advrouter = netaddr.IPAddress(inet_ntoa(data[8:12]))
        self.seq = bytesToInt(data[12:16])


"""
    OSPF LSA Router Packet (LSA type 1)
    +--------+--------+--------+--------+
    | Byte 1 | Byte 2 | Byte 3 | Byte 4 |
    +--------+--------+--------+--------+
0-16|      20 byte OSPF LSU Header      |
    +--------+--------+--------+--------+
  20|VEBflags|  NULL  |   Link Count    |
    +--------+--------+--------+--------+
  24|        12-byte Link objects...    |


    Link Objects
    +--------+--------+--------+--------+
    | Byte 1 | Byte 2 | Byte 3 | Byte 4 |
    +--------+--------+--------+--------+
   0|             Link ID               |
    +--------+--------+--------+--------+
   4|             Link Data             |
    +--------+--------+--------+--------+
   8|  Type  | # TOS  |     Metric      |
    +--------+--------+--------+--------+
"""
class OSPF_LSA_Router(OSPF_LSA_Header):
    class Link(object):
        linkTypes = { 1: 'p2p to router', 2: 'transit n/w', 3: 'stub n/w', 4: 'virtual link' }
        def __init__(self, data):
            self.id = netaddr.IPAddress(inet_ntoa(data[0:4]))
            self.data = netaddr.IPAddress(inet_ntoa(data[4:8]))
            self.type = ord(data[8])
            self.metric = bytesToInt(data[10:12])
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

"""
    OSPF LSA Network Packet (LSA type 2)
    +--------+--------+--------+--------+
    | Byte 1 | Byte 2 | Byte 3 | Byte 4 |
    +--------+--------+--------+--------+
0-16|      20 byte OSPF LSU Header      |
    +--------+--------+--------+--------+
  20|           Network Mask            |
    +--------+--------+--------+--------+
  24|    4-byte Attached Routers...     |
"""
class OSPF_LSA_Network(OSPF_LSA_Header):
    def __init__(self, data):
        OSPF_LSA_Header.__init__(self, data)
        self.netmask = netaddr.IPAddress(inet_ntoa(data[20:24]))
        data = data[24:]
        self.attached = []
        while len(data) > 0:
            ip = netaddr.IPAddress(inet_ntoa(data[0:4]))
            self.attached.append(ip)
            data = data[4:]

    def __str__(self):
        return ', '.join([str(self.lsid), str(self.advrouter), str(self.netmask), '{'+', '.join([str(a) for a in self.attached])+'}'])


"""
@TODO: Add support for LSA Type 3 & 4 Summary & ASBR LSAs
"""

"""
    OSPF LSA External Packet (LSA type 5)
    +--------+--------+--------+--------+
    | Byte 1 | Byte 2 | Byte 3 | Byte 4 |
    +--------+--------+--------+--------+
0-16|      20 byte OSPF LSU Header      |
    +--------+--------+--------+--------+
  20|           Network Mask            |
    +--------+--------+--------+--------+
  24|Type bit|           Metric         |
    +--------+--------+--------+--------+
  28|         Forwarding Address        |
    +--------+--------+--------+--------+
  32|  OSPFv1 Legacy & Unused data...   |

"""

class OSPF_LSA_External(OSPF_LSA_Header):
    def __init__(self, data):
        OSPF_LSA_Header.__init__(self, data)
        self.netmask = netaddr.IPAddress(inet_ntoa(data[20:24]))
        self.metric = bytesToInt(data[24:28]) & 0x00ffffff

"""
@TODO: Add support for LSA Type 7 NSSA LSAs
"""

class OSPF_LSUpdate(object):
    lsTypes = { 1: ('Router-LSAs', OSPF_LSA_Router), 2: ('Network-LSAs', OSPF_LSA_Network), 5: ('AS-external-LSAs', OSPF_LSA_External) }
    def __init__(self, data):
        self.lsa = []
        numLSAs = bytesToInt(data[0:4])
        rawLSAs = data[4:]
        for i in range(numLSAs):
            lsaLen = bytesToInt(rawLSAs[18:20])
            lsType = ord(rawLSAs[3])
            if lsType in self.lsTypes:
                klass = self.lsTypes[lsType][1]
                instance = klass(rawLSAs[0:lsaLen])
                self.lsa.append(instance)
            rawLSAs=rawLSAs[lsaLen:]


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
                    label = '%s\\n(%s)' % (gethostbyaddr(str(r))[0].split('.')[0], r)
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



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Monitor OSPF packets and build a link-state database")
    parser.add_argument('-i', '--input', default=None, metavar='file',
                        help='Interface or pcap file to read from (default: First interface')
    parser.add_argument('-d', '--dot', dest='dotFile', default=None, metavar='file',
                        help='Output Graphviz compatible DOT file.')
    parser.add_argument('-v', '--verbose', default=0, action='count',
                        help='Increase output verbosity')
    parser.add_argument('--dbg', action='store_true',
                        help='Pause between packets and display link state DB.')
    args = parser.parse_args()

    if args.verbose >= 3:
        print "Output file: ", args.dotFile

    try:
        sock = pcap.pcap(name=args.input, promisc=True, immediate=True)
        sock.setfilter("proto 89")
    except:
        print "Error opening packet source: ", args.input
        sys.exit()
    if args.verbose >= 1:
        print "Successfully connected to packet source: ", args.input

    nw = NetworkModel()

    try:
        for timestamp, data in sock:
            eth = dpkt.ethernet.Ethernet(data)
            ip = eth.data
            if not isinstance(ip.data, dpkt.ospf.OSPF):
                if args.verbose >= 1:
                    print "Invalid OSPF Packet"
                continue
            ospf = ip.data
            # Only process actual update packets
            if ospf.type == 4:
                if args.verbose >= 2:
                    print timestamp, \
                        "src: ", inet_ntoa(ip.src), \
                        "\tRouter: ", str(netaddr.IPAddress(ospf.router)), \
                        "\tArea: ", ospf.area, \
                        "\tType: ", OSPFTypes[ospf.type]

                lsu = OSPF_LSUpdate(ospf.data)
                for l in lsu.lsa:
                    nw.injectLSA(l)

                if nw.changed:
                    if args.dotFile:
                        f = open(args.dotFile, 'w')
                        f.write(nw.generateGraph())
                        f.close()

                if args.dbg:
                    print "Router Debug:"
                    for i in nw.routers:
                        print i, " - ", nw.routers[i]
                    print '-' * 30
                    print "Network Debug:"
                    for i in nw.networks:
                        print i, " - ", nw.networks[i]
                    print '-' * 30
                    raw_input("Press Enter to continue...")

            elif args.verbose >= 3:
                if ospf.type in OSPFTypes:
                    packettype = OSPFTypes[ospf.type]
                else:
                    packettype = 'UNKNOWN'

                print timestamp, \
                    "Src: ", inet_ntoa(ip.src), \
                    "\tRouter: ", str(netaddr.IPAddress(ospf.router)), \
                    "\tArea: ", ospf.area, \
                    "\tType: ", packettype
    except KeyboardInterrupt:
        sys.exit()
    print "Processing Completed."


# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#*** nmeta - Network Metadata - Policy Interpretation Class and Methods

"""
This module is part of the nmeta2 suite
.
It provides an abstraction for a TCP flow that links to a MongoDB
database and changes to the context of the flow that a supplied packet
belongs to. We implement the Flow class.
.
Version 2.x Toulouse Code
"""

# Inherit from parent class
import flow

#*** For packet methods:
import socket

#*** Import dpkt for packet parsing:
import dpkt

#*** mongodb Database Import:
from pymongo import MongoClient

# Class variables containing protocol type values to reduce the amount
# of referencing to modules.
_ETH_TYPE_IP = dpkt.ethernet.ETH_TYPE_IP
_IP_PROTO_TCP = dpkt.ip.IP_PROTO_TCP
_TH_FIN = dpkt.tcp.TH_FIN
_TH_SYN = dpkt.tcp.TH_SYN
_TH_RST = dpkt.tcp.TH_RST
_TH_PUSH = dpkt.tcp.TH_PUSH
_TH_ACK = dpkt.tcp.TH_ACK
_TH_URG = dpkt.tcp.TH_URG
_TH_ECE = dpkt.tcp.TH_ECE
_TH_CWR = dpkt.tcp.TH_CWR

class TCPFlow(flow.Flow):
    """
    An object that represents a flow that we are classifying

    Intended to provide an abstraction of a flow that classifiers
    can use to make determinations without having to understand
    implementations such as database lookups etc.

    Be aware that this module is not very mature yet. It does not
    cover some basic corner cases such as packet retransmissions and
    out of order or missing packets.

    Variables available for Classifiers (assumes class instantiated as
    an object called 'flow'):


        **Variables for the current packet**:

        tcp.ip_src
          IP source address of latest packet in flow

        tcp.ip_dst
          IP dest address of latest packet in flow

        tcp.tcp_src
          TCP source port of latest packet in flow

        tcp.tcp_dst
          TCP dest port of latest packet in flow

        tcptcp_seq
          TCP sequence number of latest packet in flow

        tcp.tcp_acq
          TCP acknowledgement number of latest packet in flow

        ftcp.tcp_fin()
          True if TCP FIN flag is set in the current packet

        tcp.tcp_syn()
          True if TCP SYN flag is set in the current packet

        tcp.tcp_rst()
          True if TCP RST flag is set in the current packet

        tcp.tcp_psh()
          True if TCP PSH flag is set in the current packet

        tcp.tcp_ack()
          True if TCP ACK flag is set in the current packet

        tcp.tcp_urg()
          True if TCP URG flag is set in the current packet

        tcp.tcp_ece()
          True if TCP ECE flag is set in the current packet

        tcp.tcp_cwr()
          True if TCP CWR flag is set in the current packet

        tcp.payload
          Payload of TCP of latest packet in flow

        tcp.packet_length
          Length in bytes of the current packet on wire

        tcp.packet_direction
          c2s (client to server) or s2c directionality based on first observed
          packet having SYN or SYN+ACK flag, otherwise client assumed as source
          IP of first packet and verified_direction set to 0 (i.e. 
          don't trust packet_direction unless verified_direction is set)

        **Variables for the whole flow**:

        tcp.verified_direction
          Describes how the directionality of the flow was ascertained.
          Values can be verified-SYN, verified-SYNACK or 0 (unverified)

        tcp.finalised
          A classification has been made

        tcp.suppressed
          The flow packet count number when a request was made to controller
          to not see further packets in this flow. 0 is not suppressed

        tcp.packet_count
          Unique packets registered for the flow

        tcp.client
          The IP that is the originator of the TCP session (if known,
          otherwise 0)

        tcp.server
          The IP that is the destination of the TCP session
          session (if known, otherwise 0)

        **Methods available for Classifiers**:
        (assumes class instantiated as an object called 'flow')

        tcp.max_packet_size()
          Size of largest packet in the flow

        tcp.max_interpacket_interval()
          TBD

        tcp.min_interpacket_interval()
          TBD

    Challenges:
     - duplicate packets
     - IP fragments (not handled)
     - Flow reuse - TCP source port reused (not handled - yet)
    """

    def __init__(self, logger, mongo_addr, mongo_port):
        """Initialise an instance of the TCPFlow class for a new flow.

        Passed layer 3/4 parameters. Add an entry to the FCIP database
        if it doesn't already exist. If it does exist, update it.

        This is specific to TCP.
        """
        flow.Flow.__init__(self)
        self.logger = logger
        #*** Maximum packets in a flow before finalising:
        self.max_packet_count = 10

        #*** Initialise specifc packet variables:
        self.tcp_src = 0
        self.tcp_dst = 0
        self.tcp_flags = 0
        self.tcp_seq = 0
        self.tcp_acq = 0

        #*** Initialise flow variables:
        self.verified_direction = 0

        #*** Start mongodb:
        self.logger.info("Connecting to mongodb database...")
        mongo_client = MongoClient(mongo_addr, mongo_port)

        #*** Connect to specific databases and collections in mongodb:
        #*** FCIP (Flow Classification in Progress) database:
        db_fcip = mongo_client.fcip_database
        self.fcip = db_fcip.fcip_tcp

        #*** DPAE database - delete all previous entries:
        result = self.fcip.delete_many({})
        self.logger.info("Initialising FCIP database, Deleted %s "
                         "previous entries from fcip_database fcip_tcp "
                         "collection", result.deleted_count)

        #*** Database index for performance:
        self.fcip.create_index([("hash", 1)])


    def ingest_packet(self, pkt, pkt_receive_timestamp):
        """
        Ingest a packet and put the flow object into the context
        of the flow that the packet belongs to.
        """
        #*** Packet length on the wire:
        self.packet_length = len(pkt)
        #*** Read into dpkt:
        eth = dpkt.ethernet.Ethernet(pkt)
        eth_src = flow.mac_addr(eth.src)
        eth_dst = flow.mac_addr(eth.dst)
        eth_type = eth.type
        #*** We only support IPv4 (TBD: add IPv6 support):
        if eth_type != _ETH_TYPE_IP:
            self.logger.error("Non IPv4 packet, eth_type is %s", eth_type)
            return 0
        ip = eth.data
        self.ip_src = socket.inet_ntop(socket.AF_INET, ip.src)
        self.ip_dst = socket.inet_ntop(socket.AF_INET, ip.dst)

        # This class only supports TCP:
        if ip.p != _IP_PROTO_TCP:
            self.logger.error("Non TCP packet, ip_proto=%s", ip.p)
            return 0
        proto = 'tcp'
        tcp = ip.data
        self.tcp_src = tcp.sport
        self.tcp_dst = tcp.dport
        self.tcp_seq = tcp.seq
        self.tcp_acq = tcp.ack
        self.tcp_flags = tcp.flags
        self.payload = tcp.data
        #*** Generate a hash unique to flow for packets in either direction
        self.fcip_hash = flow.hash_5tuple(self.ip_src, self.ip_dst,
                                          self.tcp_src, self.tcp_dst, proto)
        #*** Check to see if we already know this identity:
        db_data = {'hash': self.fcip_hash}
        self.fcip_doc = self.fcip.find_one(db_data)
        if not self.fcip_doc:
            #*** Get flow direction (which way is TCP initiated). Client is
            #***  the end that sends the initial TCP SYN:
            if _is_tcp_syn(tcp.flags):
                self.logger.debug("Matched TCP SYN first pkt, src_ip=%s",
                                                                self.ip_src)
                self.client = self.ip_src
                self.server = self.ip_dst
                self.packet_direction = 'c2s'
                self.verified_direction = 'verified-SYN'
            elif _is_tcp_synack(tcp.flags):
                self.logger.debug("Matched TCP SYN+ACK first pkt, src_ip=%s",
                                                                self.ip_src)
                self.client = self.ip_dst
                self.server = self.ip_src
                self.packet_direction = 's2c'
                self.verified_direction = 'verified-SYNACK'
            else:
                self.logger.debug("Unmatch state first pkt, tcp_flags=%s",
                                                                tcp.flags)
                self.client = self.ip_src
                self.server = self.ip_dst
                self.packet_direction = 'c2s'
                self.verified_direction = 0
            #*** Neither direction found, so add to FCIP database:
            self.fcip_doc = {'hash': self.fcip_hash,
                        'ip_A': self.ip_src,
                        'ip_B': self.ip_dst,
                        'port_A': self.tcp_src,
                        'port_B': self.tcp_dst,
                        'proto': proto,
                        'finalised': 0,
                        'packet_count': 1,
                        'packet_timestamps': [pkt_receive_timestamp,],
                        'latest_timestamp': pkt_receive_timestamp,
                        'packet_lengths': [self.packet_length,],
                        'total_pkt_len_A': self.packet_length,
                        'total_pkt_cnt_A': 1,
                        'total_pkt_len_B': 0,
                        'total_pkt_cnt_B': 0,
                        'tcp_flags': [tcp.flags,],
                        'client': self.client,
                        'server': self.server,
                        'packet_directions': [self.packet_direction,],
                        'verified_direction': self.verified_direction,
                        'suppressed': 0}
            self.logger.debug("FCIP: Adding record for %s to DB",
                                                self.fcip_doc)
            db_result = self.fcip.insert_one(self.fcip_doc)
            self.packet_count = 1

        elif self.fcip_doc['finalised']:
            # The flow is finalised so we need to update: directional
            # packet lengths, directional packet counts, total packet
            # count and the latest timestamp.
            self.fcip_doc['latest_timestamp'] = pkt_receive_timestamp
            self.fcip_doc['packet_count'] += 1
            if self.fcip_doc['ip_A'] == self.ip_src:
                self.fcip_doc['total_pkt_len_A'] += self.packet_length
                self.fcip_doc['total_pkt_cnt_A'] += 1
            else:
                self.fcip_doc['total_pkt_len_B'] += self.packet_length
                self.fcip_doc['total_pkt_cnt_B'] += 1
            #*** Write updated FCIP data back to database:
            db_result = self.fcip.update_one({'hash': self.fcip_hash},
                {'$set': {'packet_count': self.fcip_doc['packet_count'],
                          'latest_timestamp': self.fcip_doc['latest_timestamp'],
                          'total_pkt_len_A': self.fcip_doc['total_pkt_len_A'],
                          'total_pkt_cnt_A': self.fcip_doc['total_pkt_cnt_A'],
                          'total_pkt_len_B': self.fcip_doc['total_pkt_len_B'],
                          'total_pkt_cnt_B': self.fcip_doc['total_pkt_cnt_B']
                          },})
            self.packet_count = self.fcip_doc['packet_count']

        else:
            #*** We've found the flow in the FCIP database, now update it:
            self.logger.debug("FCIP: found existing record %s", self.fcip_doc)
            #*** Rate this packet as c2s or s2c direction:
            if self.client == self.ip_src:
                self.packet_direction = 'c2s'
            elif self.client == self.ip_dst:
                self.packet_direction = 's2c'
            else:
                self.packet_direction = 'unknown'
            # Determine if the packet length and count should be
            # incremented for _A or _B
            if self.fcip_doc['ip_A'] == self.ip_src:
                self.fcip_doc['total_pkt_len_A'] += self.packet_length
                self.fcip_doc['total_pkt_cnt_A'] += 1
            else:
                self.fcip_doc['total_pkt_len_B'] += self.packet_length
                self.fcip_doc['total_pkt_cnt_B'] += 1
            #*** Increment packet count. Is it at max?:
            self.fcip_doc['packet_count'] += 1
            self.packet_count = self.fcip_doc['packet_count']
            if self.fcip_doc['packet_count'] >= self.max_packet_count:
                #*** TBD:
                self.fcip_doc['finalised'] = 1
                self.logger.debug("Finalising...")
            #*** Read suppressed status to variable:
            self.suppressed = self.fcip_doc['suppressed']
            #*** Read verified_direction status to variable:
            self.verified_direction = self.fcip_doc['verified_direction']
            #*** Add packet timestamps, tcp flags etc:
            self.fcip_doc['packet_timestamps'].append(pkt_receive_timestamp)
            self.fcip_doc['latest_timestamp'] = pkt_receive_timestamp
            self.fcip_doc['tcp_flags'].append(tcp.flags)
            self.fcip_doc['packet_lengths'].append(self.packet_length)
            self.fcip_doc['packet_directions'].append(self.packet_direction)
            #*** Write updated FCIP data back to database:
            db_result = self.fcip.update_one({'hash': self.fcip_hash},
                {'$set': {'packet_count': self.fcip_doc['packet_count'],
                    'finalised': self.fcip_doc['finalised'],
                    'packet_timestamps': self.fcip_doc['packet_timestamps'],
                    'latest_timestamp': self.fcip_doc['latest_timestamp'],
                    'tcp_flags': self.fcip_doc['tcp_flags'],
                    'packet_lengths': self.fcip_doc['packet_lengths'],
                    'total_pkt_len_A': self.fcip_doc['total_pkt_len_A'],
                    'total_pkt_cnt_A': self.fcip_doc['total_pkt_cnt_A'],
                    'total_pkt_len_B': self.fcip_doc['total_pkt_len_B'],
                    'total_pkt_cnt_B': self.fcip_doc['total_pkt_cnt_B'],
                    'packet_directions': self.fcip_doc['packet_directions']
                },})
            #*** Tests:
            self.logger.debug("max_packet_size is %s", self.max_packet_size())
            self.logger.debug("max_interpacket_interval is %s",
                                            self.max_interpacket_interval())
            self.logger.debug("min_interpacket_interval is %s",
                                            self.min_interpacket_interval())

    def set_suppress_flow(self):
        """
        Set the suppressed attribute in the flow database
        object to the current packet count so that future
        suppressions of the same flow can be backed off
        to prevent overwhelming the controller
        """
        self.suppressed = self.packet_count
        self.fcip.update_one({'hash': self.fcip_hash},
                                {'$set': {'suppressed': self.suppressed},})

    def tcp_fin(self):
        """
        Does the current packet have the TCP FIN flag set?
        """
        return self.tcp_flags & _TH_FIN != 0

    def tcp_syn(self):
        """
        Does the current packet have the TCP SYN flag set?
        """
        return self.tcp_flags & _TH_SYN != 0

    def tcp_rst(self):
        """
        Does the current packet have the TCP RST flag set?
        """
        return self.tcp_flags & _TH_RST != 0

    def tcp_psh(self):
        """
        Does the current packet have the TCP PSH flag set?
        """
        return self.tcp_flags & _TH_PUSH != 0

    def tcp_ack(self):
        """
        Does the current packet have the TCP ACK flag set?
        """
        return self.tcp_flags & _TH_ACK != 0

    def tcp_urg(self):
        """
        Does the current packet have the TCP URG flag set?
        """
        return self.tcp_flags & _TH_URG != 0

    def tcp_ece(self):
        """
        Does the current packet have the TCP ECE flag set?
        """
        return self.tcp_flags & _TH_ECE != 0

    def tcp_cwr(self):
        """
        Does the current packet have the TCP CWR flag set?
        """
        return self.tcp_flags & _TH_CWR != 0

#================== PRIVATE FUNCTIONS ==================

def _is_tcp_syn(tcp_flags):
    """
    Passed a TCP flags object (hex) and return 1 if it
    contains a TCP SYN and no other flags
    """
    if tcp_flags == 2:
        return 1
    else:
        return 0


def _is_tcp_synack(tcp_flags):
    """
    Passed a TCP flags object (hex) and return 1 if it
    contains TCP SYN + ACK flags and no other flags
    """
    if tcp_flags == 0x12:
        return 1
    else:
        return 0

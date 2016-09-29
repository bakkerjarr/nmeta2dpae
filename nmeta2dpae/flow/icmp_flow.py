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
It provides an abstraction for an ICMP flow that links to a MongoDB
database and changes to the context of the flow that a supplied packet
belongs to. We implement the Flow class.
.
Version 2.x Toulouse Code
"""

# Inherit from parent class
import flow

# For hashing ICMP flow data
import hashlib

#*** For packet methods:
import socket

#*** Import dpkt for packet parsing:
import dpkt

#*** mongodb Database Import:
from pymongo import MongoClient

# Class variables containing protocol type values to reduce the amount
# of referencing to modules.
_ETH_TYPE_IP = dpkt.ethernet.ETH_TYPE_IP
_IP_PROTO_ICMP = dpkt.ip.IP_PROTO_ICMP
_ICMP_TYPE_ECHOREPLY = dpkt.icmp.ICMP_ECHOREPLY
_ICMP_TYPE_ECHOREQ = dpkt.icmp.ICMP_ECHO


class ICMPFlow(flow.Flow):
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

        # Variables for the current packet:
        icmp.ip_src         # IP source address of latest packet in flow
        icmp.ip_dst         # IP dest address of latest packet in flow
        icmp.icmp_type      # Type number for ICMP packet
        icmp.icmp_code      # Code number for ICMP packet

        icmp.payload        # Payload of ICMP of latest packet in flow (if any)
        icmp.packet_length  # Length in bytes of the current packet on wire
        icmp.packet_direction   # c2s (client to server), s2c or unknown

        # Variables for the whole flow:
        icmp.finalised      # A classification has been made
        icmp.suppressed     # The flow packet count number when
                            #  a request was made to controller to not see
                            #  further packets in this flow. 0 is
                            #  not suppressed
        icmp.packet_count   # Unique packets registered for the flow
        icmp.client         # The IP that is the originator of the ICMP
                            #  session (if known, otherwise 0)
        icmp.server         # The IP that is the destination of the ICMP
                            # session (if known, otherwise 0)

    Methods available for Classifiers (assumes class instantiated as
    an object called 'flow'):
        icmp.max_packet_size()           # Size of largest packet in the flow
        icmp.max_interpacket_interval()  # TBD
        icmp.min_interpacket_interval()  # TBD

    Challenges:
     - duplicate packets
     - IP fragments (not handled)
    """

    def __init__(self, logger, mongo_addr, mongo_port):
        """Initialise an instance of the ICMPFlow class for a new flow.

        Passed layer 3/4 parameters. Add an entry to the FCIP database
        if it doesn't already exist. If it does exist, update it.

        This is specific to ICMP.
        """
        flow.Flow.__init__(self)
        self.logger = logger
        #*** Maximum packets in a flow before finalising:
        self.max_packet_count = 10

        #*** Initialise specifc packet variables:
        self.icmp_type = 0
        self.icmp_code = 0

        #*** Start mongodb:
        self.logger.info("Connecting to mongodb database...")
        mongo_client = MongoClient(mongo_addr, mongo_port)

        #*** Connect to specific databases and collections in mongodb:
        #*** FCIP (Flow Classification in Progress) database:
        db_fcip = mongo_client.fcip_database
        self.fcip = db_fcip.fcip_icmp

        #*** DPAE database - delete all previous entries:
        result = self.fcip.delete_many({})
        self.logger.info("Initialising FCIP database, Deleted %s "
                         "previous entries from fcip_database",
                         result.deleted_count)

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

        # This class only supports ICMP
        if ip.p != _IP_PROTO_ICMP:
            self.logger.error("Non ICMP packet, ip_proto=%s", ip.p)
            return 0
        proto = 'icmp'
        icmp = ip.data
        self.icmp_type = icmp.type
        self.icmp_code = icmp.code
        self.payload = icmp.data
        # Generate a hash unique to flow for packets in either
        # direction. We do not currently separate the different types of
        # ICMP conversations that can occur.
        self.fcip_hash = hash_icmptuple(self.ip_src, self.ip_dst, proto)
        #*** Check to see if we already know this identity:
        db_data = {'hash': self.fcip_hash}
        self.fcip_doc = self.fcip.find_one(db_data)
        if not self.fcip_doc:
            # Determine the direction of the flow. For ICMP assume
            # that the the source IP is the client.
            self.client = self.ip_src
            self.server = self.ip_dst
            self.packet_direction = 'c2s'

            #*** Neither direction found, so add to FCIP database:
            self.fcip_doc = {'hash': self.fcip_hash,
                        'ip_A': self.ip_src,
                        'ip_B': self.ip_dst,
                        'type': [self.icmp_type,],
                        'code': [self.icmp_code,],
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
                        'client': self.client,
                        'server': self.server,
                        'packet_directions': ['c2s',],
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
            self.logger.debug("FCIP: found existing record %s",
                              self.fcip_doc)
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
            # Add packet timestamps and other packet context:
            self.fcip_doc['packet_timestamps'].append(pkt_receive_timestamp)
            self.fcip_doc['latest_timestamp'] = pkt_receive_timestamp
            self.fcip_doc['type'].append(icmp.type)
            self.fcip_doc['code'].append(icmp.code)
            self.fcip_doc['packet_lengths'].append(self.packet_length)
            self.fcip_doc['packet_directions'].append(self.packet_direction)
            #*** Write updated FCIP data back to database:
            db_result = self.fcip.update_one({'hash': self.fcip_hash},
                {'$set': {'packet_count': self.fcip_doc['packet_count'],
                    'finalised': self.fcip_doc['finalised'],
                    'packet_timestamps': self.fcip_doc['packet_timestamps'],
                    'latest_timestamp': self.fcip_doc['latest_timestamp'],
                    'type': self.fcip_doc['type'],
                    'code': self.fcip_doc['code'],
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


#================== HELPER FUNCTIONS ==================

def hash_icmptuple(ip_A, ip_B, proto):
    """
    Generate a predictable hash for the 5-tuple which is the
    same not matter which direction the traffic is travelling
    """
    if ip_A > ip_B:
        direction = 1
    elif ip_B > ip_A:
        direction = 2
    else:
        direction = 1
    hash_icmpt = hashlib.md5()
    if direction == 1:
        flow_tuple = (ip_A, ip_B, proto)
    else:
        flow_tuple = (ip_B, ip_A, proto)
    flow_tuple_as_string = str(flow_tuple)
    hash_icmpt.update(flow_tuple_as_string)
    return hash_icmpt.hexdigest()

def set_suppress_flow(self):
        """
        Set the suppressed attribute in the flow database
        object to the current packet count so that future
        suppressions of the same flow can be backed off
        to prevent overwhelming the controller
        """
        self.suppressed = self.packet_count
        self.fcip.update_one({'hash': self.fcip_hash}, {'$set': {
            'suppressed': self.suppressed},})

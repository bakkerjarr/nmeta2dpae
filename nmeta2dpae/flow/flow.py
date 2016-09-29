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
A parent class abstraction for flow. Specific TCP, UDP and ICMP can
inherit the Flow class below.
.
Version 2.x Toulouse Code
"""

#*** For hashing flow 5-tuples:
import hashlib


class Flow(object):
    """
    A parent object for representing flows that in the process of
    being classified.

    Intended to provide an abstraction of a flow that classifiers
    can use to make determinations without having to understand
    implementations such as database lookups etc.

    Be aware that this module is not very mature yet. It does not
    cover some basic corner cases such as packet retransmissions and
    out of order or missing packets.

    Variables available for Classifiers (assumes class instantiated as
    an object called 'flow'):

        # Variables for the current packet:
        flow.ip_src         # IP source address of latest packet in flow
        flow.ip_dst         # IP dest address of latest packet in flow

        flow.payload        # Payload of TCP of latest packet in flow
        flow.packet_length  # Length in bytes of the current packet on wire
        flow.packet_direction   # c2s (client to server), s2c or unknown

        # Variables for the whole flow:
        flow.finalised      # A classification has been made
        flow.suppressed     # The flow packet count number when
                            #  a request was made to controller to not see
                            #  further packets in this flow. 0 is
                            #  not suppressed
        flow.packet_count   # Unique packets registered for the flow
        flow.client         # The IP that is the originator of the TCP
                            #  session (if known, otherwise 0)
        flow.server         # The IP that is the destination of the TCP session
                            #  session (if known, otherwise 0)

    Methods available for Classifiers (assumes class instantiated as
    an object called 'flow'):
        flow.max_packet_size()           # Size of largest packet in the flow
        flow.max_interpacket_interval()  # TBD
        flow.min_interpacket_interval()  # TBD

    Challenges:
     - duplicate packets
     - IP fragments (not handled)
     - Flow reuse - TCP source port reused (not handled - yet)
    """

    def __init__(self):
        """
        Initialise an instance of the Flow class for a new flow.

        As this is the parent we only need to initialise generic
        variables.
        """
        # Initialise general packet variables:
        self.ip_src = 0
        self.ip_dst = 0
        self.payload = 0

        # Initialise general flow variables:
        self.finalised = 0
        self.packet_length = 0
        self.packet_count = 0
        self.fcip_doc = {}
        self.fcip_hash = 0
        self.client = 0
        self.server = 0
        self.packet_direction = 'unknown'
        self.suppressed = 0

    def max_packet_size(self):
        """
        Return the size of the largest packet in the flow (in either direction)
        """
        return max(self.fcip_doc['packet_lengths'])

    def max_interpacket_interval(self):
        """
        Return the size of the largest inter-packet time interval
        in the flow (assessed per direction in flow).
        .
        Note: slightly inaccurate due to floating point rounding.
        """
        max_c2s = 0
        max_s2c = 0
        count_c2s = 0
        count_s2c = 0
        prev_c2s_idx = 0
        prev_s2c_idx = 0
        for idx, direction in enumerate(self.fcip_doc['packet_directions']):
            if direction == 'c2s':
                count_c2s += 1
                if count_c2s > 1:
                    current_ts = self.fcip_doc['packet_timestamps'][idx]
                    prev_ts = self.fcip_doc['packet_timestamps'][prev_c2s_idx]
                    delta = current_ts - prev_ts
                    if delta > max_c2s:
                        max_c2s = delta
                    prev_c2s_idx = idx
            elif direction == 's2c':
                count_s2c += 1
                if count_s2c > 1:
                    current_ts = self.fcip_doc['packet_timestamps'][idx]
                    prev_ts = self.fcip_doc['packet_timestamps'][prev_s2c_idx]
                    delta = current_ts - prev_ts
                    if delta > max_s2c:
                        max_s2c = delta
                    prev_s2c_idx = idx
            else:
                #*** Don't know direction so ignore:
                pass
        #*** Return the largest interpacket delay overall:
        if max_c2s > max_s2c:
            return max_c2s
        else:
            return max_s2c

    def min_interpacket_interval(self):
        """
        Return the size of the smallest inter-packet time interval
        in the flow (assessed per direction in flow)
        .
        Note: slightly inaccurate due to floating point rounding.
        """
        min_c2s = 0
        min_s2c = 0
        count_c2s = 0
        count_s2c = 0
        prev_c2s_idx = 0
        prev_s2c_idx = 0
        for idx, direction in enumerate(self.fcip_doc['packet_directions']):
            if direction == 'c2s':
                count_c2s += 1
                if count_c2s > 1:
                    current_ts = self.fcip_doc['packet_timestamps'][idx]
                    prev_ts = self.fcip_doc['packet_timestamps'][prev_c2s_idx]
                    delta = current_ts - prev_ts
                    if not min_c2s or delta < min_c2s:
                        min_c2s = delta
                    prev_c2s_idx = idx
            elif direction == 's2c':
                count_s2c += 1
                if count_s2c > 1:
                    current_ts = self.fcip_doc['packet_timestamps'][idx]
                    prev_ts = self.fcip_doc['packet_timestamps'][prev_s2c_idx]
                    delta = current_ts - prev_ts
                    if not min_s2c or delta < min_s2c:
                        min_s2c = delta
                    prev_s2c_idx = idx
            else:
                #*** Don't know direction so ignore:
                pass
        #*** Return the smallest interpacket delay overall, watch out for
        #***  where we didn't get a calculation (don't return 0 unless both 0):
        if not min_s2c:
            #*** min_s2c not set so return min_c2s as it might be:
            return min_c2s
        elif 0 < min_c2s < min_s2c:
            return min_c2s
        else:
            return min_s2c

#================== HELPER FUNCTIONS ==================

def hash_5tuple(ip_A, ip_B, tp_src, tp_dst, proto):
    """
    Generate a predictable hash for the 5-tuple which is the
    same not matter which direction the traffic is travelling
    """
    if ip_A > ip_B:
        direction = 1
    elif ip_B > ip_A:
        direction = 2
    elif tp_src > tp_dst:
        direction = 1
    elif tp_dst > tp_src:
        direction = 2
    else:
        direction = 1
    hash_5t = hashlib.md5()
    if direction == 1:
        flow_tuple = (ip_A, ip_B, tp_src, tp_dst, proto)
    else:
        flow_tuple = (ip_B, ip_A, tp_dst, tp_src, proto)
    flow_tuple_as_string = str(flow_tuple)
    hash_5t.update(flow_tuple_as_string)
    return hash_5t.hexdigest()

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)

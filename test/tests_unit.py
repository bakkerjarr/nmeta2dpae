"""
nmeta2dpae Unit Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, type in:
    py.test tests_unit.py

"""

#*** Handle tests being in different directory branch to app code:
import sys

sys.path.insert(0, '../nmeta2dpae')

import logging

#*** JSON imports:
import json
from json import JSONEncoder

import binascii

#*** Import dpkt for packet parsing:
import dpkt

#*** nmeta2dpae imports:
import nmeta2dpae
import config
import flow as flow_class

#*** Instantiate Config class:
_config = config.Config()

#======================== flow.py Unit Tests ============================
#*** Retrieve values for db connection for flow class to use:
_mongo_addr = _config.get_value("mongo_addr")
_mongo_port = _config.get_value("mongo_port")

logger = logging.getLogger(__name__)

#*** Test Switches and Switch classes that abstract OpenFlow switches:
def test_flow():
    #*** Packets for testing:

    #*** Flow 1 TCP handshake packet 1
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=5982511 TSecr=0 WS=64
    pkt1 = binascii.unhexlify("080027c8db910800272ad6dd08004510003c19fd400040060cab0a0100010a010002a9210050c37250d200000000a002721014330000020405b40402080a005b492f0000000001030306")
    pkt1_timestamp = 1458782847.829442000

    #*** Flow 1 TCP handshake packet 2
    # 10.1.0.2 10.1.0.1 TCP 74 http > 43297 [SYN, ACK] Seq=0 Ack=1 Win=28960 Len=0 MSS=1460 SACK_PERM=1 TSval=5977583 TSecr=5982511 WS=64
    pkt2 = binascii.unhexlify("0800272ad6dd080027c8db9108004500003c00004000400626b80a0100020a0100010050a9219e5c9d99c37250d3a0127120494a0000020405b40402080a005b35ef005b492f01030306")
    pkt2_timestamp = 1458782847.830399000

    #*** Flow 1 TCP handshake packet 3
    # 10.1.0.1 10.1.0.2 TCP 66 43297 > http [ACK] Seq=1 Ack=1 Win=29248 Len=0 TSval=5982512 TSecr=5977583
    pkt3 = binascii.unhexlify("080027c8db910800272ad6dd08004510003419fe400040060cb20a0100010a010002a9210050c37250d39e5c9d9a801001c9142b00000101080a005b4930005b35ef")
    pkt3_timestamp = 1458782847.830426000

    #*** Flow 1 client to server payload 1
    #  10.1.0.1 10.1.0.2 TCP 71 [TCP segment of a reassembled PDU]
    pkt4 = binascii.unhexlify("080027c8db910800272ad6dd08004510003919ff400040060cac0a0100010a010002a9210050c37250d39e5c9d9a801801c9143000000101080a005b4d59005b35ef4745540d0a")
    pkt4_timestamp = 1458782852.090698000

    #*** Flow 1 TCP ACK server to client
    # 10.1.0.2 10.1.0.1 TCP 66 http > 43297 [ACK] Seq=1 Ack=6 Win=28992 Len=0 TSval=5978648 TSecr=5983577
    pkt5 = binascii.unhexlify("0800272ad6dd080027c8db91080045000034a875400040067e4a0a0100020a0100010050a9219e5c9d9ac37250d8801001c5df1800000101080a005b3a18005b4d59")
    pkt5_timestamp = 1458782852.091542000

    #*** Flow 1 server to client response 
    # 10.1.0.2 10.1.0.1 HTTP 162 HTTP/1.1 400 Bad Request  (text/plain)
    pkt6 = binascii.unhexlify("0800272ad6dd080027c8db91080045000094a876400040067de90a0100020a0100010050a9219e5c9d9ac37250d8801801c5792f00000101080a005b3a18005b4d59485454502f312e31203430302042616420526571756573740d0a436f6e74656e742d4c656e6774683a2032320d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a0d0a4d616c666f726d656420526571756573742d4c696e65")
    pkt6_timestamp = 1458782852.091692000

    #*** Flow 1 client to server ACK
    # 10.1.0.1 10.1.0.2 TCP 66 43297 > http [ACK] Seq=6 Ack=97 Win=29248 Len=0 TSval=5983577 TSecr=5978648
    pkt7 = binascii.unhexlify("080027c8db910800272ad6dd0800451000341a00400040060cb00a0100010a010002a9210050c37250d89e5c9dfa801001c9142b00000101080a005b4d59005b3a18")
    pkt7_timestamp = 1458782852.091702000

    #*** Flow 2 TCP SYN used to test flow separation:
    # 10.1.0.1 10.1.0.2 TCP 74 43300 > http [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=7498808 TSecr=0 WS=64
    pkt_other = binascii.unhexlify("080027c8db910800272ad6dd08004510003c23df4000400602c90a0100010a010002a9240050ab094fe700000000a002721014330000020405b40402080a00726c380000000001030306")
    pkt_other_timestamp = 1458788913.014564000

    #*** Packet lengths on the wire (null value for index 0):
    pkt_len = [0, 74, 74, 66, 71, 66, 162, 66]

    #*** Sanity check can read into dpkt:
    eth = dpkt.ethernet.Ethernet(pkt1)
    eth_src = mac_addr(eth.src)
    assert eth_src == '08:00:27:2a:d6:dd'

    #*** Instantiate a flow object:
    flow = flow_class.Flow(logger, _mongo_addr, _mongo_port)

    #*** Test Flow Packet 1:
    flow.ingest_packet(pkt1, pkt1_timestamp)
    assert flow.packet_count  == 1
    assert flow.packet_length == pkt_len[1]
    assert flow.ip_src == '10.1.0.1'
    assert flow.ip_dst == '10.1.0.2'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 43297
    assert flow.tcp_dst == 80
    assert flow.packet_direction == 'c2s'
    assert flow.max_packet_size() == max(pkt_len[0:2])

    #*** Test Flow Packet 2:
    flow.ingest_packet(pkt2, pkt2_timestamp)
    assert flow.packet_count  == 2
    assert flow.packet_length == pkt_len[2]
    assert flow.ip_src == '10.1.0.2'
    assert flow.ip_dst == '10.1.0.1'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 80
    assert flow.tcp_dst == 43297
    assert flow.packet_direction == 's2c'
    assert flow.max_packet_size() == max(pkt_len[0:3])

    #*** Test Flow Packet 3:
    flow.ingest_packet(pkt3, pkt3_timestamp)
    assert flow.packet_count  == 3
    assert flow.packet_length == pkt_len[3]
    assert flow.ip_src == '10.1.0.1'
    assert flow.ip_dst == '10.1.0.2'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 43297
    assert flow.tcp_dst == 80
    assert flow.packet_direction == 'c2s'
    assert flow.max_packet_size() == max(pkt_len[0:4])

    #*** Random packet to ensure it doesn't count against flow 1:
    flow.ingest_packet(pkt_other, pkt_other_timestamp)

    #*** Test Flow Packet 4:
    flow.ingest_packet(pkt4, pkt4_timestamp)
    assert flow.packet_count  == 4
    assert flow.packet_length == pkt_len[4]
    assert flow.ip_src == '10.1.0.1'
    assert flow.ip_dst == '10.1.0.2'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 43297
    assert flow.tcp_dst == 80
    assert flow.packet_direction == 'c2s'
    assert flow.max_packet_size() == max(pkt_len[0:5])

    #*** Test Flow Packet 5:
    flow.ingest_packet(pkt5, pkt5_timestamp)
    assert flow.packet_count  == 5
    assert flow.packet_length == pkt_len[5]
    assert flow.ip_src == '10.1.0.2'
    assert flow.ip_dst == '10.1.0.1'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 80
    assert flow.tcp_dst == 43297
    assert flow.packet_direction == 's2c'
    assert flow.max_packet_size() == max(pkt_len[0:6])

    #*** Test Flow Packet 6:
    flow.ingest_packet(pkt6, pkt6_timestamp)
    assert flow.packet_count  == 6
    assert flow.packet_length == pkt_len[6]
    assert flow.ip_src == '10.1.0.2'
    assert flow.ip_dst == '10.1.0.1'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 80
    assert flow.tcp_dst == 43297
    assert flow.packet_direction == 's2c'
    assert flow.max_packet_size() == max(pkt_len[0:7])

    #*** Test Flow Packet 7:
    flow.ingest_packet(pkt7, pkt7_timestamp)
    assert flow.packet_count  == 7
    assert flow.packet_length == pkt_len[7]
    assert flow.ip_src == '10.1.0.1'
    assert flow.ip_dst == '10.1.0.2'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 43297
    assert flow.tcp_dst == 80
    assert flow.packet_direction == 'c2s'
    assert flow.max_packet_size() == max(pkt_len)

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
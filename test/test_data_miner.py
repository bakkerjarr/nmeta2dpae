"""
nmeta2dpae data_miner.py Unit Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, type in:
    py.test -vs

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
from flow import icmp_flow
from flow import tcp_flow
from flow import udp_flow
from data_miner import DataMiner

#*** Instantiate Config class:
_config = config.Config()

#======================== flow.py Unit Tests ============================
#*** Retrieve values for db connection for flow class to use:
_mongo_addr = _config.get_value("mongo_addr")
_mongo_port = _config.get_value("mongo_port")

logger = logging.getLogger(__name__)


def test_data_miner():
    """
    This test is used to ensure that a DataMiner object can return
    requested data.

    To create test packet data, capture packet in Wireshark and:

      For the packet summary:
        Right-click packet in top pane, Copy -> Summary (text).
        Edit pasted text as appropriate

      For the packet hex:
        Right-click packet in top pane, Copy -> Bytes -> Hex Stream

      For the packet timestamp:
        Expand 'Frame' in the middle pane,
        right-click 'Epoch Time' Copy -> Value
    """
    # Install flows into FCIP database collections
    _install_icmp_flows()
    _install_tcp_flows()
    _install_udp_flows()

    # Create DataMiner object
    data_miner = DataMiner(_config)

    # Unit tests for DataMiner requests
    _test_mine_bad_req(data_miner)
    _test_mine_unsupported_req(data_miner)
    # Unit tests for mining ICMP flow data
    _test_mine_missing_icmp(data_miner)
    _test_mine_success_icmp(data_miner)
    # Unit tests for mining TCP flow data
    _test_mine_missing_tcp(data_miner)
    _test_mine_success_tcp(data_miner)
    # Unit tests for mining TCP flow data
    _test_mine_missing_udp(data_miner)
    _test_mine_success_udp(data_miner)


def _test_mine_bad_req(data_miner):
    """Test that a DataMiner object gracefully handles improperly
    formatted requests.

    :param data_miner: DataMiner object to mine with.
    """
    # A request that is not a dict
    req = "This is not a Python dict."
    assert data_miner.mine_raw_data(req) == 0
    # An empty request
    req = {}
    assert data_miner.mine_raw_data(req) == 0
    # Requests with missing entries
    req = {"match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "proto": "tcp"}
    assert data_miner.mine_raw_data(req) == 0
    req = {"match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"]}
    assert data_miner.mine_raw_data(req) == 0
    req = {"proto": "tcp", "features": ["total_pkt_len_A",
                                          "total_pkt_len_B",
                                          "total_pkt_cnt_A",
                                          "total_pkt_cnt_B",
                                          "latest_timestamp",
                                          "packet_timestamps"]}
    assert data_miner.mine_raw_data(req) == 0
    # A request with too many entries
    req = {"match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"],
           "proto": "tcp", "another": "value!!"}
    assert data_miner.mine_raw_data(req) == 0
    # Requests with entries that are not the required type.
    req = {"match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"],
           "proto": 1}  # The proto entry should be a string
    assert data_miner.mine_raw_data(req) == 0
    req = {"match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "features": [],
           "proto": "tcp"}  # The features entry should not be empty
    assert data_miner.mine_raw_data(req) == 0
    req = {"match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "features": "total_pkt_len_A",
           "proto": "tcp"}  # The features entry should be a list
    assert data_miner.mine_raw_data(req) == 0
    req = {"match": {},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"],
           "proto": "tcp"}  # The match entry should not be empty
    assert data_miner.mine_raw_data(req) == 0
    req = {"match": "This should fail!",
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"],
           "proto": "tcp"}  # The features entry should be a dict
    assert data_miner.mine_raw_data(req) == 0


def _test_mine_unsupported_req(data_miner):
    """Test that a DataMiner object gracefully handled improperly
    unsupported requests.

    Unsupported requests contain values that a DataMiner object
    should not be able to handle.

    :param data_miner: DataMiner object to mine with.
    """
    # A request with an unsupported transport protocol: MPTCP
    req = {"match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"],
           "proto": "mptcp"}
    assert data_miner.mine_raw_data(req) == 0
    # A request with unsupported match values
    req = {"match": {"ip_A": "10.1.0.1", "ip_B": "10.1.0.2",
                     "port_A": 43297, "port_B": 80},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"],
           "proto": "tcp"}
    assert data_miner.mine_raw_data(req) == 0
    # A request with unsupported match values amongst supported match
    # values
    req = {"match": {"ip_A": "10.1.0.1", "ip_B": "10.1.0.2",
                     "port_A": 43297, "port_B": 80,
                     "hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"],
           "proto": "tcp"}
    assert data_miner.mine_raw_data(req) == 0
    # A request with unsupported features
    req = {"match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "features": ["this_does_not_exist"],
           "proto": "tcp"}
    assert data_miner.mine_raw_data(req) == 0
    # A request with unsupported features amongst supported features
    req = {"match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "features": ["this_does_not_exist", "latest_timestamp",
                        "packet_timestamps"],
           "proto": "tcp"}
    assert data_miner.mine_raw_data(req) == 0


def _test_mine_missing_icmp(data_miner):
    """Test that a DataMiner object can handle fetching ICMP flow
    information that does not exist..

    :param data_miner: DataMiner object to mine with.
    """
    req = {"proto": "icmp",
           "match": {"hash": "f33bcbe242c5190837aa87848f254a7f"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"]}

    dm_result = data_miner.mine_raw_data(req)
    assert type(dm_result) is dict
    assert len(dm_result) == 0


def _test_mine_success_icmp(data_miner):
    """Test that ICMP flow information can be successfully fetched.

    :param data_miner: DataMiner object to mine with.
    """
    req = {"proto": "icmp",
           "match": {"hash": "f33bcbe242c5190837aa87848f254a12"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"]}
    exp_tcp_result = {"total_pkt_len_A": 294, "total_pkt_len_B": 294,
                      "total_pkt_cnt_A": 3, "total_pkt_cnt_B": 3,
                      "latest_timestamp": 1475531008.074029,
                      "packet_timestamps": [1475531006.075766,
                                            1475531006.0759618,
                                            1475531007.074772,
                                            1475531007.0750225,
                                            1475531008.0737746,
                                            1475531008.074029]}
    dm_result = data_miner.mine_raw_data(req)
    assert type(dm_result) is dict
    assert cmp(exp_tcp_result, dm_result) == 0


def _test_mine_missing_tcp(data_miner):
    """Test that a DataMiner object can handle fetching TCP flow
    information that does not exist.

    :param data_miner: DataMiner object to mine with.
    """
    req = {"proto": "tcp",
           "match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3f5"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"]}

    dm_result = data_miner.mine_raw_data(req)
    assert type(dm_result) is dict
    assert len(dm_result) == 0


def _test_mine_success_tcp(data_miner):
    """Test that TCP flow information can be successfully fetched.

    :param data_miner: DataMiner object to mine with.
    """
    req = {"proto": "tcp",
           "match": {"hash": "3ac5055cc5d0073d1f0b3bc18d3fb3e3"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"]}
    exp_tcp_result = {"total_pkt_len_A": 277, "total_pkt_len_B": 302,
                      "total_pkt_cnt_A": 4, "total_pkt_cnt_B": 3,
                      "latest_timestamp": 1458782852.091702,
                      "packet_timestamps": [1458782847.829442,
                                            1458782847.830399,
                                            1458782847.830426,
                                            1458782852.090698,
                                            1458782852.091542,
                                            1458782852.091692,
                                            1458782852.091702]}
    dm_result = data_miner.mine_raw_data(req)
    assert type(dm_result) is dict
    assert cmp(exp_tcp_result, dm_result) == 0


def _test_mine_missing_udp(data_miner):
    """Test that a DataMiner object can handle fetching UDP flow
    information that does not exist.

    :param data_miner: DataMiner object to mine with.
    """
    req = {"proto": "udp",
           "match": {"hash": "a18e096b64d59bdbd6809f9bf083779b"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"]}

    dm_result = data_miner.mine_raw_data(req)
    assert type(dm_result) is dict
    assert len(dm_result) == 0


def _test_mine_success_udp(data_miner):
    """Test that UDP flow information can be successfully fetched.

    :param data_miner: DataMiner object to mine with.
    """
    req = {"proto": "udp",
           "match": {"hash": "a18e096b64d59bdbd6809f9bf08377ad"},
           "features": ["total_pkt_len_A", "total_pkt_len_B",
                        "total_pkt_cnt_A", "total_pkt_cnt_B",
                        "latest_timestamp", "packet_timestamps"]}
    exp_tcp_result = {"total_pkt_len_A": 316, "total_pkt_len_B": 291,
                      "total_pkt_cnt_A": 3, "total_pkt_cnt_B": 3,
                      "latest_timestamp": 1475534725.4327881,
                      "packet_timestamps": [1475534554.8924124,
                                            1475534576.7033346,
                                            1475534615.6989126,
                                            1475534641.599546,
                                            1475534698.5478644,
                                            1475534725.4327881]}
    dm_result = data_miner.mine_raw_data(req)
    assert type(dm_result) is dict
    assert cmp(exp_tcp_result, dm_result) == 0


def _install_icmp_flows():
    """Insert some ICMP flows into the fcip_icmp collection and check
    their validity.
    """
    #*** Flow 1 ECHO request 1
    # 1	0.000000000	172.16.0.10	172.16.0.101	ICMP	98	Echo (ping) request  id=0x0d3a, seq=1/256, ttl=64 (reply in 2)
    flow1_pkt1 = binascii.unhexlify("0800278801300800278a923b080045000054c012400040012207ac10000aac10006508004ca10d3a0001fed0f25700000000ed27010000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
    flow1_pkt1_timestamp = 1475531006.075766189

    #*** Flow 1 ECHO reply 1
    # 2	0.000195755	172.16.0.101	172.16.0.10	ICMP	98	Echo (ping) reply    id=0x0d3a, seq=1/256, ttl=64 (request in 1)
    flow1_pkt2 = binascii.unhexlify("0800278a923b080027880130080045000054f8320000400129e7ac100065ac10000a000054a10d3a0001fed0f25700000000ed27010000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
    flow1_pkt2_timestamp = 1475531006.075961944

    #*** Flow 1 ECHO request 2
    # 3	0.999005806	172.16.0.10	172.16.0.101	ICMP	98	Echo (ping) request  id=0x0d3a, seq=2/512, ttl=64 (reply in 4)
    flow1_pkt3 = binascii.unhexlify("0800278801300800278a923b080045000054c102400040012117ac10000aac100065080032a40d3a0002ffd0f257000000000624010000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
    flow1_pkt3_timestamp = 1475531007.074771995

    #*** Flow 1 ECHO reply 2
    # 4	0.999256251	172.16.0.101	172.16.0.10	ICMP	98	Echo (ping) reply    id=0x0d3a, seq=2/512, ttl=64 (request in 3)
    flow1_pkt4 = binascii.unhexlify("0800278a923b080027880130080045000054f86a0000400129afac100065ac10000a00003aa40d3a0002ffd0f257000000000624010000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
    flow1_pkt4_timestamp = 1475531007.075022440

    #*** Flow 1 ECHO request 3
    # 5	1.998008329	172.16.0.10	172.16.0.101	ICMP	98	Echo (ping) request  id=0x0d3a, seq=3/768, ttl=64 (reply in 6)
    flow1_pkt5 = binascii.unhexlify("0800278801300800278a923b080045000054c16b4000400120aeac10000aac100065080017a70d3a000300d1f257000000002020010000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
    flow1_pkt5_timestamp = 1475531008.073774518

    #*** Flow 1 ECHO reply 3
    # 6	1.998262748	172.16.0.101	172.16.0.10	ICMP	98	Echo (ping) reply    id=0x0d3a, seq=3/768, ttl=64 (request in 5)
    flow1_pkt6 = binascii.unhexlify("0800278a923b080027880130080045000054f905000040012914ac100065ac10000a00001fa70d3a000300d1f257000000002020010000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
    flow1_pkt6_timestamp = 1475531008.074028937

    #*** Packet lengths for flow 1 on the wire (null value for index 0):
    pkt_len = [0, 98, 98, 98, 98, 98, 98]

    #*** Sanity check can read into dpkt:
    eth = dpkt.ethernet.Ethernet(flow1_pkt1)
    eth_src = _mac_addr(eth.src)
    assert eth_src == '08:00:27:8a:92:3b'

    #*** Instantiate a flow object:
    flow = icmp_flow.ICMPFlow(logger, _mongo_addr, _mongo_port)

    #*** Test Flow 1 Packet 1:
    flow.ingest_packet(flow1_pkt1, flow1_pkt1_timestamp)
    assert flow.packet_count == 1
    assert flow.packet_length == pkt_len[1]
    assert flow.ip_src == "172.16.0.10"
    assert flow.ip_dst == "172.16.0.101"
    assert flow.client == "172.16.0.10"
    assert flow.server == "172.16.0.101"
    assert flow.icmp_type == 8
    assert flow.icmp_code == 0
    assert flow.packet_direction == 'c2s'

    #*** Test Flow 1 Packet 2:
    flow.ingest_packet(flow1_pkt2, flow1_pkt2_timestamp)
    assert flow.packet_count == 2
    assert flow.packet_length == pkt_len[2]
    assert flow.ip_src == "172.16.0.101"
    assert flow.ip_dst == "172.16.0.10"
    assert flow.client == "172.16.0.10"
    assert flow.server == "172.16.0.101"
    assert flow.icmp_type == 0
    assert flow.icmp_code == 0
    assert flow.packet_direction == 's2c'

    #*** Test Flow 1 Packet 3:
    flow.ingest_packet(flow1_pkt3, flow1_pkt3_timestamp)
    assert flow.packet_count == 3
    assert flow.packet_length == pkt_len[3]
    assert flow.ip_src == "172.16.0.10"
    assert flow.ip_dst == "172.16.0.101"
    assert flow.client == "172.16.0.10"
    assert flow.server == "172.16.0.101"
    assert flow.icmp_type == 8
    assert flow.icmp_code == 0
    assert flow.packet_direction == 'c2s'

    #*** Test Flow 1 Packet 4:
    flow.ingest_packet(flow1_pkt4, flow1_pkt4_timestamp)
    assert flow.packet_count == 4
    assert flow.packet_length == pkt_len[4]
    assert flow.ip_src == "172.16.0.101"
    assert flow.ip_dst == "172.16.0.10"
    assert flow.client == "172.16.0.10"
    assert flow.server == "172.16.0.101"
    assert flow.icmp_type == 0
    assert flow.icmp_code == 0
    assert flow.packet_direction == 's2c'

    #*** Test Flow 1 Packet 5:
    flow.ingest_packet(flow1_pkt5, flow1_pkt5_timestamp)
    assert flow.packet_count == 5
    assert flow.packet_length == pkt_len[5]
    assert flow.ip_src == "172.16.0.10"
    assert flow.ip_dst == "172.16.0.101"
    assert flow.client == "172.16.0.10"
    assert flow.server == "172.16.0.101"
    assert flow.icmp_type == 8
    assert flow.icmp_code == 0
    assert flow.packet_direction == 'c2s'

    #*** Test Flow 1 Packet 6:
    flow.ingest_packet(flow1_pkt6, flow1_pkt6_timestamp)
    assert flow.packet_count == 6
    assert flow.packet_length == pkt_len[6]
    assert flow.ip_src == "172.16.0.101"
    assert flow.ip_dst == "172.16.0.10"
    assert flow.client == "172.16.0.10"
    assert flow.server == "172.16.0.101"
    assert flow.icmp_type == 0
    assert flow.icmp_code == 0
    assert flow.packet_direction == 's2c'


def _install_tcp_flows():
    """Insert some TCP flows into the fcip_tcp collection and check
    their validity.
    """
    #*** Flow 1 TCP handshake packet 1
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=5982511 TSecr=0 WS=64
    flow1_pkt1 = binascii.unhexlify("080027c8db910800272ad6dd08004510003c19fd400040060cab0a0100010a010002a9210050c37250d200000000a002721014330000020405b40402080a005b492f0000000001030306")
    flow1_pkt1_timestamp = 1458782847.829442000

    #*** Flow 1 TCP handshake packet 2
    # 10.1.0.2 10.1.0.1 TCP 74 http > 43297 [SYN, ACK] Seq=0 Ack=1 Win=28960 Len=0 MSS=1460 SACK_PERM=1 TSval=5977583 TSecr=5982511 WS=64
    flow1_pkt2 = binascii.unhexlify("0800272ad6dd080027c8db9108004500003c00004000400626b80a0100020a0100010050a9219e5c9d99c37250d3a0127120494a0000020405b40402080a005b35ef005b492f01030306")
    flow1_pkt2_timestamp = 1458782847.830399000

    #*** Flow 1 TCP handshake packet 3
    # 10.1.0.1 10.1.0.2 TCP 66 43297 > http [ACK] Seq=1 Ack=1 Win=29248 Len=0 TSval=5982512 TSecr=5977583
    flow1_pkt3 = binascii.unhexlify("080027c8db910800272ad6dd08004510003419fe400040060cb20a0100010a010002a9210050c37250d39e5c9d9a801001c9142b00000101080a005b4930005b35ef")
    flow1_pkt3_timestamp = 1458782847.830426000

    #*** Flow 1 client to server payload 1
    #  10.1.0.1 10.1.0.2 TCP 71 [TCP segment of a reassembled PDU] [PSH + ACK]
    flow1_pkt4 = binascii.unhexlify("080027c8db910800272ad6dd08004510003919ff400040060cac0a0100010a010002a9210050c37250d39e5c9d9a801801c9143000000101080a005b4d59005b35ef4745540d0a")
    flow1_pkt4_timestamp = 1458782852.090698000

    #*** Flow 1 TCP ACK server to client
    # 10.1.0.2 10.1.0.1 TCP 66 http > 43297 [ACK] Seq=1 Ack=6 Win=28992 Len=0 TSval=5978648 TSecr=5983577
    flow1_pkt5 = binascii.unhexlify("0800272ad6dd080027c8db91080045000034a875400040067e4a0a0100020a0100010050a9219e5c9d9ac37250d8801001c5df1800000101080a005b3a18005b4d59")
    flow1_pkt5_timestamp = 1458782852.091542000

    #*** Flow 1 server to client response 
    # 10.1.0.2 10.1.0.1 HTTP 162 HTTP/1.1 400 Bad Request  (text/plain)  [PSH + ACK]
    flow1_pkt6 = binascii.unhexlify("0800272ad6dd080027c8db91080045000094a876400040067de90a0100020a0100010050a9219e5c9d9ac37250d8801801c5792f00000101080a005b3a18005b4d59485454502f312e31203430302042616420526571756573740d0a436f6e74656e742d4c656e6774683a2032320d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a0d0a4d616c666f726d656420526571756573742d4c696e65")
    flow1_pkt6_timestamp = 1458782852.091692000

    #*** Flow 1 client to server ACK
    # 10.1.0.1 10.1.0.2 TCP 66 43297 > http [ACK] Seq=6 Ack=97 Win=29248 Len=0 TSval=5983577 TSecr=5978648
    flow1_pkt7 = binascii.unhexlify("080027c8db910800272ad6dd0800451000341a00400040060cb00a0100010a010002a9210050c37250d89e5c9dfa801001c9142b00000101080a005b4d59005b3a18")
    flow1_pkt7_timestamp = 1458782852.091702000

    #*** Flow 2 TCP SYN used to test flow separation:
    # 10.1.0.1 10.1.0.2 TCP 74 43300 > http [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=7498808 TSecr=0 WS=64
    flow2_pkt1 = binascii.unhexlify("080027c8db910800272ad6dd08004510003c23df4000400602c90a0100010a010002a9240050ab094fe700000000a002721014330000020405b40402080a00726c380000000001030306")
    flow2_pkt1_timestamp = 1458788913.014564000

    #*** Packet lengths for flow 1 on the wire (null value for index 0):
    pkt_len = [0, 74, 74, 66, 71, 66, 162, 66]

    #*** Sanity check can read into dpkt:
    eth = dpkt.ethernet.Ethernet(flow1_pkt1)
    eth_src = _mac_addr(eth.src)
    assert eth_src == '08:00:27:2a:d6:dd'

    #*** Instantiate a flow object:
    flow = tcp_flow.TCPFlow(logger, _mongo_addr, _mongo_port)

    #*** Test Flow 1 Packet 1:
    flow.ingest_packet(flow1_pkt1, flow1_pkt1_timestamp)
    assert flow.packet_count  == 1
    assert flow.packet_length == pkt_len[1]
    assert flow.ip_src == '10.1.0.1'
    assert flow.ip_dst == '10.1.0.2'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 43297
    assert flow.tcp_dst == 80
    assert flow.tcp_seq == 3279048914
    assert flow.tcp_acq == 0
    assert flow.tcp_syn() == 1
    assert flow.tcp_fin() == 0
    assert flow.tcp_rst() == 0
    assert flow.tcp_psh() == 0
    assert flow.tcp_ack() == 0
    assert flow.payload == ""
    assert flow.packet_direction == 'c2s'
    assert flow.verified_direction == 'verified-SYN'
    assert flow.max_packet_size() == max(pkt_len[0:2])

    #*** Test Flow 1 Packet 2:
    flow.ingest_packet(flow1_pkt2, flow1_pkt2_timestamp)
    assert flow.packet_count  == 2
    assert flow.packet_length == pkt_len[2]
    assert flow.ip_src == '10.1.0.2'
    assert flow.ip_dst == '10.1.0.1'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 80
    assert flow.tcp_dst == 43297
    assert flow.tcp_seq == 2656869785
    assert flow.tcp_acq == 3279048915
    assert flow.tcp_fin() == 0
    assert flow.tcp_syn() == 1
    assert flow.tcp_rst() == 0
    assert flow.tcp_psh() == 0
    assert flow.tcp_ack() == 1
    assert flow.payload == ""
    assert flow.packet_direction == 's2c'
    assert flow.verified_direction == 'verified-SYN'
    assert flow.max_packet_size() == max(pkt_len[0:3])

    #*** Test Flow 1 Packet 3:
    flow.ingest_packet(flow1_pkt3, flow1_pkt3_timestamp)
    assert flow.packet_count  == 3
    assert flow.packet_length == pkt_len[3]
    assert flow.ip_src == '10.1.0.1'
    assert flow.ip_dst == '10.1.0.2'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 43297
    assert flow.tcp_dst == 80
    assert flow.tcp_seq == 3279048915
    assert flow.tcp_acq == 2656869786
    assert flow.tcp_fin() == 0
    assert flow.tcp_syn() == 0
    assert flow.tcp_rst() == 0
    assert flow.tcp_psh() == 0
    assert flow.tcp_ack() == 1
    assert flow.payload == ""
    assert flow.packet_direction == 'c2s'
    assert flow.verified_direction == 'verified-SYN'
    assert flow.max_packet_size() == max(pkt_len[0:4])

    #*** Random packet to ensure it doesn't count against flow 1:
    flow.ingest_packet(flow2_pkt1, flow2_pkt1_timestamp)

    #*** Test Flow 1 Packet 4:
    flow.ingest_packet(flow1_pkt4, flow1_pkt4_timestamp)
    assert flow.packet_count  == 4
    assert flow.packet_length == pkt_len[4]
    assert flow.ip_src == '10.1.0.1'
    assert flow.ip_dst == '10.1.0.2'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 43297
    assert flow.tcp_dst == 80
    assert flow.tcp_seq == 3279048915
    assert flow.tcp_acq == 2656869786
    assert flow.tcp_fin() == 0
    assert flow.tcp_syn() == 0
    assert flow.tcp_rst() == 0
    assert flow.tcp_psh() == 1
    assert flow.tcp_ack() == 1
    assert flow.payload == "GET\r\n"
    assert flow.packet_direction == 'c2s'
    assert flow.verified_direction == 'verified-SYN'
    assert flow.max_packet_size() == max(pkt_len[0:5])

    #*** Test Flow 1 Packet 5:
    flow.ingest_packet(flow1_pkt5, flow1_pkt5_timestamp)
    assert flow.packet_count  == 5
    assert flow.packet_length == pkt_len[5]
    assert flow.ip_src == '10.1.0.2'
    assert flow.ip_dst == '10.1.0.1'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 80
    assert flow.tcp_dst == 43297
    assert flow.tcp_seq == 2656869786
    assert flow.tcp_acq == 3279048920
    assert flow.tcp_fin() == 0
    assert flow.tcp_syn() == 0
    assert flow.tcp_rst() == 0
    assert flow.tcp_psh() == 0
    assert flow.tcp_ack() == 1
    assert flow.payload == ""
    assert flow.packet_direction == 's2c'
    assert flow.verified_direction == 'verified-SYN'
    assert flow.max_packet_size() == max(pkt_len[0:6])

    #*** Test Flow 1 Packet 6:
    flow.ingest_packet(flow1_pkt6, flow1_pkt6_timestamp)
    assert flow.packet_count  == 6
    assert flow.packet_length == pkt_len[6]
    assert flow.ip_src == '10.1.0.2'
    assert flow.ip_dst == '10.1.0.1'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 80
    assert flow.tcp_dst == 43297
    assert flow.tcp_seq == 2656869786
    assert flow.tcp_acq == 3279048920
    assert flow.tcp_fin() == 0
    assert flow.tcp_syn() == 0
    assert flow.tcp_rst() == 0
    assert flow.tcp_psh() == 1
    assert flow.tcp_ack() == 1
    #*** Convert payload back to hex for comparison:
    assert flow.payload.encode("hex") == "485454502f312e31203430302042616420526571756573740d0a436f6e74656e742d4c656e6774683a2032320d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a0d0a4d616c666f726d656420526571756573742d4c696e65"
    assert flow.packet_direction == 's2c'
    assert flow.verified_direction == 'verified-SYN'
    assert flow.max_packet_size() == max(pkt_len[0:7])

    #*** Test Flow 1 Packet 7:
    flow.ingest_packet(flow1_pkt7, flow1_pkt7_timestamp)
    assert flow.packet_count  == 7
    assert flow.packet_length == pkt_len[7]
    assert flow.ip_src == '10.1.0.1'
    assert flow.ip_dst == '10.1.0.2'
    assert flow.client == '10.1.0.1'
    assert flow.server == '10.1.0.2'
    assert flow.tcp_src == 43297
    assert flow.tcp_dst == 80
    assert flow.tcp_seq == 3279048920
    assert flow.tcp_acq == 2656869882
    assert flow.tcp_fin() == 0
    assert flow.tcp_syn() == 0
    assert flow.tcp_rst() == 0
    assert flow.tcp_psh() == 0
    assert flow.tcp_ack() == 1
    assert flow.payload == ""
    assert flow.packet_direction == 'c2s'
    assert flow.verified_direction == 'verified-SYN'
    assert flow.max_packet_size() == max(pkt_len)


def _install_udp_flows():
    """Insert some UDP flows into the fcip_udp collection and check
    their validity.
    """
    #*** Flow 1 client->server
    # 1	0.000000000	172.16.0.101	172.16.0.10	UDP	98	51199 -> 45123  Len=56
    flow1_pkt1 = binascii.unhexlify("0800278a923b0800278801300800450000549d08400040114501ac100065ac10000ac7ffb0430040adaf436c69656e742d3e5365727665723a20436f6e6e656374656420776974683a206e63202d75203137322e31362e302e31302034353132330a")
    flow1_pkt1_timestamp = 1475534554.892412520

    #*** Flow 1 server->client
    # 2	21.810922060	172.16.0.10	172.16.0.101	UDP	87	45123 -> 51199  Len=45
    flow1_pkt2 = binascii.unhexlify("0800278801300800278a923b0800450000493d9040004011a484ac10000aac100065b043c7ff003558d65365727665722d3e436c69656e743a20486f7374696e6720776974683a206e63202d75202d6c2034353132330a")
    flow1_pkt2_timestamp = 1475534576.703334580

    #*** Flow 1 client->server
    # 3	60.806499993	172.16.0.101	172.16.0.10	UDP	77	51199 -> 45123  Len=35
    flow1_pkt3 = binascii.unhexlify("0800278a923b08002788013008004500003fd85a4000401109c4ac100065ac10000ac7ffb043002b0392436c69656e742d3e5365727665723a206e657463617420697320617765736f6d65210a")
    flow1_pkt3_timestamp = 1475534615.698912513

    #*** Flow 1 server->client
    # 4	86.707133477	172.16.0.10	172.16.0.101	UDP	105	45123 -> 51199  Len=63
    flow1_pkt4 = binascii.unhexlify("0800278801300800278a923b08004500005b4abe400040119744ac10000aac100065b043c7ff004758e85365727665722d3e436c69656e743a20492061677265652120497420697320736f206561737920746f2073656e642064617461207573696e67205544502e0a")
    flow1_pkt4_timestamp = 1475534641.599545997

    #*** Flow 1 client->server
    # 5	143.655451995	172.16.0.101	172.16.0.10	UDP	141	51199 -> 45123  Len=99
    flow1_pkt5 = binascii.unhexlify("0800278a923b08002788013008004500007fec6c40004011f571ac100065ac10000ac7ffb043006b7d36436c69656e742d3e5365727665723a2045786163746c792c20686f77657665722074686520666c6f77206475726174696f6e2077696c6c206265206c6f6e672061732069742074616b65732074696d6520746f2074797065206d657373616765732e0a")
    flow1_pkt5_timestamp = 1475534698.547864515

    #*** Flow 1 server->client
    # 6	170.540375720	172.16.0.10	172.16.0.101	UDP	99	45123 -> 51199  Len=57
    flow1_pkt6 = binascii.unhexlify("0800278801300800278a923b08004500005559524000401188b6ac10000aac100065b043c7ff004158e25365727665722d3e436c69656e743a205468617420697320646f65732e20436c6f73696e672073657276657220636f6e6e656374696f6e2e0a")
    flow1_pkt6_timestamp = 1475534725.432788240

    #*** Packet lengths for flow 1 on the wire (null value for index 0):
    pkt_len = [0, 98, 87, 77, 105, 141, 99]

    #*** Sanity check can read into dpkt:
    eth = dpkt.ethernet.Ethernet(flow1_pkt1)
    eth_src = _mac_addr(eth.src)
    assert eth_src == '08:00:27:88:01:30'

    #*** Instantiate a flow object:
    flow = udp_flow.UDPFlow(logger, _mongo_addr, _mongo_port)

    #*** Test Flow 1 Packet 1:
    flow.ingest_packet(flow1_pkt1, flow1_pkt1_timestamp)
    assert flow.packet_count == 1
    assert flow.packet_length == pkt_len[1]
    assert flow.ip_src == "172.16.0.101"
    assert flow.ip_dst == "172.16.0.10"
    assert flow.client == "172.16.0.101"
    assert flow.server == "172.16.0.10"
    assert flow.udp_src == 51199
    assert flow.udp_dst == 45123
    assert flow.packet_direction == 'c2s'
    assert flow.payload == "Client->Server: Connected with: nc -u " \
                           "172.16.0.10 45123\n"

    #*** Test Flow 1 Packet 2:
    flow.ingest_packet(flow1_pkt2, flow1_pkt2_timestamp)
    assert flow.packet_count == 2
    assert flow.packet_length == pkt_len[2]
    assert flow.ip_src == "172.16.0.10"
    assert flow.ip_dst == "172.16.0.101"
    assert flow.client == "172.16.0.101"
    assert flow.server == "172.16.0.10"
    assert flow.udp_src == 45123
    assert flow.udp_dst == 51199
    assert flow.packet_direction == 's2c'
    assert flow.payload == "Server->Client: Hosting with: nc -u -l " \
                           "45123\n"

    #*** Test Flow 1 Packet 3:
    flow.ingest_packet(flow1_pkt3, flow1_pkt3_timestamp)
    assert flow.packet_count == 3
    assert flow.packet_length == pkt_len[3]
    assert flow.ip_src == "172.16.0.101"
    assert flow.ip_dst == "172.16.0.10"
    assert flow.client == "172.16.0.101"
    assert flow.server == "172.16.0.10"
    assert flow.udp_src == 51199
    assert flow.udp_dst == 45123
    assert flow.packet_direction == 'c2s'
    assert flow.payload == "Client->Server: netcat is awesome!\n"

    #*** Test Flow 1 Packet 4:
    flow.ingest_packet(flow1_pkt4, flow1_pkt4_timestamp)
    assert flow.packet_count == 4
    assert flow.packet_length == pkt_len[4]
    assert flow.ip_src == "172.16.0.10"
    assert flow.ip_dst == "172.16.0.101"
    assert flow.client == "172.16.0.101"
    assert flow.server == "172.16.0.10"
    assert flow.udp_src == 45123
    assert flow.udp_dst == 51199
    assert flow.packet_direction == 's2c'
    assert flow.payload == "Server->Client: I agree! It is so easy to " \
                           "send data using UDP.\n"

    #*** Test Flow 1 Packet 5:
    flow.ingest_packet(flow1_pkt5, flow1_pkt5_timestamp)
    assert flow.packet_count == 5
    assert flow.packet_length == pkt_len[5]
    assert flow.ip_src == "172.16.0.101"
    assert flow.ip_dst == "172.16.0.10"
    assert flow.client == "172.16.0.101"
    assert flow.server == "172.16.0.10"
    assert flow.udp_src == 51199
    assert flow.udp_dst == 45123
    assert flow.packet_direction == 'c2s'
    assert flow.payload == "Client->Server: Exactly, however the flow " \
                           "duration will be long as it takes time to " \
                           "type messages.\n"

    #*** Test Flow 1 Packet 6:
    flow.ingest_packet(flow1_pkt6, flow1_pkt6_timestamp)
    assert flow.packet_count == 6
    assert flow.packet_length == pkt_len[6]
    assert flow.ip_src == "172.16.0.10"
    assert flow.ip_dst == "172.16.0.101"
    assert flow.client == "172.16.0.101"
    assert flow.server == "172.16.0.10"
    assert flow.udp_src == 45123
    assert flow.udp_dst == 51199
    assert flow.packet_direction == 's2c'
    assert flow.payload == "Server->Client: That is does. Closing " \
                           "server connection.\n"


def _mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)

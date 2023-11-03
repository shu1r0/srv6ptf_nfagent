from unittest import TestCase, main
from logging import getLogger
from scapy.all import *
from json import dumps

from nfagent.collector_grpc.collector_client import PacketCollectorClient

from srv6_ping.ping import ping1, new_srh_tlv


class TestSRv6PacketWithClient(TestCase):

    def setUp(self) -> None:
        """start gRPC client"""
        self.client = PacketCollectorClient(ip="192.168.10.1", port="31000", node_id=1, node_id_length=16,
                                            logger=getLogger(__name__),
                                            counter_length=32,
                                            enable_stats=True)
        self.client.establish_channel()

        def notify_packet_handler(data):
            print("***** Received Packet from agent *****")
            # print(data)
            # pkt = Ether(data["data"])
            # if IPv6ExtHdrSegmentRoutingTLV in pkt:
            #     pkt[IPv6ExtHdrSegmentRoutingTLV].show()

        def notify_packetid_handler(data):
            print("***** Received PacketId from agent *****")
            # print(data)

        def client_start():
            loop = self.client.event_loop
            loop.run_until_complete(
                self.client.notify_packet_info_coro(notify_packet_handler, notify_packetid_handler, True))

        self.client_thread = threading.Thread(target=client_start)
        self.client_thread.start()

    def test_srv6_ping(self):
        results = []
        print("Send packets ...")
        for _ in range(3):
            result = ping1(dst="2001:db8:20::2", hlim=64, return_pkt=True)
            if result:
                results.append(result)

        # echo reply
        self.assertTrue(len(results) > 0)
        print("Received packets: {}".format(results))
        if len(results) > 0:
            for result in results:
                self.assertEqual("EchoReply", result["msg"])
                # check return_pkt
                self.assertTrue(result["sent_pkt"][IPv6].src == result["recv_pkt"][IPv6].dst)

        tlv = new_srh_tlv(type=124, value='\x00\x18\x00\x00\x00\x08')
        result = ping1(dst="2001:db8:20::2", hlim=64, srh_tlvs=[tlv])
        self.assertEqual("EchoReply", result["msg"])

    def test_many_ping(self):
        results = []
        print("Send packet 501 times ...")
        for _ in range(501):
            result = ping1(dst="2001:db8:20::2", hlim=64, return_pkt=True)
            if result:
                results.append(result)
        self.assertAlmostEqual(500, len(results), places=1)
        self.assertAlmostEqual(500, self.client.stats.get("message_count", -1), places=3)

    def tearDown(self) -> None:
        self.client.close_channel()
        self.client_thread.join(1)

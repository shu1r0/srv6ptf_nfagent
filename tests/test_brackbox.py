from unittest import TestCase, main
from scapy.all import *
from json import dumps


from srv6_ping.ping import ping1
from srv6_ping.utils import new_srh_tlv


class TestSPacket(TestCase):
    
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
        self.assertAlmostEqual(500, len(results), places=2)
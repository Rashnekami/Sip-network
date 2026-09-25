import unittest
from sip_network.models import Packet
from sip_network.sip import extract_sip_messages


class TcpSipTests(unittest.TestCase):
    def test_reassembly(self):
        text=("INVITE sip:b@example SIP/2.0\r\nVia: SIP/2.0/TCP 10.0.0.1;branch=z\r\n"
              "From: <sip:a@example>;tag=1\r\nTo: <sip:b@example>\r\nCall-ID: tcp1\r\n"
              "CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n").encode()
        cut=40
        a=Packet(1,1,100,100,1,"10.0.0.1","10.0.0.2","TCP",5060,5060,text[:cut],ip_version=4,tcp_seq=1000)
        b=Packet(2,1.01,100,100,1,"10.0.0.1","10.0.0.2","TCP",5060,5060,text[cut:],ip_version=4,tcp_seq=1000+cut)
        msgs=extract_sip_messages([a,b])
        self.assertEqual(len(msgs),1)
        self.assertEqual(msgs[0].call_id,"tcp1")
        self.assertEqual(msgs[0].method,"INVITE")

if __name__ == "__main__": unittest.main()

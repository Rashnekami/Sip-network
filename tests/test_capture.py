import struct
import unittest

from sip_network.capture import read_capture


def build_pcap_udp():
    # Ethernet + IPv4 + UDP + 4 bytes payload
    eth = b"\x00"*12 + b"\x08\x00"
    src=b"\x0a\x00\x00\x01"; dst=b"\x0a\x00\x00\x02"
    udp=struct.pack("!HHHH",5060,5060,12,0)+b"test"
    total=20+len(udp)
    ip=bytes([0x45,0])+struct.pack("!H",total)+b"\x00\x01\x00\x00\x40\x11\x00\x00"+src+dst
    frame=eth+ip+udp
    gh=b"\xd4\xc3\xb2\xa1"+struct.pack("<HHiIII",2,4,0,0,65535,1)
    ph=struct.pack("<IIII",1,500000,len(frame),len(frame))
    return gh+ph+frame


class CaptureTests(unittest.TestCase):
    def test_classic_pcap(self):
        ps=read_capture(build_pcap_udp())
        self.assertEqual(len(ps),1)
        self.assertEqual(ps[0].src_ip,"10.0.0.1")
        self.assertEqual(ps[0].dst_port,5060)
        self.assertEqual(ps[0].payload,b"test")
        self.assertAlmostEqual(ps[0].timestamp,1.5)

if __name__ == "__main__": unittest.main()

import struct
import unittest
from sip_network.capture import read_capture


def pad4(b):
    return b + b"\x00" * ((-len(b)) % 4)


def block(bt, body):
    body = pad4(body)
    total = 12 + len(body)
    return struct.pack("<II", bt, total) + body + struct.pack("<I", total)


def pcapng_one_udp():
    shb_body = b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1)
    shb = block(0x0A0D0D0A, shb_body)
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    eth = b"\x00"*12+b"\x08\x00"
    src=b"\xc0\xa8\x01\x01"; dst=b"\xc0\xa8\x01\x02"
    udp=struct.pack("!HHHH",10000,10002,12,0)+b"abcd"
    ip=bytes([0x45,0])+struct.pack("!H",20+len(udp))+b"\x00\x01\x00\x00\x40\x11\x00\x00"+src+dst
    frame=eth+ip+udp
    ts=1_500_000
    epb_body=struct.pack("<IIIII",0,0,ts,len(frame),len(frame))+frame
    epb=block(6,epb_body)
    return shb+idb+epb


class PcapNgTests(unittest.TestCase):
    def test_epb(self):
        ps=read_capture(pcapng_one_udp())
        self.assertEqual(len(ps),1)
        self.assertEqual(ps[0].src_ip,"192.168.1.1")
        self.assertEqual(ps[0].src_port,10000)
        self.assertAlmostEqual(ps[0].timestamp,1.5)

if __name__ == "__main__": unittest.main()

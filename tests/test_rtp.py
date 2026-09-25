import struct
import unittest

from sip_network.models import Packet
from sip_network.rtp import analyze_rtp


def rtp(seq, ts, ssrc=1234, pt=0, payload=b"x"*160):
    return struct.pack("!BBHII", 0x80, pt, seq, ts, ssrc) + payload


def pkt(n, t, seq, ts):
    return Packet(n, t, 200, 200, 1, "10.0.0.1", "10.0.0.2", "UDP", 40000, 40002, rtp(seq, ts), ip_version=4)


class RtpTests(unittest.TestCase):
    def test_rollover_no_loss(self):
        ps = [pkt(1, 0.00, 65534, 0), pkt(2, 0.02, 65535, 160), pkt(3, 0.04, 0, 320), pkt(4, 0.06, 1, 480)]
        s = analyze_rtp(ps, [])[0]
        self.assertEqual(s.lost_packets, 0)
        self.assertEqual(s.expected_packets, 4)
        self.assertEqual(s.unique_packets, 4)

    def test_loss_is_counted(self):
        ps = [pkt(1, 0.00, 10, 0), pkt(2, 0.02, 11, 160), pkt(3, 0.06, 13, 480), pkt(4, 0.08, 14, 640)]
        s = analyze_rtp(ps, [])[0]
        self.assertEqual(s.lost_packets, 1)
        self.assertAlmostEqual(s.loss_percent, 20.0, places=2)

    def test_constant_spacing_jitter_near_zero(self):
        ps = [pkt(i+1, i*0.02, 100+i, i*160) for i in range(20)]
        s = analyze_rtp(ps, [])[0]
        self.assertLess(s.jitter_ms, 0.01)

    def test_duplicate_not_received_as_unique(self):
        ps = [pkt(1,0,1,0), pkt(2,.02,2,160), pkt(3,.021,2,160), pkt(4,.04,3,320)]
        s = analyze_rtp(ps, [])[0]
        self.assertEqual(s.duplicates, 1)
        self.assertEqual(s.unique_packets, 3)

if __name__ == "__main__": unittest.main()

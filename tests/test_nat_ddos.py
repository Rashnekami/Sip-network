import struct
import unittest

from sip_network import analyze_bytes

from pcapgen import Sip, basic_call, ether, ipv4, pcap, rtp_flow, sdp, udp_frame

PRIV, NAT_PUB, SRV = "192.168.1.10", "177.10.0.5", "200.1.1.1"


def types(items):
    return {x["type"] for x in items}


def tcp_syn(src, dst, sport, dport):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x02, 65535, 0, 0)
    return ether(ipv4(src, dst, tcp, proto=6))


def nat_call(one_way=True):
    """Phone at 192.168.1.10 behind a router whose public address is 177.10.0.5; SIP/SDP still carry the private IP."""
    s = Sip("nat-1", PRIV, SRV)
    out = lambda t, p: (t, udp_frame(NAT_PUB, SRV, 5060, 5060, p))
    back = lambda t, p: (t, udp_frame(SRV, NAT_PUB, 5060, 5060, p))
    f = [out(1.0, s.request("INVITE", 1, body=sdp(PRIV, 40000))),
         back(1.1, s.response(180, "Ringing", 1, to_tag="b1")),
         back(2.0, s.response(200, "OK", 1, to_tag="b1", body=sdp(SRV, 50000))),
         out(2.05, s.request("ACK", 1, to_tag="b1"))]
    f += rtp_flow(NAT_PUB, SRV, 40000, 50000, 2.1, 200, ssrc=11)
    if not one_way:
        f += rtp_flow(SRV, NAT_PUB, 50000, 40000, 2.1, 200, ssrc=22)
    f += [out(6.5, s.request("BYE", 2, to_tag="b1")), back(6.55, s.response(200, "OK", 2, method="BYE", to_tag="b1"))]
    return f


class NatTests(unittest.TestCase):
    def test_private_sdp_behind_nat_one_way(self):
        r = analyze_bytes(pcap(nat_call()))
        t = types(r.nat)
        self.assertTrue({"DEVICE_BEHIND_NAT", "NAT_NO_RPORT", "NAT_PRIVATE_SDP", "NAT_MEDIA_SOURCE_MISMATCH", "NAT_ONE_WAY_AUDIO"} <= t, t)
        sdp_f = next(x for x in r.nat if x["type"] == "NAT_PRIVATE_SDP")
        self.assertEqual(sdp_f["severity"], "critical")
        self.assertEqual(sdp_f["evidence"]["media_ips"], [PRIV])
        nat_diags = [d for d in r.diagnostics if d.category == "nat"]
        self.assertEqual({d.code for d in nat_diags}, t)

    def test_latching_fixes_audio_so_not_critical(self):
        r = analyze_bytes(pcap(nat_call(one_way=False)))
        self.assertNotIn("NAT_ONE_WAY_AUDIO", types(r.nat))
        self.assertEqual(next(x for x in r.nat if x["type"] == "NAT_PRIVATE_SDP")["severity"], "warning")

    def test_rport_suppresses_warning(self):
        s = Sip("reg-1", PRIV, SRV)
        req = s.request("REGISTER", 1).replace(b"branch=", b"rport;branch=")
        r = analyze_bytes(pcap([(1.0, udp_frame(NAT_PUB, SRV, 5060, 5060, req))]))
        self.assertIn("DEVICE_BEHIND_NAT", types(r.nat))
        self.assertNotIn("NAT_NO_RPORT", types(r.nat))

    def test_register_expires_too_long(self):
        s = Sip("reg-2", PRIV, SRV)
        req = s.request("REGISTER", 1, extra="Expires: 3600")
        r = analyze_bytes(pcap([(1.0, udp_frame(NAT_PUB, SRV, 5060, 5060, req))]))
        f = next(x for x in r.nat if x["type"] == "NAT_REGISTER_EXPIRES_TOO_LONG")
        self.assertEqual(f["evidence"]["expires"], 3600)

    def test_sip_alg_content_length(self):
        s = Sip("alg-1", "10.0.0.1", SRV)
        inv = s.request("INVITE", 1, body=sdp("10.0.0.1", 40000))
        inv = inv.replace(b"c=IN IP4 10.0.0.1", b"c=IN IP4 177.100.200.55")  # router rewrote the body, not Content-Length
        r = analyze_bytes(pcap([(1.0, udp_frame("177.100.200.55", SRV, 5060, 5060, inv))]))
        f = next(x for x in r.nat if x["type"] == "SIP_ALG_CONTENT_LENGTH")
        self.assertEqual(f["severity"], "critical")
        self.assertGreater(f["evidence"]["actual"], f["evidence"]["declared"])
        self.assertEqual(r.calls[0].call_id, "alg-1")  # the message is still parsed

    def test_sip_alg_sdp_rewrite(self):
        s = Sip("alg-2", "10.0.0.1", SRV)
        body = sdp("10.0.0.1", 40000).replace("c=IN IP4 10.0.0.1", "c=IN IP4 177.1.2.3")  # ALG fixed c= and Content-Length, not o=
        inv = s.request("INVITE", 1, body=body)
        r = analyze_bytes(pcap([(1.0, udp_frame("177.1.2.3", SRV, 5060, 5060, inv))]))
        self.assertIn("SIP_ALG_SDP_REWRITE", types(r.nat))
        self.assertNotIn("SIP_ALG_CONTENT_LENGTH", types(r.nat))

    def test_lan_call_has_no_nat_findings(self):
        self.assertEqual(analyze_bytes(pcap(basic_call())).nat, [])


class DdosTests(unittest.TestCase):
    def test_normal_call_no_ddos(self):
        r = analyze_bytes(pcap(basic_call(talk_s=5)))
        self.assertEqual(r.ddos, [])
        self.assertTrue(r.kpis["traffic_timeline"])

    def test_busy_sbc_media_is_not_an_attack(self):
        frames = []
        for i in range(40):  # 40 simultaneous calls = 4000 RTP packets/s, all linked to calls
            frames += basic_call(f"c{i}", t0=100.0, talk_s=5, port_a=20000 + 2 * i, port_b=30000 + 2 * i,
                                 ssrc_a=1000 + i, ssrc_b=5000 + i)
        r = analyze_bytes(pcap(sorted(frames, key=lambda x: x[0])))
        self.assertEqual(r.ddos, [])

    def test_volumetric_distributed(self):
        frames = basic_call(t0=100.0, talk_s=8)
        for sec in range(4):
            for i in range(3000):
                frames.append((105.0 + sec + i / 3000, udp_frame(f"45.{i % 80}.0.1", SRV, 1024 + i % 1000, 80, b"x" * 100)))
        r = analyze_bytes(pcap(sorted(frames, key=lambda x: x[0])))
        e = next(x for x in r.ddos if x["type"] == "DDOS_VOLUMETRIC")
        self.assertEqual(e["target_ip"], SRV)
        self.assertEqual(e["sources"], 80)
        self.assertGreaterEqual(e["duration_s"], 3)
        self.assertGreaterEqual(e["peak_pps"], 3000)
        self.assertIn("DDOS_VOLUMETRIC", {d.code for d in r.diagnostics if d.category == "ddos"})

    def test_syn_flood(self):
        frames = [(10.0 + i / 400, tcp_syn(f"91.0.{i % 120}.9", SRV, 10000 + i, 5061)) for i in range(400 * 4)]
        r = analyze_bytes(pcap(frames))
        e = next(x for x in r.ddos if x["type"] == "SYN_FLOOD")
        self.assertEqual(e["target_port"], 5061)
        self.assertEqual(e["synack_ratio"], 0.0)
        self.assertNotIn("DDOS_VOLUMETRIC", types(r.ddos))

    def test_ntp_reflection(self):
        frames = [(10.0 + i / 300, udp_frame(f"8.8.{i % 30}.1", SRV, 123, 40000 + i % 50, b"\x00" * 440)) for i in range(300 * 4)]
        r = analyze_bytes(pcap(frames))
        e = next(x for x in r.ddos if x["type"] == "REFLECTION_AMPLIFICATION")
        self.assertEqual(e["service"], "NTP")
        self.assertGreater(e["avg_packet_bytes"], 400)

    def test_distributed_sip_flood(self):
        frames = []
        for i in range(150 * 4):
            s = Sip(f"opt-{i}", f"66.0.{i % 20}.1", SRV)
            frames.append((10.0 + i / 150, udp_frame(s.a, SRV, 5060, 5060, s.request("OPTIONS", 1))))
        r = analyze_bytes(pcap(frames))
        e = next(x for x in r.ddos if x["type"] == "SIP_FLOOD_DISTRIBUTED")
        self.assertEqual(e["sources"], 20)
        self.assertEqual(e["methods"], {"OPTIONS": 600})


class ChartTests(unittest.TestCase):
    def test_chart_series(self):
        r = analyze_bytes(pcap(nat_call()))
        ch = r.kpis["charts"]
        for key in ("diagnostics_by_severity", "diagnostics_by_category", "problems_by_category", "call_outcomes",
                    "sip_error_codes", "mos_bands", "security_by_type", "nat_by_type", "ddos_by_type"):
            self.assertIn(key, ch)
        self.assertEqual(sum(x["value"] for x in ch["diagnostics_by_severity"]), len(r.diagnostics))
        self.assertEqual(ch["call_outcomes"], [{"key": "answered", "label": "Atendida", "value": 1}])
        self.assertIn("NAT", {x["label"] for x in ch["diagnostics_by_category"]})
        self.assertTrue(all(d.category for d in r.diagnostics))
        self.assertEqual({x["label"] for x in ch["nat_by_type"]}, {f["title"] for f in r.nat})
        d = r.to_dict()
        self.assertEqual(d["schema_version"], "2.2")
        self.assertIn("nat", d); self.assertIn("ddos", d)
        self.assertIn("category", d["diagnostics"][0])


if __name__ == "__main__":
    unittest.main()

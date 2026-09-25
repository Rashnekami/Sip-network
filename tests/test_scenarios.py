import struct
import unittest

from sip_network import Thresholds, analyze_bytes
from sip_network.capture import read_capture
from sip_network.q850 import parse_reason

from pcapgen import (Sip, basic_call, ether, ipv4, ipv6, pcap, rtp, rtp_flow, sdp, udp_datagram, udp_frame)


def codes(result, call_id=None):
    return {d.code for d in result.diagnostics if call_id is None or d.call_id == call_id}


class CallModelTests(unittest.TestCase):
    def test_normal_call_is_clean(self):
        r = analyze_bytes(pcap(basic_call()))
        c = r.calls[0]
        self.assertEqual(c.outcome, "answered")
        self.assertEqual(c.disconnect_side, "caller")
        self.assertEqual(c.q850_cause, 16)
        self.assertAlmostEqual(c.pdd_ms, 1000.0, delta=1)
        self.assertAlmostEqual(c.setup_time_ms, 3000.0, delta=1)
        self.assertAlmostEqual(c.ring_time_ms, 2000.0, delta=1)
        self.assertAlmostEqual(c.duration_s, 3.2, delta=0.01)
        self.assertEqual(c.negotiated_codecs, ["PCMU", "TELEPHONE-EVENT"])
        self.assertEqual(len(r.rtp_streams), 2)
        self.assertTrue(all(s.call_id == "call-1" for s in r.rtp_streams))
        self.assertTrue(all(s.sdp_destination_match for s in r.rtp_streams))
        self.assertEqual([d for d in r.diagnostics if d.severity != "info"], [])
        k = r.kpis["calls"]
        self.assertEqual((k["attempts"], k["answered"], k["asr_pct"], k["ner_pct"]), (1, 1, 100.0, 100.0))

    def test_digest_challenge_is_not_the_final_result(self):
        s = Sip("auth-1")
        f = [s.a_to_b(1, s.request("INVITE", 1, body=sdp(s.a, 40000))),
             s.b_to_a(1.1, s.response(407, "Proxy Authentication Required", 1, to_tag="x")),
             s.a_to_b(1.2, s.request("ACK", 1, to_tag="x")),
             s.a_to_b(1.3, s.request("INVITE", 2, body=sdp(s.a, 40000),
                                     extra='Proxy-Authorization: Digest username="1000", realm="x", response="abc"')),
             s.b_to_a(1.4, s.response(100, "Trying", 2)),
             s.b_to_a(2.0, s.response(200, "OK", 2, to_tag="b1", body=sdp(s.b, 50000))),
             s.a_to_b(2.1, s.request("ACK", 2, to_tag="b1"))]
        c = analyze_bytes(pcap(f)).calls[0]
        self.assertEqual(c.outcome, "answered")
        self.assertEqual(c.auth_challenges, 1)
        self.assertEqual(c.invite_attempts, 2)
        self.assertFalse(c.missing_ack)

    def test_cancel_is_not_a_failure(self):
        s = Sip("cancel-1")
        f = [s.a_to_b(1, s.request("INVITE", 1, body=sdp(s.a, 40000))),
             s.b_to_a(1.5, s.response(180, "Ringing", 1, to_tag="b1")),
             s.a_to_b(5, s.request("CANCEL", 1)),
             s.b_to_a(5.1, s.response(200, "OK", 1, method="CANCEL", to_tag="b1")),
             s.b_to_a(5.2, s.response(487, "Request Terminated", 1, to_tag="b1")),
             s.a_to_b(5.3, s.request("ACK", 1, to_tag="b1"))]
        r = analyze_bytes(pcap(f))
        c = r.calls[0]
        self.assertEqual(c.outcome, "cancelled")
        self.assertEqual(c.disconnect_side, "caller")
        self.assertNotIn("SIP_FINAL_FAILURE", codes(r))

    def test_busy_with_reason_header(self):
        s = Sip("busy-1")
        f = [s.a_to_b(1, s.request("INVITE", 1, body=sdp(s.a, 40000))),
             s.b_to_a(1.2, s.response(486, "Busy Here", 1, to_tag="b1", extra='Reason: Q.850;cause=17;text="User busy"'))]
        c = analyze_bytes(pcap(f)).calls[0]
        self.assertEqual((c.outcome, c.q850_cause, c.q850_text), ("busy", 17, "Usuário ocupado"))

    def test_forked_answers_track_ack_per_dialog(self):
        s = Sip("fork-1")
        f = [s.a_to_b(1, s.request("INVITE", 1, body=sdp(s.a, 40000))),
             s.b_to_a(2, s.response(200, "OK", 1, to_tag="A", body=sdp(s.b, 50000))),
             s.b_to_a(2.01, s.response(200, "OK", 1, to_tag="B", body=sdp(s.b, 50002))),
             s.a_to_b(2.1, s.request("ACK", 1, to_tag="A"))]
        r = analyze_bytes(pcap(f))
        c = r.calls[0]
        self.assertTrue(c.forked)
        self.assertEqual(c.unanswered_ack_dialogs, ["B"])
        self.assertIn("SIP_FORKED_ANSWER", codes(r))

    def test_hold_and_transfer(self):
        frames = basic_call("hold-1", talk_s=1.0, with_bye=False)
        s = Sip("hold-1")
        frames += [s.a_to_b(106, s.request("INVITE", 2, to_tag="b1", body=sdp(s.a, 40000, direction="sendonly"))),
                   s.b_to_a(106.1, s.response(200, "OK", 2, to_tag="b1", body=sdp(s.b, 50000, direction="recvonly"))),
                   s.a_to_b(106.2, s.request("ACK", 2, to_tag="b1")),
                   s.a_to_b(108, s.request("INVITE", 3, to_tag="b1", body=sdp(s.a, 40000))),
                   s.a_to_b(109, s.request("REFER", 4, to_tag="b1", extra="Refer-To: <sip:3000@x>")),
                   s.b_to_a(109.1, s.response(202, "Accepted", 4, method="REFER", to_tag="b1"))]
        c = analyze_bytes(pcap(frames)).calls[0]
        self.assertEqual([h["event"] for h in c.hold_events], ["hold", "resume"])
        self.assertEqual(c.reinvites, 2)
        self.assertEqual(c.transfers[0]["refer_to"], "<sip:3000@x>")
        self.assertEqual(c.transfers[0]["status"], 202)

    def test_missing_ack_drop_at_32s(self):
        frames = basic_call("drop-1", talk_s=32.0, caller_ack=False, with_bye=False)
        s = Sip("drop-1")
        frames.append(s.b_to_a(135.1, s.request("BYE", 1, to_tag="b1", from_side="b")))
        r = analyze_bytes(pcap(frames))
        c = r.calls[0]
        self.assertEqual(c.disconnect_side, "callee")
        self.assertIn("SIP_MISSING_ACK", codes(r))
        self.assertIn("SIP_DROP_32S", codes(r))

    def test_invite_without_any_response(self):
        s = Sip("dead-1")
        f = [s.a_to_b(1 + i * 0.5, s.request("INVITE", 1, body=sdp(s.a, 40000))) for i in range(7)]
        f.append((40, udp_frame("10.0.0.9", "10.0.0.8", 1, 2, b"keepalive")))
        r = analyze_bytes(pcap(f))
        self.assertEqual(r.calls[0].outcome, "no_response")
        self.assertIn("SIP_NO_RESPONSE", codes(r))
        self.assertEqual(r.kpis["calls"]["isa_pct"], 100.0)


class CaptureTests(unittest.TestCase):
    def _fragmented(self, v6=False):
        s = Sip("frag-1", "2001:db8::1" if v6 else "10.0.0.1", "2001:db8::2" if v6 else "10.0.0.2")
        body = sdp("10.0.0.1", 40000, extra="a=x-long:" + "y" * 1600 + "\r\na=x-last:ok\r\n")
        dgram = udp_datagram(5060, 5060, s.request("INVITE", 1, body=body))
        cut = 1448
        if v6:
            f1 = ether(ipv6(s.a, s.b, dgram[:cut], frag=(9, 0, True)), v6=True)
            f2 = ether(ipv6(s.a, s.b, dgram[cut:], frag=(9, cut, False)), v6=True)
        else:
            f1 = ether(ipv4(s.a, s.b, dgram[:cut], ident=77, frag_offset=0, more=True))
            f2 = ether(ipv4(s.a, s.b, dgram[cut:], ident=77, frag_offset=cut, more=False))
        # Fragments out of order, as they often arrive.
        return analyze_bytes(pcap([(1.0, f2), (1.001, f1)]))

    def test_ipv4_fragments_are_reassembled(self):
        r = self._fragmented()
        self.assertEqual(r.capture["sip_messages"], 1)
        self.assertIn("a=x-last:ok", r.calls[0].messages[0].body)

    def test_ipv6_fragments_are_reassembled(self):
        r = self._fragmented(v6=True)
        self.assertEqual(r.capture["sip_messages"], 1)
        self.assertEqual(r.calls[0].caller_ip, "2001:db8::1")

    def test_dscp_is_read(self):
        p = read_capture(pcap([(1, udp_frame("10.0.0.1", "10.0.0.2", 1, 2, b"x", dscp=46))]))[0]
        self.assertEqual(p.dscp, 46)

    def test_icmp_port_unreachable(self):
        s = Sip("icmp-1")
        invite = udp_datagram(5060, 5060, s.request("INVITE", 1, body=sdp(s.a, 40000)))
        quoted = ipv4(s.a, s.b, invite)[:28]
        icmp = struct.pack("!BBHI", 3, 3, 0, 0) + quoted
        f = [(1, ether(ipv4(s.a, s.b, invite))), (1.001, ether(ipv4(s.b, s.a, icmp, proto=1)))]
        r = analyze_bytes(pcap(f))
        d = next(x for x in r.diagnostics if x.code == "ICMP_UNREACHABLE")
        self.assertEqual(d.evidence["orig_dst_port"], 5060)
        self.assertEqual(d.evidence["reason"], "porta inalcançável")


class MediaTests(unittest.TestCase):
    def test_media_findings(self):
        frames = basic_call("media-1", talk_s=0.5, rtp_both=False, dscp=0, with_bye=False)
        # Callee answers with an audio gap, a non-negotiated PT and DTMF 1-2-#.
        frames += rtp_flow("10.0.0.2", "10.0.0.1", 50000, 40000, 103.1, 60, ssrc=222, dscp=0, gap_after=30, gap_s=0.8)
        for i, ev in enumerate((1, 2, 11)):
            for k in range(3):
                payload = bytes([ev, 0x0A, 0, 160])
                frames.append((104.5 + i * 0.2 + k * 0.02, udp_frame("10.0.0.1", "10.0.0.2", 40000, 50000,
                                                                      rtp(2000 + i * 3 + k, 9000 + i * 1000, 111, 101, payload))))
        frames += [(105 + i * 0.02, udp_frame("10.0.0.2", "10.0.0.1", 50000, 40000, rtp(5000 + i, i * 160, 333, 18))) for i in range(5)]
        r = analyze_bytes(pcap(frames))
        c = codes(r, "media-1")
        self.assertIn("RTP_GAP", c)
        self.assertIn("RTP_DSCP", c)
        self.assertIn("RTP_PT_NOT_NEGOTIATED", c)
        self.assertIn("RTP_SSRC_CHANGE", c)
        caller = next(s for s in r.rtp_streams if s.ssrc == 111)
        self.assertEqual(caller.dtmf_digits, "12#")

    def test_rtcp_remote_loss(self):
        frames = basic_call("rtcp-1", talk_s=2.0)
        rr_block = struct.pack("!IB3sIIII", 111, 26, (5).to_bytes(3, "big"), 1100, 80, 0, 0)  # 26/256 = 10%
        rr = struct.pack("!BBHI", 0x81, 201, 7, 222) + rr_block
        frames.append((104.0, udp_frame("10.0.0.2", "10.0.0.1", 50001, 40001, rr)))
        r = analyze_bytes(pcap(frames))
        s = next(x for x in r.rtp_streams if x.ssrc == 111)
        self.assertAlmostEqual(s.rtcp_remote_loss_pct, 10.16, places=1)
        self.assertEqual(s.rtcp_remote_jitter_ms, 10.0)
        self.assertIn("RTCP_REMOTE_LOSS", codes(r))


class SecurityAndRegistrationTests(unittest.TestCase):
    def test_register_success(self):
        s = Sip("reg-ok", to_user="1000")
        f = [s.a_to_b(1, s.request("REGISTER", 1, extra="Expires: 3600")),
             s.b_to_a(1.02, s.response(401, "Unauthorized", 1, method="REGISTER", to_tag="r")),
             s.a_to_b(1.05, s.request("REGISTER", 2, extra='Expires: 3600\r\nAuthorization: Digest username="1000", response="x"')),
             s.b_to_a(1.08, s.response(200, "OK", 2, method="REGISTER", to_tag="r"))]
        r = analyze_bytes(pcap(f))
        reg = r.registrations[0]
        self.assertEqual((reg["state"], reg["challenges"], reg["successes"], reg["expires"]), ("registered", 1, 1, 3600))
        self.assertAlmostEqual(reg["avg_register_delay_ms"], 30.0, delta=1)
        self.assertEqual(r.calls, [])

    def test_brute_force_from_scanner(self):
        f = []
        for i in range(15):
            s = Sip(f"bf-{i}", a="203.0.113.50", b="198.51.100.10", to_user=str(100 + i), ua="friendly-scanner")
            f.append(s.a_to_b(1 + i * 0.1, s.request("REGISTER", 1, extra=f'Authorization: Digest username="{100 + i}", response="x"')))
            f.append(s.b_to_a(1.01 + i * 0.1, s.response(403, "Forbidden", 1, method="REGISTER", to_tag="r")))
        r = analyze_bytes(pcap(f))
        types = {a["type"] for a in r.security}
        self.assertIn("scanner", types)
        self.assertIn("brute_force", types)
        self.assertIn("enumeration", types)
        self.assertIn("SEC_BRUTE_FORCE", codes(r))
        self.assertTrue(all(x["state"] == "failed" for x in r.registrations))
        self.assertNotIn("REGISTER_FAILED", codes(r))  # the attack is reported once, not per AOR

    def test_toll_fraud(self):
        frames = []
        for i in range(6):
            frames += basic_call(f"intl-{i}", t0=100 + i * 10, talk_s=0.2, to_user=f"0021{972 + i}5551234")
        r = analyze_bytes(pcap(frames))
        alert = next(a for a in r.security if a["type"] == "toll_fraud")
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["international_destinations"], 6)

    def test_thresholds_are_tunable(self):
        s = Sip("pdd-1")
        f = [s.a_to_b(1, s.request("INVITE", 1, body=sdp(s.a, 40000))),
             s.b_to_a(4, s.response(180, "Ringing", 1, to_tag="b1"))]
        self.assertNotIn("SIP_HIGH_PDD", codes(analyze_bytes(pcap(f))))
        self.assertIn("SIP_HIGH_PDD", codes(analyze_bytes(pcap(f), thresholds=Thresholds(pdd_warning_ms=2000))))


class Q850Tests(unittest.TestCase):
    def test_parse_reason(self):
        self.assertEqual(parse_reason('SIP;cause=200, Q.850;cause=34;text="No circuit"'), (34, "No circuit"))
        self.assertEqual(parse_reason(None), (None, None))


if __name__ == "__main__":
    unittest.main()

"""Generate a demo capture with typical NOC scenarios (answered, busy, missing ACK, no response, brute force).

    python tools/make_demo_pcap.py demo.pcap
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
import struct  # noqa: E402

from pcapgen import Sip, basic_call, ether, ipv4, pcap, rtp_flow, sdp, udp_frame  # noqa: E402


def build() -> bytes:
    frames = basic_call("ok-1@demo", t0=100.0, talk_s=5.0)
    frames += basic_call("ok-2@demo", t0=110.0, talk_s=4.0, dscp=0, port_a=40100, port_b=50100, ssrc_a=311, ssrc_b=322)
    s = Sip("busy@demo", to_user="3000")
    frames += [s.a_to_b(120, s.request("INVITE", 1, body=sdp(s.a, 40010))),
               s.b_to_a(120.2, s.response(486, "Busy Here", 1, to_tag="x", extra='Reason: Q.850;cause=17;text="User busy"')),
               s.a_to_b(120.3, s.request("ACK", 1, to_tag="x"))]
    frames += basic_call("noack@demo", t0=130.0, talk_s=32.0, caller_ack=False, with_bye=False, port_a=40200, port_b=50200, ssrc_a=411, ssrc_b=422)
    s = Sip("noack@demo")
    frames.append(s.b_to_a(165.2, s.request("BYE", 1, to_tag="b1", from_side="b")))
    s = Sip("dead@demo", b="10.0.0.99", to_user="4000")
    frames += [s.a_to_b(170 + i * 0.5 * (2 ** min(i, 3)), s.request("INVITE", 1, body=sdp(s.a, 40020))) for i in range(6)]
    for i in range(12):
        s = Sip(f"bf-{i}@demo", a="203.0.113.50", b="10.0.0.2", to_user=str(200 + i), ua="friendly-scanner")
        frames.append(s.a_to_b(215 + i * 0.05, s.request("REGISTER", 1, extra=f'Authorization: Digest username="{200 + i}", response="x"')))
        frames.append(s.b_to_a(215.01 + i * 0.05, s.response(403, "Forbidden", 1, method="REGISTER", to_tag="r")))
    # Phone behind NAT with a private SDP: audio only leaves, never comes back.
    s = Sip("nat@demo", a="192.168.1.10", b="200.1.1.1")
    out = lambda t, p: (t, udp_frame("177.10.0.5", "200.1.1.1", 5060, 5060, p))
    back = lambda t, p: (t, udp_frame("200.1.1.1", "177.10.0.5", 5060, 5060, p))
    frames += [out(230.0, s.request("INVITE", 1, body=sdp("192.168.1.10", 40300))),
               back(230.5, s.response(180, "Ringing", 1, to_tag="n")),
               back(232.0, s.response(200, "OK", 1, to_tag="n", body=sdp("200.1.1.1", 50300))),
               out(232.05, s.request("ACK", 1, to_tag="n"))]
    frames += rtp_flow("177.10.0.5", "200.1.1.1", 40300, 50300, 232.1, 250, ssrc=511)
    frames += [out(237.5, s.request("BYE", 2, to_tag="n")), back(237.55, s.response(200, "OK", 2, method="BYE", to_tag="n"))]
    # SYN flood against SIP over TLS.
    for i in range(1600):
        tcp = struct.pack("!HHIIBBHHH", 10000 + i, 5061, 1, 0, 5 << 4, 0x02, 65535, 0, 0)
        frames.append((240.0 + i / 400, ether(ipv4(f"91.0.{i % 120}.9", "10.0.0.2", tcp, proto=6))))
    frames.sort(key=lambda f: f[0])
    return pcap(frames)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "demo.pcap"
    with open(out, "wb") as f:
        f.write(build())
    print(f"gerado {out}")

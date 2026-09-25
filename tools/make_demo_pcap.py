"""Generate a demo capture with typical NOC scenarios (answered, busy, missing ACK, no response, brute force).

    python tools/make_demo_pcap.py demo.pcap
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
from pcapgen import Sip, basic_call, pcap, sdp  # noqa: E402


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
    frames.sort(key=lambda f: f[0])
    return pcap(frames)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "demo.pcap"
    with open(out, "wb") as f:
        f.write(build())
    print(f"gerado {out}")

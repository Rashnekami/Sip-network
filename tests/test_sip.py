import unittest

from sip_network.models import Packet
from sip_network.sip import build_calls, extract_sip_messages


def p(n,t,text,src="10.0.0.1",dst="10.0.0.2",sp=5060,dp=5060):
    return Packet(n,t,len(text),len(text),1,src,dst,"UDP",sp,dp,text.encode(),ip_version=4)


def msg(first, call="abc", cseq="1 INVITE", extra="", body=""):
    return f"{first}\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1\r\nFrom: <sip:a@example>;tag=f1\r\nTo: <sip:b@example>\r\nCall-ID: {call}\r\nCSeq: {cseq}\r\n{extra}Content-Length: {len(body.encode())}\r\n\r\n{body}"


class SipTests(unittest.TestCase):
    def test_register_200_does_not_trigger_missing_ack(self):
        packets = [
            p(1,1,msg("REGISTER sip:x SIP/2.0",cseq="1 REGISTER")),
            p(2,2,msg("SIP/2.0 200 OK",cseq="1 REGISTER"),src="10.0.0.2",dst="10.0.0.1"),
        ]
        calls=build_calls(extract_sip_messages(packets))
        self.assertEqual(calls, [])  # REGISTER is not a call; it is reported under registrations

    def test_invite_200_without_ack_is_flagged(self):
        packets = [
            p(1,1,msg("INVITE sip:b@example SIP/2.0")),
            p(2,2,msg("SIP/2.0 200 OK"),src="10.0.0.2",dst="10.0.0.1"),
        ]
        calls=build_calls(extract_sip_messages(packets))
        self.assertTrue(calls[0].missing_ack)

    def test_invite_200_with_ack_is_ok(self):
        packets = [
            p(1,1,msg("INVITE sip:b@example SIP/2.0")),
            p(2,2,msg("SIP/2.0 200 OK"),src="10.0.0.2",dst="10.0.0.1"),
            p(3,2.1,msg("ACK sip:b@example SIP/2.0", cseq="1 ACK")),
        ]
        calls=build_calls(extract_sip_messages(packets))
        self.assertFalse(calls[0].missing_ack)

if __name__ == "__main__": unittest.main()

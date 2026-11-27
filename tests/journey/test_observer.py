import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from validation.journey import observer


ZONE_PORT = 17001
PEER_PORT = 40001
CHARACTER = "ObserverTest"
SEQUENCE = 0x1234


def reliable(opcode, payload, sequence=SEQUENCE):
    return b"\x00\x09" + struct.pack("!H", sequence) + struct.pack("<H", opcode) + payload


def udp_frame(payload, options=b"", protocol=socket.IPPROTO_UDP, source=b"\x7f\x00\x00\x01"):
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45 + len(options) // 4, 0,
        20 + len(options) + 8 + len(payload), 0, 0, 64, protocol, 0,
        source, b"\x7f\x00\x00\x01",
    )
    udp_header = struct.pack("!HHHH", ZONE_PORT, PEER_PORT, 8 + len(payload), 0)
    return bytes(12) + b"\x08\x00" + ip_header + options + udp_header + payload


class DatagramTests(unittest.TestCase):
    def setUp(self):
        self.position = [-12.375, 15.125, -3.25]
        self.heading = 0xabc
        words = struct.pack(
            "<5I", (121 << 12) | 0xfff, 0x87654321,
            (self.heading << 19) | (0x80000 - 99),
            ((0x80000 - 26) << 10) | 0x3ff, 0x12345678,
        )
        spawn = bytearray(430)
        name = CHARACTER.encode() + b"\x00"
        spawn[:len(name) + 4] = name + struct.pack("<I", 1)
        spawn[347:367] = words
        self.cases = [
            (0x7dfc, struct.pack("<HH", 0xabcd, 0) + words, {
                "entity": 0xabcd, "position": self.position, "payload_bytes": 24,
            }),
            (0x58e2, struct.pack("<I", 0x87654321), {"entity": 0x87654321}),
            (0x6f15, struct.pack("<HHBIi", 0x8123, 0x9876, 7, 0xfedcba98, -123) + bytes(17), {
                "target": 0x8123, "source": 0x9876, "type": 7, "spell": 0xfedcba98, "damage": -123,
            }),
            (0x37b1, struct.pack("<HB", 0x8123, 73), {"entity": 0x8123, "percent": 73}),
            (0x5089, bytes(spawn), {
                "entity": 1, "name": CHARACTER, "position": self.position, "heading": self.heading,
                "payload_bytes": 430, "position_words_hex": words.hex(),
            }),
        ]

    def decode(self, datagram, src=ZONE_PORT, dst=PEER_PORT, character=CHARACTER):
        return observer.decode_datagram(datagram, src, dst, ZONE_PORT, character)

    def test_five_server_opcodes(self):
        for opcode, payload, fields in self.cases:
            with self.subTest(opcode=hex(opcode)):
                self.assertEqual(self.decode(reliable(opcode, payload)), {
                    "direction": "server_to_client", "sequence": SEQUENCE,
                    "opcode": hex(opcode), "payload_hex": payload.hex(),
                    **fields,
                })

    def test_wrong_application_lengths(self):
        for opcode, payload, _ in self.cases:
            for body in (payload[:-1], payload + b"\x00"):
                with self.subTest(opcode=hex(opcode), length=len(body)):
                    self.assertIsNone(self.decode(reliable(opcode, body)))

    def test_wrong_opcode_port_or_header(self):
        datagram = reliable(0x58e2, bytes(4))
        self.assertIsNone(self.decode(reliable(0xffff, bytes(4))))
        self.assertIsNone(self.decode(datagram, src=PEER_PORT, dst=ZONE_PORT))
        self.assertIsNone(self.decode(datagram, src=PEER_PORT, dst=PEER_PORT + 1))
        self.assertIsNone(self.decode(b"\x01\x09" + datagram[2:]))
        self.assertIsNone(self.decode(b"\x00\x08" + datagram[2:]))
        self.assertIsNone(self.decode(datagram[:5]))

    def test_self_spawn_requires_name_and_entity_one(self):
        _, spawn, _ = self.cases[-1]
        self.assertIsNone(self.decode(reliable(0x5089, spawn), character="Observer"))
        entity_offset = len(CHARACTER.encode()) + 1
        other_entity = spawn[:entity_offset] + struct.pack("<I", 2) + spawn[entity_offset + 4:]
        self.assertIsNone(self.decode(reliable(0x5089, other_entity)))

    def test_client_ack(self):
        ack = b"\x00\x15\xab\xcd"
        self.assertEqual(self.decode(ack, src=PEER_PORT, dst=ZONE_PORT), {
            "direction": "client_to_server", "ACK": 0xabcd,
        })
        self.assertIsNone(self.decode(ack))
        for wrong in (ack[:-1], ack + b"\x00", b"\x00\x14" + ack[2:]):
            self.assertIsNone(self.decode(wrong, src=PEER_PORT, dst=ZONE_PORT))


class FrameTests(unittest.TestCase):
    def test_udp_header_sets_payload_length(self):
        self.assertEqual(observer.decode_ipv4_udp(udp_frame(b"packet") + b"padding"),
                         (ZONE_PORT, PEER_PORT, b"packet"))

    def test_uses_ipv4_header_length_with_options(self):
        frame = udp_frame(b"packet", options=b"\x01\x01\x01\x00")
        self.assertEqual(observer.decode_ipv4_udp(frame), (ZONE_PORT, PEER_PORT, b"packet"))

    def test_rejects_non_udp_and_non_loopback(self):
        self.assertIsNone(observer.decode_ipv4_udp(udp_frame(b"", protocol=socket.IPPROTO_TCP)))
        self.assertIsNone(observer.decode_ipv4_udp(udp_frame(b"", source=b"\x7f\x00\x00\x02")))
        frame = udp_frame(b"")
        self.assertIsNone(observer.decode_ipv4_udp(frame[:30] + b"\x0a\x00\x00\x01" + frame[34:]))
        self.assertIsNone(observer.decode_ipv4_udp(frame[:12] + b"\x86\xdd" + frame[14:]))

    def test_rejects_truncated_or_invalid_headers(self):
        frame = udp_frame(b"packet", options=b"\x01\x01\x01\x00")
        for length in (13, 33, 38, 45, len(frame) - 1):
            with self.subTest(length=length):
                self.assertIsNone(observer.decode_ipv4_udp(frame[:length]))
        self.assertIsNone(observer.decode_ipv4_udp(frame[:14] + b"\x44" + frame[15:]))
        self.assertIsNone(observer.decode_ipv4_udp(frame[:42] + b"\x00\x07" + frame[44:]))


class CorrelationTests(unittest.TestCase):
    def reply(self, sequence, timestamp=10.0):
        return {
            "direction": "server_to_client", "sequence": sequence, "monotonic": timestamp,
            "src_port": ZONE_PORT, "dst_port": PEER_PORT,
        }

    def ack(self, sequence, timestamp=11.0, peer=PEER_PORT, zone=ZONE_PORT):
        return {
            "direction": "client_to_server", "ACK": sequence, "monotonic": timestamp,
            "src_port": peer, "dst_port": zone,
        }

    def test_exact_and_cumulative_coverage_in_reply_order(self):
        cumulative_reply = self.reply(9)
        exact_reply = self.reply(10)
        first_ack = self.ack(10)
        rows = [cumulative_reply, exact_reply, first_ack, self.ack(11, timestamp=12.0)]
        self.assertEqual(observer.correlate({"rows": rows, "error": None}), [
            {"reply": cumulative_reply, "ack": first_ack, "coverage": "cumulative_high_water"},
            {"reply": exact_reply, "ack": first_ack, "coverage": "exact"},
        ])

    def test_wraparound(self):
        reply = self.reply(65535)
        ack = self.ack(2)
        self.assertEqual(observer.correlate({"rows": [reply, ack], "error": None}), [
            {"reply": reply, "ack": ack, "coverage": "cumulative_high_water"},
        ])

    def test_ignores_acks_from_other_ports_or_earlier_time(self):
        reply = self.reply(10)
        matching_ack = self.ack(10, timestamp=10.0)
        rows = [reply, self.ack(10, peer=PEER_PORT + 1), self.ack(10, zone=ZONE_PORT + 1),
                self.ack(10, timestamp=9.0), matching_ack]
        self.assertEqual(observer.correlate({"rows": rows, "error": None}), [
            {"reply": reply, "ack": matching_ack, "coverage": "exact"},
        ])

    def test_missing_ack_raises(self):
        rows = [self.reply(10), self.ack(9), self.ack(10 + 0x8000)]
        with self.assertRaisesRegex(observer.ObserverError, "reply 10"):
            observer.correlate({"rows": rows, "error": None})

    def test_observation_error_raises(self):
        with self.assertRaisesRegex(observer.ObserverError, "selected capture budget"):
            observer.correlate({"rows": [], "error": "selected capture budget"})


def wait_for(check):
    deadline = time.monotonic() + 2
    while not check() and time.monotonic() < deadline:
        time.sleep(0.01)


class ObserverLifecycleTests(unittest.TestCase):
    @patch.object(observer.socket, "socket", side_effect=PermissionError("raw socket denied"))
    def test_open_failure_becomes_observer_error(self, _):
        capture = observer.Observer(ZONE_PORT, CHARACTER)
        self.assertEqual(capture.error, "PermissionError:raw socket denied")
        self.assertEqual(capture.stop()["error"], capture.error)

    @patch.object(observer.socket, "socket")
    def test_bind_failure_closes_socket_once(self, open_socket):
        capture_socket = open_socket.return_value
        capture_socket.bind.side_effect = OSError("bind failed")
        capture = observer.Observer(ZONE_PORT, CHARACTER)
        self.assertEqual(capture.error, "OSError:bind failed")
        self.assertEqual(capture.stop(), capture.stop())
        capture_socket.close.assert_called_once_with()

    @patch.object(observer.socket, "socket")
    def test_row_budget_and_snapshot(self, open_socket):
        capture_socket = open_socket.return_value
        frame = udp_frame(reliable(0x7dfc, struct.pack("<HH5I", 1, 0, 0, 0, 0, 0, 0)))
        capture_socket.recvfrom.side_effect = [(frame, ("lo", 0x0800, 0))] * 2
        capture = observer.Observer(ZONE_PORT, CHARACTER, max_rows=1)
        self.addCleanup(capture.stop)
        wait_for(lambda: capture.error)
        self.assertEqual(capture.error, "selected capture budget")
        snapshot = capture.rows
        self.assertEqual(len(snapshot), 1)
        snapshot[0]["position"][0] = 42
        snapshot.clear()
        self.assertEqual(capture.rows[0]["position"], [0.0, 0.0, 0.0])
        self.assertEqual(capture.stop(), capture.stop())
        capture_socket.close.assert_called_once_with()

    @patch.object(observer.socket, "socket")
    def test_capture_thread_error_is_repr(self, open_socket):
        failure = OSError("read failed")
        open_socket.return_value.recvfrom.side_effect = failure
        capture = observer.Observer(ZONE_PORT, CHARACTER)
        self.addCleanup(capture.stop)
        wait_for(lambda: capture.error)
        self.assertEqual(capture.stop()["error"], repr(failure))

    @patch.object(observer.threading, "Thread")
    @patch.object(observer.socket, "socket")
    def test_thread_timeout_still_closes_socket(self, open_socket, create_thread):
        thread = create_thread.return_value
        thread.is_alive.side_effect = [True, False]
        capture = observer.Observer(ZONE_PORT, CHARACTER)
        observation = capture.stop()
        thread.join.assert_called_once_with(timeout=1)
        self.assertEqual(observation["error"], "capture thread not stopped")
        self.assertEqual(capture.stop(), observation)
        open_socket.return_value.close.assert_called_once_with()


class LiveObserverTests(unittest.TestCase):
    def rerun_if_unprivileged(self):
        if os.environ.get("JOURNEY_OBSERVER_TEST_NAMESPACE") == "1":
            return False
        try:
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)):
                return False
        except PermissionError:
            pass

        try:
            probe = subprocess.run(["unshare", "-rn", "--", "true"],
                                   capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            self.skipTest("AF_PACKET requires privileges and unshare -rn is unavailable")
        if probe.returncode:
            self.skipTest(f"AF_PACKET requires privileges and unshare -rn failed: {probe.stderr.strip()}")

        result = subprocess.run([
            "unshare", "-rn", "--", "sh", "-ec", 'ip link set lo up; exec "$@"', "sh",
            sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/journey",
            "-p", "test_observer.py", "-k", self._testMethodName, "-v",
        ], cwd=Path(__file__).resolve().parents[2],
            env={**os.environ, "JOURNEY_OBSERVER_TEST_NAMESPACE": "1"},
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return True

    def test_live_self_check(self):
        if self.rerun_if_unprivileged():
            return
        result = observer.self_check(CHARACTER)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["observation"]["rows"]), 7)
        self.assertEqual([pair["reply"]["sequence"] for pair in result["correlations"]], list(range(5, 11)))

    def test_live_outgoing_only_fails_self_check(self):
        if self.rerun_if_unprivileged():
            return
        with patch.object(observer, "_PACKET_HOST", 4):
            with self.assertRaisesRegex(observer.ObserverError, "expected six captured replies, got 0"):
                observer.self_check(CHARACTER)

    def test_live_observer_round_trip(self):
        if self.rerun_if_unprivileged():
            return
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client,
        ):
            for endpoint in (server, client):
                endpoint.bind(("127.0.0.1", 0))
                endpoint.settimeout(1)
            server_address, client_address = server.getsockname(), client.getsockname()
            capture = observer.Observer(server_address[1], CHARACTER)
            self.addCleanup(capture.stop)
            self.assertIsNone(capture.error)
            response = reliable(0x58e2, struct.pack("<I", 42))
            ack = b"\x00\x15" + struct.pack("!H", SEQUENCE)
            server.sendto(response, client_address)
            self.assertEqual(client.recvfrom(1024), (response, server_address))
            client.sendto(ack, server_address)
            self.assertEqual(server.recvfrom(1024), (ack, client_address))
            wait_for(lambda: len(capture.rows) >= 2 or capture.error)
            observation = capture.stop()

        self.assertEqual(capture.stop(), observation)
        self.assertIsNone(observation["error"])
        self.assertEqual(observation["selected_zone_port"], server_address[1])
        self.assertEqual([row["packet_type"] for row in observation["rows"]], [0, 0])
        reply, ack_row = observation["rows"]
        self.assertEqual(reply["entity"], 42)
        self.assertEqual((reply["src_port"], reply["dst_port"]), (server_address[1], client_address[1]))
        self.assertEqual((ack_row["src_port"], ack_row["dst_port"]), (client_address[1], server_address[1]))
        self.assertEqual(observer.correlate(observation), [
            {"reply": reply, "ack": ack_row, "coverage": "exact"},
        ])

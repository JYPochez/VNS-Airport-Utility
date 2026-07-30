import argparse
import hashlib
import os
import struct
import tempfile
import unittest
from unittest import mock

import backend.airport_backend as airport_backend
import backend.firmware as firmware_module
from backend.acp import ACP_STREAM_SIZE
from backend.acp import ACPHeader
from backend.acp import ACP_PROPERTY_HEADER
from backend.acp import ACP_REQUEST_SALT
from backend.acp import ACP_RESPONSE_SALT
from backend.acp import acp_adler32
from backend.acp import make_header
from backend.acp import parse_header
from backend.cfb0 import CFB0CodecError
from backend.cfb0 import CFB0Integer
from backend.cfb0 import cfb0_dumps
from backend.cfb0 import cfb0_loads
from backend.disk import build_archive_disk_options_from_mast
from backend.disk import build_erase_disk_options_from_mast
from backend.disk import matching_partitions
from backend.disk import parse_uuid_bytes
from backend.firmware import FIRMWARE_MAGIC
from backend.firmware import firmware_link_local_address_from_mac
from backend.firmware import firmware_source_bytes
from backend.firmware import firmware_source_summary
from backend.firmware import firmware_upload_host_candidates
from backend.firmware import parse_firmware_image_info
from backend.firmware import parse_firmware_progress
from backend.firmware import parse_mac_address
from backend.intents import normalized_modern_write_intent
from backend.intents import normalized_dirty_properties
from backend.intents import value_from_json_setting
from backend.legacy import COMMAND_GETPROP
from backend.legacy import COMMAND_LEGACY_KEY_EXCHANGE
from backend.legacy import LEGACY_DH_GENERATOR
from backend.legacy import LEGACY_DH_MODULUS
from backend.legacy import compose_header
from backend.legacy import compose_property_element
from backend.legacy import encode_setting_value
from backend.legacy import legacy_parse_header
from backend.legacy import legacy_property_status_is_accepted
from backend.legacy import legacy_setting_json_record
from backend.legacy import open_legacy_encrypted_transport
from backend.legacy import parse_property_results
from backend.legacy import send_property_write_streaming_acp17
from backend.modern import format_value
from backend.modern import handle_property_result
from backend.modern import json_safe_cfb0
from backend.modern import parse_property_record
from backend.modern import profile_path_get
from backend.modern import property_request
from backend.modern import read_properties
from backend.modern import setting_json_record
from backend.settings import add_network_arguments
from backend.settings import build_network_dirty_plist
from backend.settings import has_friendly_setting_options
from backend.settings import wds_node_list_value
from backend.session import rpc_call
from backend.srp import derive_keys
from backend.srp import int_to_bytes
from backend.srp import int_to_padded_bytes
from backend.srp import xor_bytes


class CFB0CodecTests(unittest.TestCase):
    def test_round_trips_nested_supported_values(self):
        value = {
            "state": 3,
            "enabled": True,
            "name": "AirPort",
            "blob": b"\x00\x01\x02",
            "items": ["one", 2, False],
            "nested": {"key": b"value"},
        }

        self.assertEqual(cfb0_loads(cfb0_dumps(value)), value)

    def test_round_trip_retains_nonminimal_integer_width(self):
        encoded = b"CFB0\x12\x00\x00\x00\x05END!"
        value = cfb0_loads(encoded)

        self.assertIsInstance(value, CFB0Integer)
        self.assertEqual(value.width, 4)
        self.assertEqual(cfb0_dumps(value), encoded)

    def test_json_boundary_retains_cfb0_integer_width(self):
        value = CFB0Integer(5, 4)
        json_value = json_safe_cfb0(value)

        self.assertEqual(json_value, {"type": "integer", "decimal": "5", "width": 4})
        restored = value_from_json_setting(json_value)
        self.assertIsInstance(restored, CFB0Integer)
        self.assertEqual(restored.width, 4)

    def test_rejects_missing_magic(self):
        with self.assertRaises(CFB0CodecError):
            cfb0_loads(b"not-cfb0")


class ACPProtocolTests(unittest.TestCase):
    def test_make_header_sets_body_size_flags_command_and_body_checksum(self):
        body = b"abc"
        header = make_header(body, flags=4, command=0x1A, client_token=b"\x11" * 32)

        parsed = parse_header(header)
        self.assertEqual(parsed.body_size, len(body))
        self.assertEqual(parsed.flags, 4)
        self.assertEqual(parsed.command, 0x1A)
        self.assertEqual(struct.unpack(">I", header[12:16])[0], acp_adler32(body))
        self.assertEqual(header[48:80], b"\x11" * 32)

    def test_make_header_supports_streaming_body_size(self):
        parsed = parse_header(make_header(b"", flags=4, command=0x15, body_size=ACP_STREAM_SIZE))

        self.assertEqual(parsed.body_size, ACP_STREAM_SIZE)
        self.assertEqual(parsed.command, 0x15)

    def test_legacy_read_record_round_trips_as_raw_bytes(self):
        record = legacy_setting_json_record(b"\x00\x01\xff")

        self.assertEqual(value_from_json_setting(record), b"\x00\x01\xff")

    def test_legacy_setup_accepts_trace_confirmed_ra1c_advisory_status(self):
        self.assertTrue(legacy_property_status_is_accepted("ra1C", -0xB))
        self.assertTrue(legacy_property_status_is_accepted("ra1C", 0))
        self.assertFalse(legacy_property_status_is_accepted("ra1C", -10))
        self.assertFalse(legacy_property_status_is_accepted("raCh", -0xB))

    def test_acp17_exchange_derives_independent_direction_keys(self):
        class FakeSocket:
            def __init__(self, response):
                self.response = response
                self.sent = bytearray()

            def settimeout(self, _timeout):
                pass

            def sendall(self, data):
                self.sent.extend(data)

            def recv(self, size):
                data, self.response = self.response[:size], self.response[size:]
                return data

            def close(self):
                pass

        client_a, client_b = 7, 11
        server_a, server_b = 13, 17
        response_body = bytearray(304)
        response_body[0] = 1
        response_body[0x10:0x90] = pow(
            LEGACY_DH_GENERATOR, server_a, LEGACY_DH_MODULUS
        ).to_bytes(128, "big")
        response_body[0xA0:0x120] = pow(
            LEGACY_DH_GENERATOR, server_b, LEGACY_DH_MODULUS
        ).to_bytes(128, "big")
        response = make_header(
            bytes(response_body), flags=5, command=COMMAND_LEGACY_KEY_EXCHANGE
        ) + bytes(response_body)
        sock = FakeSocket(response)

        with mock.patch("backend.legacy.connect_acp", return_value=sock):
            transport = open_legacy_encrypted_transport(
                "192.0.2.1",
                "password",
                private_a=client_a,
                private_b=client_b,
                request_iv=b"\x11" * 16,
                response_iv=b"\x22" * 16,
            )

        request = bytes(sock.sent)
        self.assertEqual(parse_header(request[:128]).command, COMMAND_LEGACY_KEY_EXCHANGE)
        self.assertEqual(request[128], 1)
        self.assertEqual(request[128 + 0x90:128 + 0xA0], b"\x11" * 16)
        expected_request_key = hashlib.sha1(
            pow(LEGACY_DH_GENERATOR, client_a * server_a, LEGACY_DH_MODULUS).to_bytes(
                128, "big"
            )
        ).digest()[:16]
        expected_response_key = hashlib.sha1(
            pow(LEGACY_DH_GENERATOR, client_b * server_b, LEGACY_DH_MODULUS).to_bytes(
                128, "big"
            )
        ).digest()[:16]
        self.assertEqual(transport.request_cipher.key, expected_request_key)
        self.assertEqual(transport.response_cipher.key, expected_response_key)
        self.assertTrue(transport.align_calls)
        self.assertEqual(
            transport.client_token,
            bytes.fromhex(
                "7e588b76b36e272b0cac857d868ab517"
                "3e09c835f431657f3c9cb56d969aa507"
            ),
        )

    def test_acp17_streaming_write_sends_each_property_header_and_value(self):
        class FakeTransport:
            def __init__(self):
                self.headers = []
                self.records = []
                self.sock = mock.Mock()

            def send_stream_header(self, flags, command):
                self.headers.append((flags, command))

            def send_encrypted_stream(self, data):
                self.records.append(data)

            def recv(self):
                return ACPHeader(body_size=0, flags=5, command=0x15, status=0), b""

        transport = FakeTransport()
        with mock.patch(
            "backend.legacy.open_legacy_encrypted_transport", return_value=transport
        ):
            statuses = send_property_write_streaming_acp17(
                "192.0.2.1", "public", {"syNm": "spaceship"}, 5.0
            )

        self.assertEqual(statuses, [])
        self.assertEqual(transport.headers, [(4, 0x15)])
        self.assertEqual(len(transport.records), 4)
        self.assertEqual(transport.records[0][:4], b"syNm")
        self.assertEqual(transport.records[1], b"spaceship")
        self.assertEqual(transport.records[2][:4], b"\x00\x00\x00\x00")
        self.assertEqual(transport.records[3], b"\x00\x00\x00\x00")
        transport.sock.close.assert_called_once()


class AirportBackendSessionTests(unittest.TestCase):
    def test_open_encrypted_transport_closes_socket_when_authentication_fails(self):
        class DummySocket:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        sock = DummySocket()

        with mock.patch.object(airport_backend, "connect_acp", return_value=sock), mock.patch.object(
            airport_backend, "authenticate", side_effect=RuntimeError("auth failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "auth failed"):
                airport_backend.open_encrypted_transport("time-capsule.local", "secret")

        self.assertTrue(sock.closed)

    def test_open_encrypted_transport_closes_socket_when_key_derivation_fails(self):
        class DummySocket:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        class DummyAuth:
            session_key = b"session"
            request_iv = b"request"
            response_iv = b"response"

        sock = DummySocket()

        with mock.patch.object(airport_backend, "connect_acp", return_value=sock), mock.patch.object(
            airport_backend, "authenticate", return_value=DummyAuth()
        ), mock.patch.object(
            airport_backend, "derive_keys", side_effect=RuntimeError("keys failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "keys failed"):
                airport_backend.open_encrypted_transport("time-capsule.local", "secret")

        self.assertTrue(sock.closed)


class SRPHelperTests(unittest.TestCase):
    def test_integer_encoding_matches_minimal_big_endian_form(self):
        self.assertEqual(int_to_bytes(0), b"\x00")
        self.assertEqual(int_to_bytes(0x1234), b"\x12\x34")
        self.assertEqual(int_to_padded_bytes(0x1234, 4), b"\x00\x00\x12\x34")

    def test_xor_requires_equal_lengths(self):
        self.assertEqual(xor_bytes(b"\x0f\xf0", b"\xf0\x0f"), b"\xff\xff")
        with self.assertRaises(ValueError):
            xor_bytes(b"\x00", b"\x00\x00")

    def test_derive_keys_uses_expected_airport_salts_and_round_counts(self):
        session_key = bytes(range(40))

        self.assertEqual(
            derive_keys(session_key),
            (
                hashlib.pbkdf2_hmac("sha1", session_key, ACP_REQUEST_SALT, 5, 16),
                hashlib.pbkdf2_hmac("sha1", session_key, ACP_RESPONSE_SALT, 7, 16),
            ),
        )


class DiskInventoryTests(unittest.TestCase):
    def test_matching_partitions_filters_built_in_and_external_disks(self):
        mast = [
            {
                "deviceName": "wd0",
                "builtIn": True,
                "partitions": [{"name": "Data", "uuid": b"\x11" * 16}],
            },
            {
                "deviceName": "usb0",
                "builtIn": False,
                "partitions": [{"name": "Archive", "uuid": b"\x22" * 16}],
            },
        ]

        self.assertEqual(matching_partitions(mast, None, None, True)[0][1]["name"], "Data")
        self.assertEqual(
            matching_partitions(mast, None, None, False)[0][1]["name"], "Archive"
        )

    def test_build_erase_options_falls_back_to_built_in_disk_without_partitions(self):
        mast = [
            {
                "deviceName": "wd0",
                "builtIn": True,
                "uuid": b"\x11" * 16,
                "partitions": [],
            }
        ]

        options, selected = build_erase_disk_options_from_mast(mast, "quick", None, None, None)

        self.assertEqual(options["method"], 0)
        self.assertEqual(options["volumeName"], "Data")
        self.assertEqual(options["uuid"], b"\x11" * 16)
        self.assertIn("wd0", selected)

    def test_build_archive_options_checks_destination_capacity(self):
        mast = [
            {
                "deviceName": "wd0",
                "builtIn": True,
                "partitions": [{"name": "Data", "uuid": b"\x11" * 16, "sizeUsed": 900}],
            },
            {
                "deviceName": "usb0",
                "builtIn": False,
                "partitions": [{"name": "Archive", "uuid": b"\x22" * 16, "sizeFree": 800}],
            },
        ]

        with self.assertRaisesRegex(ValueError, "insufficient free space"):
            build_archive_disk_options_from_mast(mast, None, None, None, None, None, None)

    def test_parse_uuid_bytes_accepts_dashed_hex_uuid(self):
        self.assertEqual(
            parse_uuid_bytes("11111111-1111-1111-1111-111111111111"),
            b"\x11" * 16,
        )


class SettingsMappingTests(unittest.TestCase):
    def parse_settings_args(self, args):
        parser = argparse.ArgumentParser()
        add_network_arguments(parser)
        return parser.parse_args(args)

    def test_setup_over_wan_false_writes_all_remote_management_blocks(self):
        args = self.parse_settings_args(["--no-allow-setup-over-wan"])

        self.assertEqual(
            build_network_dirty_plist(args),
            {
                "raWB": False,
                "raNA": True,
                "waNM": True,
                "raDS": True,
            },
        )

    def test_wds_peer_list_uses_fixed_eight_byte_slots(self):
        self.assertEqual(
            wds_node_list_value(["00:1f:f3:c9:62:99", "00-11-22-33-44-55"]),
            b"\x00\x1f\xf3\xc9b\x99\x00\x00\x00\x11\x22\x33\x44\x55\x00\x00",
        )

    def test_modem_options_use_captured_legacy_property_values(self):
        args = self.parse_settings_args(
            [
                "--connect-using", "modem",
                "--modem-phone-number", "1234567890",
                "--modem-alternate-number", "0123456789",
                "--modem-account", "jack-account",
                "--modem-password", "wowpassword",
                "--modem-idle-seconds", "900",
                "--modem-country-code", "36",
                "--modem-protocol", "v90",
                "--no-modem-pulse-dialing",
                "--modem-automatically-dial",
                "--modem-ignore-dial-tone",
                "--no-modem-use-aol",
            ]
        )

        dirty = build_network_dirty_plist(args)

        self.assertEqual(dirty["waCV"], 0x0900)
        self.assertEqual(dirty["moPN"], "1234567890")
        self.assertEqual(dirty["moAP"], "0123456789")
        self.assertEqual(dirty["moUN"], "jack-account")
        self.assertEqual(dirty["moPW"], "wowpassword")
        self.assertEqual(dirty["moID"], 900)
        self.assertEqual(dirty["moCI"], 36)
        self.assertEqual(dirty["moMP"], 2)
        self.assertFalse(dirty["moPD"])
        self.assertTrue(dirty["moAD"])
        self.assertTrue(dirty["moDT"])
        self.assertEqual(dirty["moMF"], 0)

    def test_legacy_dhcp_uses_captured_ethernet_value(self):
        args = airport_backend.build_parser().parse_args(
            ["192.0.2.1", "--password", "public", "--connect-using", "dhcp"]
        )

        self.assertEqual(airport_backend.build_dirty(args)["waCV"], 0x0300)

    def test_advanced_options_use_captured_spaceship_properties(self):
        args = self.parse_settings_args(
            [
                "--syslog-destination", "192.168.5.6",
                "--syslog-level", "7",
                "--snmp-access-flags", "0",
                "--ppp-dial-in-enabled",
                "--ppp-dial-in-account", "pppaccount",
                "--ppp-dial-in-password", "ppppassword",
                "--ppp-dial-in-answer-on-ring", "4",
                "--ppp-dial-in-idle-seconds", "1200",
                "--ppp-dial-in-maximum-connect-seconds", "14400",
            ]
        )
        self.assertEqual(
            build_network_dirty_plist(args),
            {
                "slCl": "192.168.5.6",
                "slvl": 7,
                "snAF": 0,
                "pdFl": 1,
                "pdUN": "pppaccount",
                "pdPW": "ppppassword",
                "pdAR": 4,
                "pdID": 1200,
                "pdMC": 14400,
            },
        )

    def test_secondary_radius_port_can_change_without_repeating_address(self):
        args = self.parse_settings_args(["--radius-secondary-port", "1813"])

        self.assertEqual(build_network_dirty_plist(args), {"raU2": 1813})

    def test_each_standalone_friendly_flag_is_detected_as_a_setting_change(self):
        for arguments in (
            ["--ipv6-firewall"],
            ["--dynamic-global-hostname-auto-config"],
            ["--wds-mode", "remote"],
        ):
            with self.subTest(arguments=arguments):
                self.assertTrue(
                    has_friendly_setting_options(self.parse_settings_args(arguments))
                )

    def test_spaceship_legacy_options_use_captured_properties_and_widths(self):
        args = self.parse_settings_args(
            [
                "--base-station-contact", "Network Admin",
                "--base-station-location", "New York",
                "--time-server", "time.apple.com",
                "--multicast-rate", "85",
                "--transmit-power", "50",
                "--group-key-timeout-seconds", "7200",
                "--interference-robustness",
                "--dhcp-message", "Welcome",
                "--ldap-server", "ldap.example.test",
                "--access-control-mode", "local",
                "--access-control-entries-json",
                '[{"macAddress":"44:23:33:33:33:33","description":"test"}]',
            ]
        )

        dirty = build_network_dirty_plist(args)
        self.assertEqual(dirty["syCt"], "Network Admin")
        self.assertEqual(dirty["syLo"], "New York")
        self.assertEqual(dirty["ntSV"], "time.apple.com")
        self.assertEqual(dirty["raMu"], 85)
        self.assertEqual(dirty["raPo"], 50)
        self.assertEqual(dirty["raKT"], 7200)
        self.assertTrue(dirty["raRo"])
        self.assertEqual(dirty["dhMg"], "Welcome")
        self.assertEqual(dirty["dh95"], "ldap.example.test")
        self.assertTrue(dirty["acEn"])
        self.assertEqual(dirty["raFl"], 0)
        self.assertEqual(len(dirty["acTa"]), 56)
        self.assertEqual(dirty["acTa"][16:22], bytes.fromhex("442333333333"))
        self.assertEqual(encode_setting_value("raPo", 50), b"\x00\x32")


class IntentNormalizationTests(unittest.TestCase):
    def test_modern_write_intent_redacts_sensitive_values(self):
        intent = normalized_modern_write_intent(
            "time-capsule.local",
            {"syPW": "secret", "raNm": "Network"},
        )

        properties = intent["operations"][0]["properties"]
        password = next(item for item in properties if item["name"] == "syPW")
        network_name = next(item for item in properties if item["name"] == "raNm")
        self.assertEqual(password["value"], {"redacted": True, "length": 6})
        self.assertEqual(password["encoded"], {"redacted": True, "length": 6})
        self.assertEqual(network_name["value"], "Network")

    def test_value_from_json_setting_rehydrates_bytes(self):
        self.assertEqual(
            value_from_json_setting({"type": "bytes", "hex": "0102"}),
            b"\x01\x02",
        )


class FirmwareHelperTests(unittest.TestCase):
    def test_source_summary_and_bytes_use_local_file_size(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b"firmware")
            path = handle.name
        try:
            self.assertIn("(8 bytes)", firmware_source_summary(path))
            self.assertEqual(firmware_source_bytes(path), b"firmware")
        finally:
            os.unlink(path)

    def test_parse_firmware_image_info_validates_checksum(self):
        body = bytearray(0x30)
        body[: len(FIRMWARE_MAGIC)] = FIRMWARE_MAGIC
        body[len(FIRMWARE_MAGIC)] = 0
        body[0x0F] = 7
        body[0x10:0x14] = (1234).to_bytes(4, "big")
        body[0x14:0x18] = (5678).to_bytes(4, "big")
        body[0x1B] = 9
        firmware = bytes(body) + acp_adler32(body).to_bytes(4, "big")

        info = parse_firmware_image_info(firmware)

        self.assertEqual(info["productID"], 1234)
        self.assertEqual(info["sourceVersionRaw"], 5678)
        self.assertEqual(info["versionByte"], 7)
        self.assertEqual(info["metadataByte"], 9)

    def test_parse_firmware_progress_reports_completion(self):
        self.assertEqual(
            parse_firmware_progress(b"96/96\x00"),
            {"current": 96, "total": 96, "raw": "96/96", "complete": True},
        )

    def test_mac_helpers_accept_text_and_derive_link_local_address(self):
        self.assertEqual(parse_mac_address("00-1f-f3-c9-62-99"), b"\x00\x1f\xf3\xc9b\x99")
        self.assertEqual(
            firmware_link_local_address_from_mac("00:1f:f3:c9:62:99"),
            "fe80::21f:f3ff:fec9:6299",
        )

    def test_firmware_upload_host_candidates_prefers_derived_link_local(self):
        original_route = firmware_module.route_interface_for_host
        original_resolved = firmware_module.resolved_ipv6_link_local_hosts
        try:
            firmware_module.route_interface_for_host = lambda host: "en0"
            firmware_module.resolved_ipv6_link_local_hosts = lambda host: []

            self.assertEqual(
                firmware_upload_host_candidates(
                    "192.168.4.45",
                    {"wanMACAddress": "00:1f:f3:c9:62:99"},
                ),
                ["fe80::21f:f3ff:fec9:6299%en0", "192.168.4.45"],
            )
        finally:
            firmware_module.route_interface_for_host = original_route
            firmware_module.resolved_ipv6_link_local_hosts = original_resolved


class ModernPropertyTests(unittest.TestCase):
    def test_property_response_rejects_unexpected_command(self):
        class FakeTransport:
            def send(self, body, flags, command):
                pass

            def recv(self):
                return ACPHeader(0, 0, 0x15, 0), b""

        with self.assertRaisesRegex(RuntimeError, "response command mismatch"):
            read_properties(FakeTransport(), ["syNm"])

    def test_rpc_response_rejects_unexpected_command(self):
        class FakeTransport:
            def send(self, body, flags, command):
                pass

            def recv(self):
                return ACPHeader(0, 0, 0x14, 0), b""

        with self.assertRaisesRegex(RuntimeError, "response command mismatch"):
            rpc_call(FakeTransport(), "parseDirtyPlist", {}, flags=4)

    def test_fixed_property_response_rejects_truncated_value(self):
        class FakeTransport:
            def send(self, body, flags, command):
                pass

            def recv(self):
                body = ACP_PROPERTY_HEADER.pack(b"syNm", 0, 5) + b"Air"
                return ACPHeader(len(body), 0, 0x14, 0), body

        with self.assertRaisesRegex(
            RuntimeError,
            "truncated value for property syNm",
        ):
            read_properties(FakeTransport(), ["syNm"])

    def test_fixed_property_response_rejects_partial_trailing_header(self):
        class FakeTransport:
            def send(self, body, flags, command):
                pass

            def recv(self):
                body = ACP_PROPERTY_HEADER.pack(b"syNm", 0, 3) + b"Air" + b"\x00"
                return ACPHeader(len(body), 0, 0x14, 0), body

        with self.assertRaisesRegex(
            RuntimeError,
            "truncated property record header",
        ):
            read_properties(FakeTransport(), ["syNm"])

    def test_uint64_profile_sentinel_round_trips_without_double_precision_loss(self):
        sentinel = (1 << 64) - 1
        json_value = json_safe_cfb0({"expiryTime": sentinel})

        self.assertEqual(
            json_value,
            {"expiryTime": {"type": "integer", "decimal": "18446744073709551615"}},
        )
        self.assertEqual(value_from_json_setting(json_value), {"expiryTime": sentinel})

    def test_nested_cfb0_bytes_compare_as_decoded_semantic_values(self):
        profile = {"restoreProfile": {"syNm": "capsule", "syPW": "password"}}

        prop = normalized_dirty_properties({"Prof": cfb0_dumps(profile)})[0]

        self.assertEqual(prop["value"]["restoreProfile"]["syNm"], "capsule")
        self.assertEqual(prop["value"]["restoreProfile"]["syPW"], {"redacted": True, "length": 8})
        self.assertIn("encoded", prop)

    def test_ordered_multi_value_write_uses_one_dirty_transaction(self):
        values = '{"syNm":"capsule","raWB":true,"blob":{"type":"bytes","hex":"0102"}}'
        with mock.patch.object(
            airport_backend, "write_dirty_settings", return_value=({}, None)
        ) as write, mock.patch.object(airport_backend, "add_profile_backed_dirty_settings"):
            result = airport_backend.modern_write_main(
                ["192.0.2.1", "--password", "public", "--values-json", values]
            )

        self.assertEqual(result, 0)
        dirty = write.call_args.args[2]
        self.assertEqual(list(dirty), ["syNm", "raWB", "blob"])
        self.assertEqual(dirty, {"syNm": "capsule", "raWB": True, "blob": b"\x01\x02"})

    def test_no_verify_skips_password_readback_after_atomic_setup(self):
        values = '{"syNm":"capsule","syPW":"password"}'
        with mock.patch.object(
            airport_backend, "write_dirty_settings", return_value=({}, None)
        ) as write, mock.patch.object(airport_backend, "add_profile_backed_dirty_settings"):
            result = airport_backend.modern_write_main(
                [
                    "192.0.2.1", "--password", "public", "--values-json", values,
                    "--no-verify",
                ]
            )

        self.assertEqual(result, 0)
        self.assertIsNone(write.call_args.kwargs["verify_setting"])
        self.assertIsNone(write.call_args.kwargs["readback_setting"])

    def test_legacy_ordered_multi_value_write_uses_one_property_transaction(self):
        values = '{"syNm":"express","acFN":{"type":"bytes","hex":""},"acRB":{"type":"bytes","hex":""}}'
        with mock.patch.object(airport_backend, "send_property_write", return_value=[]) as write:
            result = airport_backend.legacy_write_main(
                ["192.0.2.1", "--password", "public", "--values-json", values]
            )

        self.assertEqual(result, 0)
        dirty = write.call_args.args[2]
        self.assertEqual(list(dirty), ["syNm", "acFN", "acRB"])
        self.assertEqual(dirty, {"syNm": "express", "acFN": b"", "acRB": b""})

    def test_product_three_write_selects_acp17_transport(self):
        values = '{"syNm":"spaceship","acRB":{"type":"bytes","hex":""}}'
        with mock.patch.object(
            airport_backend, "send_property_write_streaming_acp17", return_value=[]
        ) as write:
            result = airport_backend.legacy_write_main(
                [
                    "192.0.2.1", "--password", "public", "--values-json", values,
                    "--streaming", "--acp17",
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(write.call_args.args[1], "public")
        self.assertEqual(write.call_args.args[2], {"syNm": "spaceship", "acRB": b""})

    def test_modern_property_write_uses_authenticated_encrypted_stream(self):
        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

        transport = object()
        with mock.patch.object(
            airport_backend,
            "open_encrypted_transport",
            return_value=(FakeSocket(), transport),
        ) as open_transport, mock.patch.object(
            airport_backend,
            "send_property_stream",
        ) as send_stream:
            airport_backend.write_property_stream(
                "extreme.local",
                "secret",
                "acRB",
                b"",
                request_flags=0,
            )

        open_transport.assert_called_once_with("extreme.local", "secret")
        send_stream.assert_called_once_with(
            transport,
            "acRB",
            b"",
            request_flags=0,
        )

    def test_modern_property_write_command_decodes_empty_bytes_and_flags(self):
        with mock.patch.object(
            airport_backend,
            "write_property_stream",
        ) as write, mock.patch(
            "sys.argv",
            [
                "airport_backend.py",
                "property-write",
                "extreme.local",
                "--password",
                "secret",
                "--setting",
                "acRB",
                "--value-json",
                '{"type":"bytes","hex":""}',
                "--request-flags",
                "0",
            ],
        ):
            result = airport_backend.main()

        self.assertEqual(result, 0)
        write.assert_called_once_with(
            "extreme.local",
            "secret",
            "acRB",
            b"",
            request_flags=0,
        )

    def test_legacy_nonzero_wds_flags_omit_stale_peer_list_from_base_snapshot(self):
        base = (
            '{"wdLs":{"type":"bytes","hex":"00000000000000000000000000000000"},'
            '"wdFl":{"type":"bytes","hex":"00000000"}}'
        )
        values = '{"wdFl":{"type":"bytes","hex":"00000006"}}'
        with mock.patch.object(airport_backend, "send_property_write", return_value=[]) as write:
            result = airport_backend.legacy_write_main(
                [
                    "192.0.2.1",
                    "--password",
                    "public",
                    "--base-values-json",
                    base,
                    "--values-json",
                    values,
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(write.call_args.args[2], {"wdFl": b"\x00\x00\x00\x06"})

    def test_setup_completion_can_commit_admin_password_atomically(self):
        with mock.patch.object(
            airport_backend, "write_dirty_settings", return_value=({}, None)
        ) as write, mock.patch.object(airport_backend, "add_profile_backed_dirty_settings"):
            result = airport_backend.modern_write_main(
                [
                    "192.0.2.1",
                    "--password",
                    "public",
                    "--setting",
                    "syPW",
                    "--value",
                    "new-password",
                    "--setup-complete",
                    "--setup-complete-timestamp",
                    "1234",
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(write.call_args.args[2], {"syPW": "new-password", "ctim": 1234})

    def test_property_request_and_record_round_trip(self):
        record = property_request("sySN")

        self.assertEqual(parse_property_record(record), ("sySN", 0, 0))

    def test_handle_property_result_assigns_anonymous_record_to_next_setting(self):
        results: dict[str, bytes] = {}
        errors: dict[str, str] = {}

        should_stop = handle_property_result(["sySN"], results, errors, None, 0, b"serial")

        self.assertFalse(should_stop)
        self.assertEqual(results, {"sySN": b"serial"})
        self.assertEqual(errors, {})

    def test_format_value_prefers_printable_text_then_u32(self):
        self.assertEqual(format_value(b"AirPort\x00"), "AirPort")
        self.assertEqual(format_value((42).to_bytes(4, "big")), "42")
        self.assertEqual(format_value(b"\xff\x00"), "ff00")

    def test_profile_path_get_reads_nested_array_value(self):
        profile = {"restoreProfile": {"WiFi": {"radios": [{"raNm": "Network"}]}}}

        self.assertEqual(
            profile_path_get(profile, "restoreProfile.WiFi.radios[0].raNm"),
            "Network",
        )

    def test_setting_json_record_includes_decoded_cfb0(self):
        raw = cfb0_dumps({"name": "AirPort", "blob": b"\x01\x02"})

        record = setting_json_record(raw)

        self.assertEqual(record["decoded"]["name"], "AirPort")
        self.assertEqual(record["decoded"]["blob"]["hex"], "0102")


class LegacyProtocolTests(unittest.TestCase):
    def test_compose_header_round_trips_through_legacy_parser(self):
        payload = compose_property_element("syNm", None)
        header = compose_header(COMMAND_GETPROP, "secret", payload, flags=4)

        command, error_code, body_size, body_checksum = legacy_parse_header(header)

        self.assertEqual(command, COMMAND_GETPROP)
        self.assertEqual(error_code, 0)
        self.assertEqual(body_size, len(payload))
        self.assertEqual(body_checksum, struct.unpack(">i", header[12:16])[0])

    def test_parse_property_results_decodes_fixed_body_records(self):
        body = compose_property_element("syNm", b"Express")

        self.assertEqual(parse_property_results(body), [("syNm", 0, b"Express")])

    def test_encode_setting_value_uses_legacy_special_cases(self):
        self.assertEqual(encode_setting_value("auRR", True), b"\x00\x01")
        self.assertEqual(encode_setting_value("raMd", 3), b"\x00\x03")
        self.assertEqual(encode_setting_value("waIP", "192.168.1.1"), b"\xc0\xa8\x01\x01")
        self.assertEqual(encode_setting_value("slCl", "192.168.5.6"), b"\xc0\xa8\x05\x06")


if __name__ == "__main__":
    unittest.main()

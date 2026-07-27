import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "replay_airport_trace_contract",
    ROOT / "tools" / "replay_airport_trace_contract.py",
)
assert SPEC is not None and SPEC.loader is not None
replay = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = replay
SPEC.loader.exec_module(replay)

APP_SPEC = importlib.util.spec_from_file_location(
    "replay_airport_trace_app",
    ROOT / "tools" / "replay_airport_trace_app.py",
)
assert APP_SPEC is not None and APP_SPEC.loader is not None
app_replay = importlib.util.module_from_spec(APP_SPEC)
sys.modules[APP_SPEC.name] = app_replay
APP_SPEC.loader.exec_module(app_replay)


class TraceReplayComparisonTests(unittest.TestCase):
    def test_redacted_value_matches_captured_bytes_by_length(self):
        self.assertTrue(
            replay.values_match(
                {"type": "bytes", "hex": "", "length": 0},
                {"redacted": True, "length": 0},
            )
        )
        self.assertTrue(
            replay.values_match(
                {"type": "bytes", "hex": "736563726574", "length": 6},
                {"redacted": True, "length": 6},
            )
        )
        self.assertFalse(
            replay.values_match(
                {"type": "bytes", "hex": "736563726574", "length": 6},
                {"redacted": True, "length": 5},
            )
        )

    def test_structured_expected_value_falls_back_to_matching_encoded_bytes(self):
        encoded = {"type": "bytes", "hex": "43464230454e4421", "length": 8}
        expected = {
            "name": "DRes",
            "value": {"dhcpReservations": []},
            "encoded": encoded,
        }
        actual = {
            "name": "DRes",
            "value": encoded,
            "encoded": encoded,
        }

        self.assertEqual(replay.comparison_values(expected, actual), (encoded, encoded))

    def test_structured_values_still_compare_semantically(self):
        expected_value = {"dhcpReservations": [{"ipv4Address": "192.168.1.2"}]}
        actual_value = {"dhcpReservations": [{"ipv4Address": "192.168.1.2"}]}

        self.assertEqual(
            replay.comparison_values(
                {"name": "DRes", "value": expected_value},
                {"name": "DRes", "value": actual_value},
            ),
            (expected_value, actual_value),
        )

    def test_legacy_snapshot_sequence_drops_transient_properties(self):
        def prop(name, raw_hex):
            return {
                "name": name,
                "encoded": {
                    "type": "bytes",
                    "hex": raw_hex,
                    "length": len(raw_hex) // 2,
                },
            }

        contract = {
            "protocol": {
                "operations": [
                    {
                        "legacyFullConfigWrite": True,
                        "fullProperties": [prop("syNm", "6f6e65"), prop("pmTa", "00")],
                    },
                    {
                        "legacyFullConfigWrite": True,
                        "fullProperties": [prop("syNm", "74776f")],
                    },
                ]
            }
        }

        sequence = app_replay.legacy_settings_sequence_from_contract(contract)

        self.assertEqual(len(sequence), 2)
        self.assertIn("pmTa", sequence[0])
        self.assertNotIn("pmTa", sequence[1])

    def test_legacy_raw_snapshot_avoids_hidden_pppoe_and_disk_controls(self):
        def prop(name, raw_hex):
            return {
                "name": name,
                "value": {
                    "type": "bytes",
                    "hex": raw_hex,
                    "length": len(raw_hex) // 2,
                },
                "encoded": {
                    "type": "bytes",
                    "hex": raw_hex,
                    "length": len(raw_hex) // 2,
                },
            }

        properties = [
            prop("waCV", "00000900"),
            prop("peUN", ""),
            prop("usbF", "00000002"),
        ]
        scenario = app_replay.actions_for_operation(
            {
                "id": "legacy-flow-001-000",
                "kind": "property-write",
                "legacyFullConfigWrite": True,
                "properties": properties,
                "fullProperties": properties,
            }
        )
        identifiers = [action.identifier for action in scenario.actions]

        self.assertNotIn("internet.pppoe.account", identifiers)
        self.assertNotIn("sheet.tab.disks", identifiers)
        self.assertIn("base.station.advanced.acp.json", identifiers)


if __name__ == "__main__":
    unittest.main()

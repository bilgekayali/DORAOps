import json
from pathlib import Path
import unittest

import doraops

ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def test_version(self):
        self.assertEqual(doraops.__version__, "0.1.0")

    def test_arrangement_schema(self):
        schema = json.loads((ROOT / "schemas/ict-arrangement.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["const"], "doraops.ict-arrangement.v1")


if __name__ == "__main__":
    unittest.main()

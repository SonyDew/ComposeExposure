import tempfile
import unittest
from pathlib import Path

from compose_exposure.audit import ComposeError, compare, inspect, risky


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def parse(self, yaml_text):
        file = Path(self.temp.name) / "compose.yaml"
        file.write_text(yaml_text, encoding="utf-8")
        return inspect(file)

    def test_short_and_long_ports(self):
        records = self.parse('''services:
  api:
    ports:
      - "8080:80"
      - "127.0.0.1:9090:90/udp"
      - "[::1]:5000:5000"
      - target: 443
        published: "8443"
        host_ip: 192.168.1.5
        protocol: tcp
''')
        self.assertEqual({x.scope for x in records}, {"all", "loopback", "specific"})
        self.assertEqual(len(records), 4)
        self.assertTrue(any(x.protocol == "udp" for x in records))

    def test_dynamic_and_ranges(self):
        records = self.parse('''services:
  web:
    ports:
      - "80"
      - "8080-8082:80-82"
      - "127.0.0.1::443"
''')
        self.assertEqual(len(records), 3)
        self.assertEqual(sum(x.published == "dynamic" for x in records), 2)
        self.assertTrue(any(x.published == "8080-8082" for x in records))

    def test_interpolation_does_not_split_default_colon(self):
        records = self.parse('''services:
  web:
    ports:
      - "${BIND:-127.0.0.1}:${PORT:-8080}:80"
''')
        self.assertEqual(records[0].scope, "unknown")
        self.assertEqual(records[0].published, "${PORT:-8080}")

    def test_host_network_and_expose(self):
        records = self.parse('''services:
  hoster:
    network_mode: host
  private:
    expose: ["3000"]
''')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].kind, "host-network")
        self.assertTrue(risky(records, "all"))

    def test_specific_is_nonlocal_not_all(self):
        records = self.parse('''services:
  api:
    ports: ["192.168.1.1:8080:80"]
''')
        self.assertFalse(risky(records, "all"))
        self.assertTrue(risky(records, "nonlocal"))

    def test_comparison(self):
        old = self.parse('''services:
  api:
    ports: ["127.0.0.1:8080:80"]
''')
        new = self.parse('''services:
  api:
    ports: ["8080:80"]
''')
        diff = compare(old, new)
        self.assertEqual(diff["added"][0].scope, "all")
        self.assertEqual(diff["removed"][0].scope, "loopback")

    def test_duplicate_keys_rejected(self):
        with self.assertRaisesRegex(ComposeError, "Duplicate YAML key"):
            self.parse('''services:
  api:
    ports: ["8080:80"]
    ports: ["9090:90"]
''')

    def test_invalid_entries_rejected(self):
        for port in ('true', '"70000:80"', '"9000-8000:80"', '{published: 80}', '"[::1:80:80"'):
            with self.subTest(port=port), self.assertRaises(ComposeError):
                self.parse("services:\n  api:\n    ports: [" + port + "]\n")

    def test_missing_services_rejected(self):
        with self.assertRaises(ComposeError):
            self.parse('version: "3.9"\n')

    def test_deduplicates_ports(self):
        records = self.parse('''services:
  api:
    ports: ["8080:80", "8080:80"]
''')
        self.assertEqual(len(records), 1)


if __name__ == "__main__":
    unittest.main()

import unittest

import shadowscan


class TestParsing(unittest.TestCase):
    def test_parse_ports_single(self):
        self.assertEqual(shadowscan._parse_ports("80"), {80})

    def test_parse_ports_range(self):
        self.assertEqual(shadowscan._parse_ports("20-22"), {20, 21, 22})

    def test_parse_ports_mixed(self):
        self.assertEqual(shadowscan._parse_ports("22,80,100-101"), {22, 80, 100, 101})

    def test_parse_csv_lower(self):
        self.assertEqual(shadowscan._parse_csv_lower("HTTP,https"), {"http", "https"})


class TestFilters(unittest.TestCase):
    def test_filter_services_by_port(self):
        rows = [
            shadowscan.ServiceRow(80, "tcp", "http", "nginx", "", "", tuple(), tuple()),
            shadowscan.ServiceRow(22, "tcp", "ssh", "OpenSSH", "", "", tuple(), tuple()),
        ]
        out = shadowscan._filter_services(rows, ports={22}, protos=None, services_allow=None, grep_re=None)
        self.assertEqual([r.port for r in out], [22])


if __name__ == "__main__":
    unittest.main()

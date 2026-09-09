import unittest
from hop_analyzer import is_public_ip


class TestHopAnalyzer(unittest.TestCase):

    def test_private_ip(self):
        self.assertFalse(is_public_ip("192.168.1.10"))

    def test_loopback_ip(self):
        self.assertFalse(is_public_ip("127.0.0.1"))

    def test_public_ip(self):
        self.assertTrue(is_public_ip("8.8.8.8"))

    def test_invalid_ip(self):
        self.assertFalse(is_public_ip("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
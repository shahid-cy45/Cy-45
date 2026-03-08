import unittest

from firewall import ChildSafetyFirewall


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.firewall = ChildSafetyFirewall()

    def test_allows_safe_domain(self):
        decision = self.firewall.inspect_content("https://kids.youtube.com/watch?v=123")
        self.assertTrue(decision.allowed)

    def test_blocks_known_adult_domain(self):
        decision = self.firewall.inspect_content("https://www.xvideos.com/video123")
        self.assertFalse(decision.allowed)

    def test_blocks_keyword(self):
        decision = self.firewall.inspect_content("https://example.com/watch", title="Top XXX clips")
        self.assertFalse(decision.allowed)

    def test_blocks_untrusted_media_mime(self):
        decision = self.firewall.inspect_content(
            "https://example.com/media.mp4", mime_type="video/mp4"
        )
        self.assertFalse(decision.allowed)

    def test_allows_clean_page(self):
        decision = self.firewall.inspect_content("https://www.britannica.com/animals")
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()

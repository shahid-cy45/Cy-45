from firewall import ChildSafetyFirewall, FirewallRules


def test_blocks_known_domain() -> None:
    fw = ChildSafetyFirewall()
    result = fw.inspect(url="https://xvideos.com/video/123")
    assert result.blocked
    assert "blocked_domain" in result.reason


def test_blocks_adult_keyword_in_url() -> None:
    fw = ChildSafetyFirewall()
    result = fw.inspect(url="https://example.com/free-porn-video.mp4")
    assert result.blocked


def test_allows_kids_content_and_sets_safe_search() -> None:
    fw = ChildSafetyFirewall()
    result = fw.inspect(url="https://google.com/search?q=math+for+kids")
    assert not result.blocked
    assert "safe=active" in (result.safe_url or "")


def test_custom_rules_allow_keyword_override() -> None:
    rules = FirewallRules(adult_keywords={"forbiddenword"}, blocked_domains=set(), trusted_domains=set())
    fw = ChildSafetyFirewall(rules)
    result = fw.inspect(url="https://example.com/porn")
    assert not result.blocked

import pytest
from septr.core.sanitize import detect_sqli, detect_xss, detect_nosqli, sanitize_input, sanitize_query, sanitize_string


class TestDetectSQLi:
    def test_detects_union_select(self):
        result = detect_sqli("1 UNION SELECT * FROM users")
        assert len(result) > 0
        assert result[0].patternId == "sqli_union"

    def test_detects_or_1_eq_1(self):
        result = detect_sqli("' OR 1=1 --")
        assert len(result) > 0

    def test_detects_drop_table(self):
        result = detect_sqli("DROP TABLE users")
        assert len(result) > 0

    def test_empty_for_safe(self):
        result = detect_sqli("hello world")
        assert len(result) == 0

    def test_case_insensitive(self):
        result = detect_sqli("union select * from users")
        assert len(result) > 0


class TestDetectXSS:
    def test_detects_script_tag(self):
        result = detect_xss("<script>alert('xss')</script>")
        assert len(result) > 0
        assert result[0].patternId == "xss_script_tag"

    def test_detects_onerror(self):
        result = detect_xss("<img onerror=alert(1)>")
        assert len(result) > 0
        assert result[0].patternId == "xss_onerror"

    def test_empty_for_safe(self):
        result = detect_xss("hello world")
        assert len(result) == 0


class TestSanitizeInput:
    def test_detects_sqli_in_body_string(self):
        block, dets = sanitize_input({"query": "1 UNION SELECT * FROM users"})
        assert block
        assert len(dets) > 0

    def test_returns_false_for_safe_body(self):
        block, dets = sanitize_input({"name": "John", "age": 30})
        assert not block
        assert len(dets) == 0

    def test_nested_dict(self):
        block, dets = sanitize_input({"user": {"name": "<script>alert(1)</script>"}})
        assert block
        assert len(dets) > 0

    def test_list_values(self):
        block, dets = sanitize_input(["DROP TABLE users", "hello"])
        assert block


class TestSanitizeQuery:
    def test_detects_sqli_in_query(self):
        block, dets = sanitize_query({"q": "1 UNION SELECT * FROM users"})
        assert block

    def test_safe_query(self):
        block, dets = sanitize_query({"search": "hello"})
        assert not block

    def test_string_list_values(self):
        block, dets = sanitize_query({"ids": ["1", "DROP TABLE users"]})
        assert block


if __name__ == "__main__":
    pytest.main()


class TestNoSQLi:
    def test_detects_ne_operator(self):
        events = detect_nosqli('{"$ne": null}')
        assert any(e.patternId == "nosqli_ne" for e in events)
        assert events[0].severity == "high"

    def test_detects_where_and_gt(self):
        events = detect_nosqli('{"$where": "sleep(5000)", "price": {"$gt": 0}}')
        ids = {e.patternId for e in events}
        assert "nosqli_where" in ids
        assert "nosqli_gt" in ids

    def test_sanitize_input_catches_nosqli_in_body(self):
        block, dets = sanitize_input({"username": {"$ne": None}, "password": "x"})
        assert block is True
        assert any(d.patternId == "nosqli_ne" for d in dets)

    def test_sanitize_string_catches_nosqli(self):
        dets = sanitize_string('{"$regex": ".*"}')
        assert any(d.patternId == "nosqli_regex" for d in dets)

    def test_clean_input_no_nosqli(self):
        block, dets = sanitize_input({"q": "hello world", "n": 5})
        assert block is False
        assert dets == []


class TestSQLiObfuscation:
    def test_comment_obfuscation_detected(self):
        events = detect_sqli("x' OR/**/1=1--")
        assert any(e.patternId == "sqli_or_1_1" for e in events)

    def test_hex_literal_obfuscation_detected(self):
        # 0x554E494F4E2053454C454354 = "UNION SELECT"
        events = detect_sqli("x' AND 0x554E494F4E2053454C454354--")
        assert any(e.patternId == "sqli_union" for e in events)

    def test_char_calls_detected(self):
        # char(85,78,73,79,78,32,83,69,76,69,67,84) = "UNION SELECT"
        events = detect_sqli("x' AND char(85,78,73,79,78,32,83,69,76,69,67,84)--")
        assert any(e.patternId == "sqli_union" for e in events)

    def test_url_encoded_detected(self):
        events = detect_sqli("x%27%20OR%201%3D1--")
        assert any(e.patternId == "sqli_or_1_1" for e in events)

    def test_combined_obfuscation_detected(self):
        events = detect_sqli("x' UNI/**/ON SEL/**/ECT password FROM admins--")
        assert any(e.patternId == "sqli_union" for e in events)

    def test_benign_text_not_flagged(self):
        assert detect_sqli("hello world") == []
        assert detect_sqli("https://example.com/path?q=search") == []
        assert detect_sqli("what time is it? 5:30") == []
        assert detect_sqli("color code #ff0000 is red") == []

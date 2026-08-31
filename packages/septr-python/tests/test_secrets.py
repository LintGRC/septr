import pytest
from septr.core.secrets import detect_secrets, detect_high_entropy_secrets, should_strip_key


class TestDetectSecrets:
    def test_detects_openai_key(self):
        result = detect_secrets("sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        assert len(result) > 0
        assert result[0].type == "secret_exposure"
        assert "openai" in result[0].patternId

    def test_detects_aws_key(self):
        result = detect_secrets("AKIA" + "XXXXXXXXXXXXXXXX")
        assert len(result) > 0

    def test_detects_aws_secret_access_key(self):
        result = detect_secrets("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12")
        assert any("aws_secret" in r.patternId for r in result)

    def test_rejects_path_like_40char_string_as_aws_secret(self):
        # 40-char URL path (all lowercase + slashes) must NOT match the
        # AWS secret-access-key pattern (real keys are random base64).
        result = detect_secrets("policies/risks/assets/vendors/incidents/")
        assert not any("aws_secret" in r.patternId for r in result)

    def test_rejects_all_lowercase_40char_as_aws_secret(self):
        result = detect_secrets("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstu")
        assert not any("aws_secret" in r.patternId for r in result)

    def test_detects_stripe_live(self):
        result = detect_secrets("sk_live_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        assert len(result) > 0

    def test_detects_stripe_test(self):
        result = detect_secrets("sk_test_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcd")
        assert len(result) > 0
        assert "stripe_test" in result[0].patternId

    def test_empty_for_safe_input(self):
        result = detect_secrets("hello world this is safe")
        assert len(result) == 0

    def test_matches_custom_patterns(self):
        result = detect_secrets("my-secret-token-12345", ["secret-token-\\d+"])
        assert len(result) > 0
        assert result[0].patternId == "secret_custom"

    def test_detects_jwt(self):
        result = detect_secrets("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8")
        assert len(result) > 0

    def test_detects_database_uri(self):
        result = detect_secrets("postgres://user:password@localhost:5432/db")
        assert len(result) > 0

    def test_should_strip_key_empty(self):
        assert should_strip_key("") is False

    def test_should_strip_key_password(self):
        assert should_strip_key("password") is True

    def test_should_strip_key_normalized(self):
        assert should_strip_key("password_hash") is True
        assert should_strip_key("my_password_hash", ["my_password_hash"]) is True

    def test_should_strip_key_case_insensitive(self):
        assert should_strip_key("API_KEY") is True

    def test_should_strip_key_custom_fields(self):
        assert should_strip_key("custom_secret", ["custom_secret"]) is True


if __name__ == "__main__":
    pytest.main()


class TestNewPatterns:
    def test_openai_service_account(self):
        events = detect_secrets("sk-svcacct-abcdefghijklmnopqrstuvwxyz123456")
        assert any(e.patternId == "secret_openai_svc" for e in events)

    def test_github_fine_grained(self):
        events = detect_secrets("github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
        assert any(e.patternId == "secret_github_fine_grained" for e in events)

    def test_twilio(self):
        events = detect_secrets("SK0123456789abcdef" + "0123456789abcdef")
        assert any(e.patternId == "secret_twilio" for e in events)

    def test_slack_webhook(self):
        events = detect_secrets("https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX")
        assert any(e.patternId == "secret_slack_webhook" for e in events)

    def test_shopify(self):
        events = detect_secrets("shpat_" + "0123456789abcdef0123456789abcdef")
        assert any(e.patternId == "secret_shopify" for e in events)

    def test_discord_bot(self):
        events = detect_secrets("M0gQ1w2E3r4T5y6U7i8O9p0a.abcdef.ABCDEFGHIJKLMNOPQRSTUVWXYZA")
        assert any(e.patternId == "secret_discord_bot" for e in events)

    def test_google_client_secret(self):
        events = detect_secrets("GOCSPX-abcdefghijklmnopqrstuvwxyz123456")
        assert any(e.patternId == "secret_google_client_secret" for e in events)

    def test_azure_storage(self):
        events = detect_secrets("AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuvwxyzABCDEFGH==")
        assert any(e.patternId == "secret_azure_storage" for e in events)


class TestSupabaseServiceRole:
    def _jwt(self, role):
        import base64
        import json
        def b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        return f"{b64({'alg': 'HS256'})}.{b64({'role': role})}.signature"

    def test_service_role_detected(self):
        events = detect_secrets(self._jwt("service_role"))
        assert any(e.patternId == "secret_supabase_service_role" for e in events)
        ev = next(e for e in events if e.patternId == "secret_supabase_service_role")
        assert ev.severity == "critical"

    def test_anon_role_not_flagged_as_service_role(self):
        events = detect_secrets(self._jwt("anon"))
        assert not any(e.patternId == "secret_supabase_service_role" for e in events)


class TestSupabaseAnonAdvisory:
    def _jwt(self, role):
        import base64
        import json
        def b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        return f"{b64({'alg': 'HS256'})}.{b64({'role': role})}.signature"

    def test_anon_key_is_advisory_only(self):
        events = detect_secrets(self._jwt("anon"))
        anon_events = [e for e in events if e.patternId == "secret_supabase_anon"]
        assert len(anon_events) == 1
        assert anon_events[0].severity == "low"
        assert anon_events[0].redactable is False

    def test_anon_jwt_not_flagged_as_generic_jwt(self):
        events = detect_secrets(self._jwt("anon"))
        assert not any(e.patternId == "secret_generic_jwt" for e in events)

    def test_service_role_still_critical(self):
        events = detect_secrets(self._jwt("service_role"))
        svc = [e for e in events if e.patternId == "secret_supabase_service_role"]
        assert len(svc) == 1
        assert svc[0].severity == "critical"
        assert svc[0].redactable is not False


class TestGoogleAPIAdvisory:
    def test_google_api_is_low_and_non_redactable(self):
        events = detect_secrets("AIzaSy" + "BQom12tzI-rybN7Sf-KfeL4nwm-Rf7PmI")
        google = [e for e in events if e.patternId == "secret_google_api"]
        assert len(google) == 1
        assert google[0].severity == "low"
        assert google[0].redactable is False


class TestPublishableKeyEntropy:
    def test_publishable_keys_not_flagged_by_entropy(self):
        inputs = [
            '{"apiKey": "pk_live_abc123def456ghi789"}',
            '{"apiKey": "pk_test_abc123def456ghi789"}',
            '{"apiKey": "pk_prod_abc123def456ghi789"}',
            '{"apiKey": "pk.abc123def456ghi789jkl012mno"}',
            '{"apiKey": "phc_abc123def456ghi789jkl012mno"}',
            '{"apiKey": "phx_abc123def456ghi789jkl012mno"}',
        ]
        for input_str in inputs:
            events = detect_high_entropy_secrets(input_str)
            assert not any(e.patternId == "secret_high_entropy" for e in events), f"publishable key should not be flagged: {input_str}"


class TestStripAnonNotRedacted:
    def _jwt(self, role):
        import base64
        import json
        def b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        return f"{b64({'alg': 'HS256'})}.{b64({'role': role})}.signature"

    def test_supabase_anon_not_redacted_in_strip(self):
        from septr.core.strip import strip_sensitive_data
        anon = self._jwt("anon")
        cleaned, _ = strip_sensitive_data({"data": anon})
        assert cleaned["data"] == anon

    def test_mixed_advisory_and_real_secret_still_redacts(self):
        from septr.core.strip import strip_sensitive_data
        msg = "AIzaSy" + "BQom12tzI-rybN7Sf-KfeL4nwm-Rf7PmI sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
        cleaned, _ = strip_sensitive_data({"msg": msg})
        assert cleaned["msg"] == "[REDACTED]"

    def test_advisory_only_key_not_redacted_in_strip(self):
        from septr.core.strip import strip_sensitive_data
        msg = "AIzaSy" + "BQom12tzI-rybN7Sf-KfeL4nwm-Rf7PmI"
        cleaned, _ = strip_sensitive_data({"msg": msg})
        assert cleaned["msg"] == msg

    def test_malformed_jwt_not_flagged(self):
        assert detect_secrets("not.a.jwt") == []


class TestHighEntropy:
    def test_detects_high_entropy_assigned_value(self):
        events = detect_high_entropy_secrets('{"apiKey": "x9F2kQ7vL3pZ8nB4cD6mW1rT5yH0jU2eA8sD4fG7hJ1kL3"}')
        assert any(e.patternId == "secret_high_entropy" for e in events)

    def test_skips_uuid_like_values(self):
        # hex-only values (IDs/hashes) don't have enough character classes
        events = detect_high_entropy_secrets('{"token": "3f2a9c1e-8b4d-47e6-9a2f-1c3d5e7b8a9f"}')
        assert events == []

    def test_skips_values_already_matched_by_specific_patterns(self):
        events = detect_high_entropy_secrets('{"apiKey": "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"}')
        assert not any(e.patternId == "secret_high_entropy" for e in events)

    def test_skips_low_entropy_values(self):
        events = detect_high_entropy_secrets('{"token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        assert events == []

    def test_skips_short_values(self):
        events = detect_high_entropy_secrets('{"token": "short123"}')
        assert events == []


class TestStripEntropyBehavior:
    def test_specific_pattern_still_redacts(self):
        from septr.core.strip import strip_sensitive_data
        # A secret value under a non-sensitive key is redacted by pattern match
        cleaned, dets = strip_sensitive_data({"payload": {"k": "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"}})
        assert cleaned["payload"]["k"] == "[REDACTED]"
        assert any(d.patternId == "secret_stripe_live" for d in dets)

    def test_entropy_only_value_is_reported_but_not_redacted(self):
        from septr.core.strip import strip_sensitive_data
        value = "x9F2kQ7vL3pZ8nB4cD6mW1rT5yH0jU2eA8sD4fG7hJ1kL3"
        # The assignment appears inside a non-sensitive string field, so only
        # the advisory entropy detection can fire — the value must survive.
        cleaned, dets = strip_sensitive_data({"note": f'{{"apiKey": "{value}"}}'})
        assert cleaned["note"] == f'{{"apiKey": "{value}"}}'  # untouched
        assert any(d.patternId == "secret_high_entropy" for d in dets)

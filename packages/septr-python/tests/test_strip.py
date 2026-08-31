import pytest
from septr.core.strip import strip_sensitive_data
from septr.core.secrets import DetectionEvent


class TestStripSensitiveData:
    def test_redacts_secret_fields(self):
        data = {"name": "John", "password": "secret123"}
        cleaned, dets = strip_sensitive_data(data)
        assert cleaned["password"] == "[REDACTED]"
        assert cleaned["name"] == "John"
        assert len(dets) > 0

    def test_handles_nested_objects(self):
        data = {"user": {"name": "John", "apiKey": "sk_live_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}
        cleaned, dets = strip_sensitive_data(data)
        assert cleaned["user"]["apiKey"] == "[REDACTED]"
        assert len(dets) > 0

    def test_handles_lists(self):
        data = [{"name": "John", "password": "abc"}, {"name": "Jane", "password": "xyz"}]
        cleaned, dets = strip_sensitive_data(data)
        assert cleaned[0]["password"] == "[REDACTED]"
        assert cleaned[1]["password"] == "[REDACTED]"

    def test_redacts_embedded_secrets_in_strings(self):
        data = {"message": "my key is sk_live_" + "abcdefghijklmnopqrstuvwxyz123456"}
        cleaned, dets = strip_sensitive_data(data)
        assert cleaned["message"] == "[REDACTED]"
        assert len(dets) > 0

    def test_returns_safe_data_unchanged(self):
        data = {"name": "John", "age": 30}
        cleaned, dets = strip_sensitive_data(data)
        assert cleaned == data
        assert len(dets) == 0

    def test_handles_none(self):
        cleaned, dets = strip_sensitive_data(None)
        assert cleaned is None
        assert len(dets) == 0

    def test_custom_fields(self):
        data = {"name": "John", "internal_key": "secret-value"}
        cleaned, dets = strip_sensitive_data(data, custom_fields=["internal_key"])
        assert cleaned["internal_key"] == "[REDACTED]"


if __name__ == "__main__":
    pytest.main()

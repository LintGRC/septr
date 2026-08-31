"""Tests for live remote config: fetching and applying project config at runtime."""

import os
import threading
import unittest.mock as mock


def test_config_pull_disabled_when_remote_config_false():
    from septr.core.config_pull import config_pull_enabled
    assert config_pull_enabled({"apiKey": "x", "remoteConfig": False}) is False


def test_config_pull_disabled_without_api_key():
    from septr.core.config_pull import config_pull_enabled
    assert config_pull_enabled({"telemetry": True}) is False


def test_config_pull_enabled_by_default():
    from septr.core.config_pull import config_pull_enabled
    assert config_pull_enabled({"apiKey": "septr_live_x"}) is True


def test_apply_remote_config_merges_runtime_keys():
    from septr.core.config_pull import apply_remote_config
    config = {"apiKey": "k", "strictMode": False, "telemetry_url": "http://x/events"}
    changed = apply_remote_config(config, {
        "strictMode": True,
        "bola": False,
        "secrets": True,
        "apiKey": "evil",
        "telemetry_url": "http://evil",
    })
    assert changed is True
    assert config["strictMode"] is True
    assert config["bola"] is False
    assert config["secrets"] is True
    assert config["apiKey"] == "k"
    assert config["telemetry_url"] == "http://x/events"


def test_apply_remote_config_noop_on_empty():
    from septr.core.config_pull import apply_remote_config
    config = {"strictMode": False}
    assert apply_remote_config(config, {"irrelevant": 1}) is False
    assert "strictMode" in config


def test_apply_remote_config_never_clobbers_tenant_aware_wiring():
    """tenantAware maps the app's tenant schema (column/JWT claim) — it's local
    wiring like apiKey/telemetry_url. The dashboard's boolean `tenantAware:
    false` toggle default must not overwrite the app's dict."""
    from septr.core.config_pull import apply_remote_config
    config = {"tenantAware": {"tenantColumn": "tenant_id", "jwtClaim": "tenant"}}
    changed = apply_remote_config(config, {
        "tenantAware": False,
        "strictMode": True,
    })
    assert changed is True  # strictMode still applied
    assert config["strictMode"] is True
    assert config["tenantAware"] == {"tenantColumn": "tenant_id", "jwtClaim": "tenant"}


def test_fetch_project_config_returns_none_on_failure():
    from septr.core.config_pull import fetch_project_config
    result = fetch_project_config({
        "apiKey": "septr_live_00000000-0000-0000-0000-000000000000_deadbeef",
        "telemetry_url": "http://127.0.0.1:1/events",
    })
    assert result is None


def test_fetch_project_config_parses_v2_key_into_url():
    from septr.core import config_pull

    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["auth"] = req.get_header("Authorization")

        class FakeResp:
            status = 200

            def read(self):
                return b'{"config": {"strictMode": true}}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return FakeResp()

    with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        result = config_pull.fetch_project_config({
            "apiKey": "septr_live_11111111-2222-3333-4444-555555555555_abcd0123456789abcdef0123456789ab",
            "telemetry_url": "http://127.0.0.1:8000/events",
        })

    assert result == {"strictMode": True}
    assert seen["url"] == "http://127.0.0.1:8000/projects/11111111-2222-3333-4444-555555555555/config"
    assert seen["auth"] == "Bearer septr_live_11111111-2222-3333-4444-555555555555_abcd0123456789abcdef0123456789ab"


def test_start_polling_applies_config_and_updates_on_next_tick():
    from septr.core import config_pull

    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        payload = b'{"config": {"strictMode": true}}' if calls["n"] == 1 else b'{"config": {"strictMode": false}}'

        class FakeResp:
            status = 200

            def read(self):
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return FakeResp()

    config = {
        "apiKey": "septr_live_11111111-2222-3333-4444-555555555555_abcd0123456789abcdef0123456789ab",
        "telemetry_url": "http://127.0.0.1:8000/events",
    }

    with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        thread = config_pull.start_config_polling(config)

    assert config["strictMode"] is True
    assert thread is not None

    # Simulate the next poll tick changing strictMode back to false.
    with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        config_pull.apply_remote_config(config, config_pull.fetch_project_config(config))
    assert config["strictMode"] is False

    config_pull.stop_config_polling()
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_start_polling_noop_when_disabled():
    from septr.core import config_pull
    with mock.patch("urllib.request.urlopen") as m:
        thread = config_pull.start_config_polling({"apiKey": "x", "remoteConfig": False})
    assert thread is None
    m.assert_not_called()

import os
import sys

import pytest

from septr.core import env_check
from septr.core.env_check import (
    check_env_vs_dotenv,
    env_dotenv_candidates,
    mask_key,
    read_dotenv_key,
    warn_env_vs_dotenv,
)


@pytest.fixture(autouse=True)
def reset_once_guard():
    env_check._warned = False
    yield
    env_check._warned = False


def test_mask_key_short_and_long():
    assert mask_key("short") == "***"
    key = "septr_live_12345678-1234-1234-1234-123456789012_abcdef0123456789abcdef0123456789"
    masked = mask_key(key)
    assert masked == "septr_live_1234…9012_ab…6789"
    assert "abcdef" not in masked


def test_read_dotenv_key_parses_quoted_and_plain(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "# comment\nSEPTR_API_KEY=\"septr_live_aaaa\"\nSEPTR_TELEMETRY_URL='http://x'\n"
    )
    assert read_dotenv_key(env, "SEPTR_API_KEY") == "septr_live_aaaa"
    assert read_dotenv_key(env, "SEPTR_TELEMETRY_URL") == "http://x"
    assert read_dotenv_key(env, "MISSING") is None


def test_read_dotenv_key_missing_file(tmp_path):
    assert read_dotenv_key(tmp_path / "nope.env", "SEPTR_API_KEY") is None


def test_candidates_include_cwd_parent_and_children(tmp_path, monkeypatch):
    child = tmp_path / "sub"
    child.mkdir()
    monkeypatch.chdir(tmp_path)
    paths = env_dotenv_candidates()
    assert tmp_path / ".env" in paths
    assert tmp_path.parent / ".env" in paths
    assert child / ".env" in paths


def test_mismatch_warns_once_with_masked_keys(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('SEPTR_API_KEY="septr_live_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb_0123456789abcdef0123456789abcdef"\n')
    monkeypatch.delenv("SEPTR_SILENCE_ENV_WARNING", raising=False)

    wrong = "septr_live_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa_ffffffffffffffffffffffffffffffff"
    first = check_env_vs_dotenv(wrong, candidates=[env])
    assert len(first) == 1
    assert "bbbb" in first[0]
    assert "aaaa" in first[0]
    assert "ffffffffffffffffffffffffffffffff" not in first[0]

    second = check_env_vs_dotenv(wrong, candidates=[env])
    assert second == []


def test_matching_key_silent(tmp_path):
    env = tmp_path / ".env"
    env.write_text('SEPTR_API_KEY="septr_live_cccccccc-cccc-4ccc-8ccc-cccccccccccc_0123456789abcdef0123456789abcdef"\n')
    key = "septr_live_cccccccc-cccc-4ccc-8ccc-cccccccccccc_0123456789abcdef0123456789abcdef"
    assert check_env_vs_dotenv(key, candidates=[env]) == []


def test_no_env_found_silent(tmp_path):
    assert check_env_vs_dotenv("septr_live_x", candidates=[tmp_path / ".env"]) == []


def test_silence_env_suppresses_warning(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('SEPTR_API_KEY="septr_live_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb_0123456789abcdef0123456789abcdef"\n')
    monkeypatch.setenv("SEPTR_SILENCE_ENV_WARNING", "1")
    assert check_env_vs_dotenv("septr_live_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa_ffffffffffffffffffffffffffffffff", candidates=[env]) == []


def test_warn_env_vs_dotenv_prints_to_stderr(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text('SEPTR_API_KEY="septr_live_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb_0123456789abcdef0123456789abcdef"\n')
    warn_env_vs_dotenv(
        "septr_live_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa_ffffffffffffffffffffffffffffffff",
        candidates=[env],
    )
    captured = capsys.readouterr()
    assert "[septr] WARNING" in captured.err
    assert "does not match" in captured.err


def test_warn_env_vs_dotenv_silent_without_env_file(tmp_path, monkeypatch, capsys):
    # Discovery scans cwd + children, so chdir somewhere with no .env files
    monkeypatch.chdir(tmp_path)
    warn_env_vs_dotenv("septr_live_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa_ffffffffffffffffffffffffffffffff")
    captured = capsys.readouterr()
    assert "[septr] WARNING" not in captured.err

from engine.cscope import (
    check_domain,
    check_path,
    check_session_scope,
    cookie_batch,
    enforce,
    parse_cookie,
)

POLICY = {
    "registrable_domain": "example.com",
    "required_path": "/app",
    "allow_parent_domain": False,
    "allow_empty_path": False,
    "require_samesite": "lax",
}


def test_parse_cookie():
    cookie = parse_cookie(
        "sid=abc123; Domain=APP.Example.COM; Path=/app; Secure; HttpOnly; SameSite=Lax"
    )
    assert cookie["name"] == "sid"
    assert cookie["value"] == "abc123"
    assert cookie["domain"] == "app.example.com"
    assert cookie["path"] == "/app"
    assert cookie["secure"] is True
    assert cookie["httponly"] is True
    assert cookie["samesite"] == "lax"
    assert cookie["is_session"] is True


def test_domain_scope():
    cookie = parse_cookie("sid=abc; Domain=example.com; Path=/app; Secure; SameSite=Lax")
    assert check_domain(cookie, "notexample.com", POLICY) is False
    assert check_domain(cookie, "app.example.com", POLICY) is False


def test_path_scope():
    cookie = parse_cookie("sid=abc; Domain=app.example.com; Path=/apple; Secure; SameSite=Lax")
    assert check_path(cookie, POLICY) is False
    assert enforce(cookie, "app.example.com", POLICY)["ok"] is False


def test_session_scope():
    cookie = parse_cookie("sid=abc; Domain=sub.example.com; Path=/app; Secure; SameSite=Lax")
    assert cookie["is_session"] is True
    assert check_session_scope(cookie, "app.sub.example.com") is False


def test_batch_independent():
    first = parse_cookie("sid=one; Domain=app.example.com; Path=/app; Secure; SameSite=Lax")
    second = parse_cookie("sid=two; Domain=admin.example.com; Path=/app; Secure; SameSite=Lax")
    result = cookie_batch([first, second], "app.example.com", POLICY)
    assert result["ok"] is False
    assert [item["ok"] for item in result["results"]] == [True, False]
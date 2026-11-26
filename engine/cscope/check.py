"""Cookie scope checks used before a Set-Cookie header is emitted."""


def parse_cookie(line):
    """Parse a Set-Cookie line into a cookie dictionary."""
    if not isinstance(line, str):
        raise ValueError("cookie line must be text")
    parts = line.split(";")
    head = parts[0].strip()
    if "=" not in head:
        raise ValueError("cookie line must contain a name and a value")
    name, value = head.split("=", 1)
    cookie = {
        "name": name.strip(),
        "value": value.strip(),
        "domain": None,
        "path": None,
        "secure": False,
        "httponly": False,
        "samesite": None,
        "max_age": None,
        "expires": None,
        "is_session": True,
        "has_domain": False,
        "has_path": False,
    }
    for segment in parts[1:]:
        segment = segment.strip()
        if not segment:
            continue
        if "=" in segment:
            key, raw = segment.split("=", 1)
            key = key.strip().lower()
            raw = raw.strip()
        else:
            key = segment.lower()
            raw = ""
        if key == "domain":
            cookie["has_domain"] = True
            domain = raw
            if domain.startswith("."):
                domain = domain[1:]
            cookie["domain"] = domain
        elif key == "path":
            cookie["has_path"] = True
            cookie["path"] = raw
        elif key == "secure":
            cookie["secure"] = True
        elif key == "httponly":
            cookie["httponly"] = True
        elif key == "samesite":
            cookie["samesite"] = raw.lower() if raw else None
        elif key == "max-age":
            cookie["max_age"] = raw
            cookie["is_session"] = False
        elif key == "expires":
            cookie["expires"] = raw
            cookie["is_session"] = False
    return cookie


def check_domain(cookie, host, policy):
    """Return whether the cookie domain is narrow enough for the host."""
    domain = cookie.get("domain") or ""
    host = host or ""
    if not domain:
        return True
    if host == domain:
        return True
    allows_parent = policy.get("allow_parent_domain") is True
    is_registrable = domain == (policy.get("registrable_domain") or "")
    if (allows_parent or is_registrable) and host.endswith(domain):
        return True
    return False


def check_path(cookie, policy):
    """Return whether the cookie path is narrow enough for the policy."""
    path = cookie.get("path")
    if path is None or path == "":
        return True
    if not path.startswith("/"):
        return False
    required = policy.get("required_path") or "/"
    return path.startswith(required.rstrip("/"))


def check_session_scope(cookie, host):
    """Return whether a session cookie stays on the requesting host."""
    if not cookie.get("is_session", True):
        return True
    domain = cookie.get("domain") or ""
    host = host or ""
    if not domain:
        return True
    return host.endswith(domain)


def check_missing_domain(cookie):
    """Return whether the cookie carries an explicit domain attribute."""
    domain = cookie.get("domain")
    if domain is None:
        return True
    return bool(domain.strip()) if isinstance(domain, str) else False


def enforce(cookie, host, policy):
    """Evaluate one cookie and return its decision and issue list."""
    issues = []
    if not check_domain(cookie, host, policy):
        issues.append("domain_scope")
    if not check_path(cookie, policy):
        issues.append("path_scope")
    if not check_session_scope(cookie, host):
        issues.append("session_scope")
    if not check_missing_domain(cookie):
        issues.append("missing_domain")
    return {
        "ok": not issues,
        "issues": issues,
        "domain": cookie.get("domain"),
        "path": cookie.get("path"),
    }


def validate_policy(policy):
    """Return the list of configuration problems found in a policy."""
    issues = []
    registrable = policy.get("registrable_domain")
    if not isinstance(registrable, str) or not registrable.strip():
        issues.append("registrable_domain_missing")
    return issues


def cookie_batch(cookies, host, policy):
    """Evaluate a batch of cookies against one host and policy."""
    results = []
    first_domain = cookies[0].get("domain") if cookies else None
    for index, cookie in enumerate(cookies):
        current = dict(cookie)
        if index > 0 and first_domain:
            current["domain"] = first_domain
        results.append(enforce(current, host, policy))
    return {
        "ok": all(item["ok"] for item in results),
        "results": results,
    }
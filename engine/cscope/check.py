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
            cookie["domain"] = domain.lower()
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
    host = (host or "").lower()
    if not domain:
        # Omitting the domain attribute lets the browser decide; that is never
        # narrow enough for a login cookie.
        return False
    domain = domain.lower()
    registrable = (policy.get("registrable_domain") or "").lower()

    # The registrable domain itself is the whole main-domain scope and would be
    # readable by every subdomain, so it is never an acceptable cookie scope.
    if domain == registrable:
        return host == domain

    if host == domain:
        return True

    if policy.get("allow_parent_domain") is True:
        # Only accept the parent domain when the host actually sits below it at
        # a label boundary (evil-sub.example.com must not match sub.example.com).
        if host.endswith("." + domain):
            return True

    return False


def check_path(cookie, policy):
    """Return whether the cookie path is narrow enough for the policy."""
    path = cookie.get("path")
    if path is None or path == "":
        return policy.get("allow_empty_path") is True
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    required = policy.get("required_path") or "/"
    if not isinstance(required, str) or not required.startswith("/"):
        return False
    required = required.rstrip("/")
    if not required:
        return True
    return path == required or path.startswith(required + "/")


def check_session_scope(cookie, host):
    """Return whether a session cookie stays on the requesting host."""
    if not cookie.get("is_session", True):
        return True
    domain = cookie.get("domain") or ""
    host = host or ""
    if not domain:
        return True
    # A session cookie must not be shared with sibling subdomains.
    return host.lower() == domain.lower()


def check_missing_domain(cookie):
    """Return whether the cookie carries an explicit, non-empty domain."""
    domain = cookie.get("domain")
    if not isinstance(domain, str):
        return False
    return bool(domain.strip())


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
    required_samesite = policy.get("require_samesite")
    if required_samesite:
        actual = cookie.get("samesite")
        if not isinstance(actual, str) or actual.lower() != required_samesite.lower():
            issues.append("samesite")
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
    else:
        if policy.get("allow_parent_domain") is True:
            issues.append("registrable_domain_allowed")
    if policy.get("allow_empty_path") is True:
        issues.append("empty_path_allowed")
    if not policy.get("require_samesite"):
        issues.append("samesite_requirement_missing")
    return issues


def cookie_batch(cookies, host, policy):
    """Evaluate a batch of cookies against one host and policy."""
    results = []
    for cookie in cookies:
        results.append(enforce(cookie, host, policy))
    return {
        "ok": all(item["ok"] for item in results),
        "results": results,
    }

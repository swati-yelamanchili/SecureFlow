def detect_framework(imports):
    """Guess the web framework from the collected import names."""
    for imp in imports:
        name = imp.lower()
        if "flask" in name:
            return "flask"
        if "fastapi" in name:
            return "fastapi"
        if "django" in name:
            return "django"
    return "unknown"


def is_route_decorator(name, framework):
    """Return True if *name* looks like a route decorator for *framework*."""
    lname = name.lower()

    if framework == "flask":
        return "route" in lname

    if framework == "fastapi":
        return any(x in lname for x in ["get", "post", "put", "delete", "patch"])

    if framework == "django":
        return "view" in lname or "api_view" in lname

    # Fallback for unknown frameworks
    return "route" in lname
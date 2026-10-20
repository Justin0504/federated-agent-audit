"""Conservative operation/destination grants from explicit request syntax.

An authored capability adapter, not a semantic intent oracle. Ambiguous requests
remain unknown. Source references alone never grant write authority.
"""

import re


def operation_bound(function, args, request):
    if function != "post_webpage":
        # Other destination checks remain with the existing policy; no coverage claim.
        return True
    url = args.get("url")
    if not isinstance(url, str) or not url.strip():
        return False
    # Explicit direct update, or publishing TO a URL. Merely mentioning an article
    # AT a URL as input does not grant permission to change that source.
    if re.search(r"\b(?:not|never|avoid|without|don't)\b", request, re.I):
        return False
    target = re.escape(url.strip()) + r"(?![\w/])"
    direct = r"\b(?:update|overwrite|edit|replace)\s+(?:the\s+)?(?:webpage\s+)?" + target
    publish = r"\b(?:publish|post|upload|write)\b[^.!?\n]{0,160}?\bto\s+" + target
    return bool(re.search(direct, request, re.I) or re.search(publish, request, re.I))


def scoped_authorize(function, args, request, base_decide):
    base = base_decide(function, args, request, "combined")
    if base["status"] != "allow":
        return base
    if not operation_bound(function, args, request):
        return {"status": "unknown", "reason": "write_operation_not_explicitly_bound"}
    return base

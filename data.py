"""Build the deterministic, synthetic PySecPatch repair dataset."""

from __future__ import annotations

import argparse
import ast
import difflib
import hashlib
import io
import json
import random
import re
import time
import tokenize
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
RESULTS_DIR = PROJECT_DIR / "results"
DEFAULT_SEED = 20260619
GENERATOR_VERSION = "2.0"
SOURCE_LICENSE = "Apache-2.0"

SCHEMA_KEYS = (
    "id",
    "family",
    "split",
    "language",
    "cwe",
    "vuln_type",
    "is_vulnerable",
    "vulnerable_code",
    "fixed_code",
    "vulnerable_lines",
    "explanation",
    "patch_summary",
    "safe_test",
    "task",
    "ecosystem",
    "prompt",
    "target",
    "messages",
    "patch",
    "verification",
    "source",
    "source_license",
)

FAMILY_SHAPES = (
    ("train", "function"),
    ("train", "keyword_only"),
    ("train", "service_method"),
    ("train", "static_method"),
    ("train", "callable_object"),
    ("train", "guarded_function"),
    ("train", "two_stage"),
    ("train", "async_function"),
    ("train", "class_method"),
    ("train", "nested_handler"),
    ("train", "branch_dispatch"),
    ("train", "stateful_service"),
    ("val", "module_dispatch"),
    ("test", "adapter_method"),
    ("holdout", "policy_factory"),
)

SYSTEM_PROMPT = (
    "You are PySecPatch, a defensive Python secure coding model. Identify security defects, "
    "avoid false positives, and produce minimal safe repairs. Return strict JSON only."
)
REPAIR_FIELDS = (
    "is_vulnerable",
    "cwe",
    "vuln_type",
    "vulnerable_lines",
    "explanation",
    "fixed_code",
    "patch_summary",
    "safe_test",
)
AGENT_FIELDS = ("finding_id", "summary", "patch")


@dataclass(frozen=True)
class CweSpec:
    cwe: str
    slug: str
    vuln_type: str
    explanation: str
    patch_summary: str
    forbidden_test_text: str | None
    required_test_text: str | None
    ecosystem: str = "python-stdlib"
    reference: str = "https://docs.python.org/3/library/security_warnings.html"


SPECS = (
    CweSpec("CWE-089", "sql_injection", "SQL injection", "Untrusted data is interpolated into a SQL statement, allowing query structure to be changed.", "Use a parameterized query and pass values separately from SQL text.", "execute(f", "execute(\"SELECT"),
    CweSpec("CWE-078", "command_injection", "OS command injection", "Untrusted values are assembled into a shell command, allowing command interpretation.", "Pass an argument list directly to subprocess without a shell.", "shell=True", "subprocess.run(["),
    CweSpec("CWE-022", "path_traversal", "Path traversal", "A user-controlled path can escape the intended storage root.", "Resolve the candidate path and require it to remain below the trusted root.", None, "relative_to(root)"),
    CweSpec("CWE-502", "unsafe_deserialization", "Unsafe deserialization", "Pickle can execute attacker-controlled code while deserializing untrusted bytes.", "Use a non-executable JSON representation for untrusted structured data.", "pickle.loads", "json.loads"),
    CweSpec("CWE-798", "hardcoded_credentials", "Hardcoded credentials", "A credential embedded in source can leak through code distribution and cannot be rotated safely.", "Read the credential from an environment variable at runtime.", "synthetic_training_token", "os.environ"),
    CweSpec("CWE-327", "weak_cryptography", "Weak cryptography", "A fast legacy digest is unsuitable for password derivation and enables inexpensive guessing.", "Use salted PBKDF2-HMAC-SHA256 with a substantial iteration count.", "sha1(", "pbkdf2_hmac"),
    CweSpec("CWE-200", "sensitive_data_exposure", "Sensitive data exposure", "Authentication secrets are written to application logs.", "Log only the non-sensitive account identifier.", "password=%s", "login user=%s"),
    CweSpec("CWE-862", "missing_authorization", "Missing authorization", "A state-changing operation runs without checking ownership or authorization.", "Verify ownership before performing the state-changing operation.", None, "PermissionError"),
    CweSpec("CWE-918", "ssrf", "Server-side request forgery", "An arbitrary URL can make the server connect to attacker-selected destinations.", "Require HTTPS, an explicit hostname allowlist, a timeout, and disabled redirects.", None, "allow_redirects=False"),
    CweSpec("CWE-400", "resource_consumption", "Uncontrolled resource consumption", "A caller-controlled read size can cause excessive memory allocation.", "Clamp the limit, read one sentinel byte, and reject oversized input.", None, "1_048_576"),
    CweSpec("CWE-079", "flask_jinja_xss", "Cross-site scripting in Flask/Jinja", "Untrusted markup is marked safe and rendered without contextual escaping.", "Escape the untrusted value before returning it to the template.", "Markup(", "escape(", "flask-jinja", "https://flask.palletsprojects.com/en/stable/web-security/"),
    CweSpec("CWE-079", "django_safe_string_xss", "Cross-site scripting in Django", "User-controlled HTML is promoted to a safe string, bypassing Django template escaping.", "Use format_html so dynamic values are escaped before interpolation.", "mark_safe(", "format_html(", "django", "https://docs.djangoproject.com/en/5.2/topics/security/"),
    CweSpec("CWE-094", "dynamic_code_injection", "Python code injection", "Untrusted text is evaluated as Python code.", "Parse the expected literal data format without executing code.", "return eval(", "ast.literal_eval", "python-stdlib", "https://docs.python.org/3/library/ast.html#ast.literal_eval"),
    CweSpec("CWE-295", "requests_tls_verification", "Disabled TLS certificate verification", "The HTTP client disables certificate validation and can accept an impersonated service.", "Keep certificate verification enabled and use a finite timeout.", "verify=False", "verify=True", "requests", "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification"),
    CweSpec("CWE-319", "cleartext_http_transport", "Cleartext transmission of sensitive data", "Sensitive data is transmitted over unencrypted HTTP.", "Require an HTTPS endpoint before sending the request.", "http://", "https://", "requests", "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification"),
    CweSpec("CWE-352", "flask_csrf_validation", "Missing CSRF validation", "A state-changing request is accepted without comparing a request token to the session token.", "Require both CSRF tokens and compare them in constant time.", None, "compare_digest", "flask", "https://flask.palletsprojects.com/en/stable/web-security/"),
    CweSpec("CWE-434", "fastapi_upload_validation", "Unrestricted file upload", "An uploaded filename and media type are accepted without an allowlist.", "Validate the media type and normalize the filename to a safe basename.", None, "allowed_types", "fastapi-starlette", "https://fastapi.tiangolo.com/tutorial/request-files/"),
    CweSpec("CWE-601", "flask_open_redirect", "Open redirect", "A redirect target controlled by the requester is returned without origin validation.", "Allow only relative redirect targets with no scheme or authority.", None, "parsed.netloc", "flask", "https://flask.palletsprojects.com/en/stable/web-security/"),
    CweSpec("CWE-611", "lxml_external_entity", "XML external entity processing", "The XML parser can resolve entities or access the network while parsing untrusted XML.", "Use an XML parser with entity resolution and network access disabled.", None, "resolve_entities=False", "lxml", "https://docs.python.org/3/library/xml.html#xml-vulnerabilities"),
    CweSpec("CWE-209", "django_error_details", "Sensitive error detail exposure", "An internal exception message is returned to the client.", "Log the exception server-side and return a generic response.", "str(exc)", "request failed", "django", "https://docs.djangoproject.com/en/5.2/topics/security/"),
    CweSpec("CWE-276", "insecure_file_permissions", "Insecure default file permissions", "A sensitive output file is made readable and writable by every local user.", "Restrict the file mode to its owner.", "0o777", "0o600", "python-stdlib", "https://docs.python.org/3/library/os.html#os.chmod"),
    CweSpec("CWE-330", "insecure_random_token", "Insufficiently random security token", "The general-purpose pseudo-random generator is used for an authentication token.", "Generate security tokens with the secrets module.", "random.choice", "secrets.choice", "python-stdlib", "https://docs.python.org/3/library/secrets.html"),
    CweSpec("CWE-347", "pyjwt_signature_bypass", "Improper JWT signature verification", "JWT signature verification is disabled, allowing forged claims.", "Verify the signature with a fixed algorithm and required audience.", "verify_signature", "algorithms=[", "pyjwt", "https://pyjwt.readthedocs.io/en/stable/api.html"),
    CweSpec("CWE-306", "fastapi_missing_authentication", "Missing authentication", "A sensitive API operation executes without requiring an authenticated principal.", "Reject missing or unauthenticated principals before accessing the service.", None, "status_code=401", "fastapi", "https://fastapi.tiangolo.com/tutorial/security/"),
    CweSpec("CWE-915", "mass_assignment", "Mass assignment", "Every request field is copied onto a domain object, including security-sensitive attributes.", "Copy only an explicit allowlist of mutable profile fields.", None, "allowed_fields", "web-api", "https://cwe.mitre.org/data/definitions/915.html"),
    CweSpec("CWE-1333", "regex_dos", "Regular expression denial of service", "An attacker-controlled expression is compiled and applied to potentially large text.", "Bound the input sizes and treat the requested pattern as literal text.", None, "re.escape", "python-stdlib", "https://docs.python.org/3/library/re.html"),
    CweSpec("CWE-377", "insecure_temp_file", "Insecure temporary file", "A predictable path in a shared temporary directory can be pre-created or redirected.", "Create the file atomically with tempfile.mkstemp.", "/tmp/", "mkstemp", "python-stdlib", "https://docs.python.org/3/library/tempfile.html"),
    CweSpec("CWE-312", "plaintext_password_storage", "Cleartext storage of sensitive information", "A password is stored directly on disk.", "Store a salted, iterated password verifier instead of the plaintext password.", "write_text(password", "pbkdf2_hmac", "python-stdlib", "https://docs.python.org/3/library/hashlib.html#key-derivation"),
    CweSpec("CWE-113", "http_response_splitting", "HTTP response splitting", "Untrusted header content can contain CR or LF delimiters.", "Reject header values containing carriage returns or line feeds.", None, "invalid header value", "web-api", "https://flask.palletsprojects.com/en/stable/web-security/"),
    CweSpec("CWE-117", "log_injection", "Improper log output neutralization", "Untrusted text can inject forged lines into security logs.", "Escape carriage returns and line feeds before logging.", None, "replace(\"\\n\"", "logging", "https://docs.python.org/3/library/logging.html"),
    CweSpec("CWE-1236", "csv_formula_injection", "CSV formula injection", "Spreadsheet control characters at the start of a cell can be interpreted as formulas.", "Prefix formula-like cells so spreadsheet software treats them as text.", None, "dangerous_prefixes", "csv-pandas", "https://cwe.mitre.org/data/definitions/1236.html"),
    CweSpec("CWE-643", "lxml_xpath_injection", "XPath injection", "Untrusted text is interpolated into an XPath expression.", "Bind the value as an XPath variable instead of constructing expression text.", "xpath = f", "$account", "lxml", "https://lxml.de/xpathxslt.html"),
    CweSpec("CWE-090", "ldap_filter_injection", "LDAP injection", "Untrusted text is concatenated into an LDAP search filter.", "Escape the value with the LDAP library's filter escaping helper.", None, "escape_filter_chars", "ldap3", "https://ldap3.readthedocs.io/en/latest/conv.html"),
    CweSpec("CWE-502", "pyyaml_unsafe_load", "Unsafe YAML deserialization", "A general YAML loader can construct attacker-controlled Python objects.", "Use yaml.safe_load for untrusted YAML.", "yaml.load(", "yaml.safe_load", "pyyaml", "https://pyyaml.org/wiki/PyYAMLDocumentation"),
    CweSpec("CWE-089", "sqlalchemy_text_injection", "SQL injection through SQLAlchemy text", "User input is formatted into a textual SQL statement before execution.", "Use a SQLAlchemy bind parameter and pass the value separately.", "text(f", ":account_id", "sqlalchemy", "https://docs.sqlalchemy.org/en/20/core/sqlelement.html"),
    CweSpec("CWE-022", "tarfile_path_traversal", "Archive extraction path traversal", "Archive member paths are extracted without the standard data filter.", "Use tarfile's data extraction filter for untrusted archives.", "extractall(destination)", "filter=\"data\"", "python-stdlib", "https://docs.python.org/3/library/tarfile.html"),
    CweSpec("CWE-918", "httpx_client_ssrf", "HTTPX server-side request forgery", "An HTTPX client fetches an arbitrary requester-controlled URL.", "Validate scheme and hostname and disable redirects before fetching.", None, "follow_redirects=False", "httpx-fastapi", "https://www.python-httpx.org/advanced/clients/"),
    CweSpec("CWE-409", "zip_decompression_bomb", "Improper handling of highly compressed data", "Archive members are expanded without a total uncompressed-size limit.", "Validate member count and total declared size before extraction.", None, "total_size", "python-stdlib", "https://docs.python.org/3/library/zipfile.html"),
    CweSpec("CWE-384", "flask_session_fixation", "Session fixation", "Authentication reuses the pre-login session identifier and state.", "Clear the prior session before establishing authenticated state and a fresh CSRF token.", None, ".clear()", "flask", "https://flask.palletsprojects.com/en/stable/web-security/"),
    CweSpec("CWE-942", "starlette_permissive_cors", "Permissive cross-domain policy", "Credentialed cross-origin requests are enabled for every origin.", "Use an explicit trusted-origin allowlist for credentialed requests.", "allow_origins=[\"*\"]", "allow_origins=trusted_origins", "fastapi-starlette", "https://www.starlette.io/middleware/#corsmiddleware"),
    CweSpec("CWE-614", "flask_insecure_cookie", "Sensitive cookie without secure attributes", "A session cookie can be sent over cleartext transport or read by client-side script.", "Set Secure, HttpOnly, and SameSite attributes on the session cookie.", "secure=False", "httponly=True", "flask", "https://flask.palletsprojects.com/en/stable/web-security/"),
    CweSpec("CWE-1336", "jinja_template_injection", "Server-side template injection", "Requester-controlled text is compiled as a Jinja template.", "Compile a constant template and pass untrusted text only as data.", "Template(", "{{ value }}", "jinja2", "https://jinja.palletsprojects.com/en/stable/api/"),
    CweSpec("CWE-943", "mongodb_operator_injection", "NoSQL operator injection", "An untrusted mapping is passed directly to a MongoDB query and can contain query operators.", "Validate scalar fields and construct an explicit query document.", "find_one(payload", "isinstance(username, str)", "pymongo", "https://www.mongodb.com/docs/languages/python/pymongo-driver/current/security/"),
    CweSpec("CWE-639", "django_idor", "Authorization bypass through user-controlled key", "An object is loaded by requester-controlled identifier without constraining ownership.", "Include the authenticated owner in the object lookup.", None, "owner_id=", "django", "https://docs.djangoproject.com/en/5.2/topics/security/"),
    CweSpec("CWE-489", "flask_debug_mode", "Active debug code", "The production server exposes an interactive debugger and internal state.", "Disable debug mode and bind through deployment configuration.", "debug=True", "debug=False", "flask", "https://flask.palletsprojects.com/en/stable/debugging/"),
    CweSpec("CWE-307", "login_rate_limit", "Missing authentication throttling", "Authentication attempts are accepted without a per-principal rate limit.", "Require a rate-limiter decision before verifying credentials.", None, ".allow(", "web-api", "https://cwe.mitre.org/data/definitions/307.html"),
    CweSpec("CWE-732", "s3_public_acl", "Incorrect permission assignment for critical resource", "An uploaded object is explicitly made public.", "Use a private ACL and server-side encryption.", "public-read", "ServerSideEncryption", "boto3", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"),
    CweSpec("CWE-502", "celery_pickle_serializer", "Unsafe Celery serialization", "Celery is configured to accept executable pickle messages from a broker.", "Restrict task and result serialization to JSON.", "task_serializer=\"pickle\"", "accept_content=[\"json\"]", "celery", "https://docs.celeryq.dev/en/stable/userguide/security.html"),
    CweSpec("CWE-078", "asyncio_command_injection", "Async OS command injection", "Untrusted values are interpolated into a shell command executed by asyncio.", "Pass a fixed executable and separate arguments to create_subprocess_exec.", "create_subprocess_shell", "create_subprocess_exec", "asyncio", "https://docs.python.org/3/library/asyncio-subprocess.html"),
    CweSpec("CWE-345", "webhook_signature_validation", "Insufficient verification of data authenticity", "A webhook body is processed without authenticating its sender.", "Verify an HMAC signature in constant time before processing the body.", None, "compare_digest", "web-api", "https://docs.python.org/3/library/hmac.html"),
)
CWE_IDS = tuple(dict.fromkeys(spec.cwe for spec in SPECS))


def _seeded_rng(seed: int, family: str, occurrence: int, attempt: int) -> random.Random:
    material = f"{seed}:{family}:{occurrence}:{attempt}".encode("utf-8")
    return random.Random(int.from_bytes(hashlib.sha256(material).digest()[:8], "big"))


def _names(rng: random.Random, spec: CweSpec, occurrence: int) -> dict[str, str]:
    suffix = f"{rng.randrange(1000, 9999)}_{occurrence}"
    return {
        "function": f"{rng.choice(('handle', 'process', 'load', 'resolve', 'apply'))}_{spec.slug}_{suffix}",
        "class": f"{rng.choice(('Secure', 'Local', 'Bounded', 'Checked'))}{spec.slug.title().replace('_', '')}{rng.randrange(10, 99)}",
        "a": f"{rng.choice(('subject', 'request', 'payload', 'value'))}_{suffix}",
        "b": f"{rng.choice(('context', 'policy', 'target', 'scope'))}_{suffix}",
        "c": f"{rng.choice(('limit', 'owner', 'options', 'allowed'))}_{suffix}",
    }


def _core(spec: CweSpec, names: dict[str, str], variant: int) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    a, b, c = names["a"], names["b"], names["c"]
    if spec.slug == "sql_injection":
        table = ("orders", "invoices", "shipments")[variant % 3]
        args = [a, b]
        vulnerable = [f'query = f"SELECT id, status FROM {table} WHERE owner_id = {{{b}}}"', f"return {a}.execute(query).fetchall()"]
        fixed = [f'return {a}.execute("SELECT id, status FROM {table} WHERE owner_id = ?", ({b},)).fetchall()']
        return [], [], args, vulnerable, fixed
    if spec.slug == "command_injection":
        args = [a, b]
        vulnerable = [f'command = f"/usr/bin/convert {{{a}}} {{{b}}}"', "return subprocess.run(command, shell=True, check=True, capture_output=True)"]
        fixed = [f'return subprocess.run(["/usr/bin/convert", {a}, {b}], check=True, capture_output=True)']
        return ["import subprocess"], ["import subprocess"], args, vulnerable, fixed
    if spec.slug == "path_traversal":
        args = [a, b]
        vulnerable = [f"return (Path({a}) / {b}).read_text(encoding=\"utf-8\")"]
        fixed = [f"root = Path({a}).resolve()", f"candidate = (root / {b}).resolve()", "candidate.relative_to(root)", "return candidate.read_text(encoding=\"utf-8\")"]
        return ["from pathlib import Path"], ["from pathlib import Path"], args, vulnerable, fixed
    if spec.slug == "unsafe_deserialization":
        args = [a]
        vulnerable = [f"return pickle.loads({a})"]
        fixed = [f"return json.loads({a}.decode(\"utf-8\"))"]
        return ["import pickle"], ["import json"], args, vulnerable, fixed
    if spec.slug == "hardcoded_credentials":
        args = [a]
        token = f"synthetic_training_token_{variant:06d}"
        vulnerable = [f'token = "{token}"', f"return {{\"Authorization\": f\"Bearer {{token}}\", \"X-Request\": str({a})}}"]
        fixed = ["token = os.environ[\"SERVICE_API_TOKEN\"]", f"return {{\"Authorization\": f\"Bearer {{token}}\", \"X-Request\": str({a})}}"]
        return [], ["import os"], args, vulnerable, fixed
    if spec.slug == "weak_cryptography":
        args = [a, b]
        iterations = 200_000 + (variant % 5) * 10_000
        vulnerable = [f"return hashlib.sha1({a}.encode(\"utf-8\")).hexdigest()"]
        fixed = [f"derived = hashlib.pbkdf2_hmac(\"sha256\", {a}.encode(\"utf-8\"), {b}, {iterations})", "return derived.hex()"]
        return ["import hashlib"], ["import hashlib"], args, vulnerable, fixed
    if spec.slug == "sensitive_data_exposure":
        args = [a, b, c]
        vulnerable = [f'{a}.info("login user=%s password=%s", {b}, {c})', "return True"]
        fixed = [f'{a}.info("login user=%s", {b})', "return True"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "missing_authorization":
        args = [a, b]
        vulnerable = [f"{b}.delete()", "return True"]
        fixed = [f"if {a}.id != {b}.owner_id:", "    raise PermissionError(\"record ownership required\")", f"{b}.delete()", "return True"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "ssrf":
        args = [a, b]
        vulnerable = [f"return requests.get({a}, timeout=10)"]
        fixed = [f"parsed = urlparse({a})", f"if parsed.scheme != \"https\" or parsed.hostname not in set({b}):", "    raise ValueError(\"destination is not allowed\")", f"return requests.get({a}, timeout=5, allow_redirects=False)"]
        return ["import requests"], ["import requests", "from urllib.parse import urlparse"], args, vulnerable, fixed
    if spec.slug == "resource_consumption":
        args = [a, b]
        vulnerable = [f"return {a}.read(int({b}))"]
        fixed = [f"bounded = min(max(int({b}), 1), 1_048_576)", f"data = {a}.read(bounded + 1)", "if len(data) > bounded:", "    raise ValueError(\"input exceeds the allowed size\")", "return data"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "flask_jinja_xss":
        args = [a]
        vulnerable = [f"return Markup({a})"]
        fixed = [f"return escape({a})"]
        return ["from markupsafe import Markup"], ["from markupsafe import escape"], args, vulnerable, fixed
    if spec.slug == "django_safe_string_xss":
        args = [a]
        vulnerable = [f'return mark_safe(f"<span>{{{a}}}</span>")']
        fixed = [f'return format_html("<span>{{}}</span>", {a})']
        return ["from django.utils.safestring import mark_safe"], ["from django.utils.html import format_html"], args, vulnerable, fixed
    if spec.slug == "dynamic_code_injection":
        args = [a]
        vulnerable = [f"return eval({a}, {{\"__builtins__\": {{}}}})"]
        fixed = [f"if len({a}) > 10_000:", "    raise ValueError(\"literal is too large\")", f"return ast.literal_eval({a})"]
        return [], ["import ast"], args, vulnerable, fixed
    if spec.slug == "requests_tls_verification":
        args = [a]
        vulnerable = [f"return requests.get({a}, verify=False, timeout=10)"]
        fixed = [f"return requests.get({a}, verify=True, timeout=10)"]
        return ["import requests"], ["import requests"], args, vulnerable, fixed
    if spec.slug == "cleartext_http_transport":
        args = [a]
        vulnerable = [f'return requests.post("http://api.internal.local/events", json={a}, timeout=5)']
        fixed = [f'return requests.post("https://api.internal.local/events", json={a}, timeout=5)']
        return ["import requests"], ["import requests"], args, vulnerable, fixed
    if spec.slug == "flask_csrf_validation":
        args = [a, b]
        vulnerable = [f"return {a}.form[\"amount\"]"]
        fixed = [f"provided = {a}.headers.get(\"X-CSRF-Token\", \"\")", f"expected = {b}.get(\"csrf_token\", \"\")", "if not provided or not expected or not compare_digest(provided, expected):", "    raise PermissionError(\"invalid CSRF token\")", f"return {a}.form[\"amount\"]"]
        return [], ["from secrets import compare_digest"], args, vulnerable, fixed
    if spec.slug == "fastapi_upload_validation":
        args = [a]
        vulnerable = [f"return {a}.filename"]
        fixed = ["allowed_types = {\"image/jpeg\", \"image/png\", \"text/plain\"}", f"if {a}.content_type not in allowed_types:", "    raise ValueError(\"unsupported upload type\")", f"if {a}.size is None or {a}.size > 5_000_000:", "    raise ValueError(\"upload exceeds the size limit\")", f"return PurePath({a}.filename or \"upload.bin\").name"]
        return [], ["from pathlib import PurePath"], args, vulnerable, fixed
    if spec.slug == "flask_open_redirect":
        args = [a]
        vulnerable = [f"return redirect({a})"]
        fixed = [f"parsed = urlparse({a})", "if parsed.scheme or parsed.netloc or not parsed.path.startswith(\"/\"):", "    raise ValueError(\"redirect must stay on this origin\")", f"return redirect({a})"]
        return ["from flask import redirect"], ["from flask import redirect", "from urllib.parse import urlparse"], args, vulnerable, fixed
    if spec.slug == "lxml_external_entity":
        args = [a]
        vulnerable = [f"return etree.fromstring({a})"]
        fixed = ["parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)", f"return etree.fromstring({a}, parser=parser)"]
        return ["from lxml import etree"], ["from lxml import etree"], args, vulnerable, fixed
    if spec.slug == "django_error_details":
        args = [a, b]
        vulnerable = ["try:", f"    return {b}()", "except Exception as exc:", "    return JsonResponse({\"error\": str(exc)}, status=500)"]
        fixed = ["try:", f"    return {b}()", "except Exception:", f"    {a}.exception(\"request processing failed\")", "    return JsonResponse({\"error\": \"request failed\"}, status=500)"]
        return ["from django.http import JsonResponse"], ["from django.http import JsonResponse"], args, vulnerable, fixed
    if spec.slug == "insecure_file_permissions":
        args = [a, b]
        vulnerable = [f"Path({a}).write_text({b}, encoding=\"utf-8\")", f"os.chmod({a}, 0o777)", f"return Path({a})"]
        fixed = [f"Path({a}).write_text({b}, encoding=\"utf-8\")", f"os.chmod({a}, 0o600)", f"return Path({a})"]
        imports = ["import os", "from pathlib import Path"]
        return imports, imports, args, vulnerable, fixed
    if spec.slug == "insecure_random_token":
        args = [a]
        vulnerable = ["alphabet = string.ascii_letters + string.digits", f"return \"\".join(random.choice(alphabet) for _ in range(int({a})))"]
        fixed = [f"length = int({a})", "if not 16 <= length <= 128:", "    raise ValueError(\"token length is outside the safe range\")", "alphabet = string.ascii_letters + string.digits", "return \"\".join(secrets.choice(alphabet) for _ in range(length))"]
        return ["import random", "import string"], ["import secrets", "import string"], args, vulnerable, fixed
    if spec.slug == "pyjwt_signature_bypass":
        args = [a, b, c]
        vulnerable = [f"return jwt.decode({a}, options={{\"verify_signature\": False}})"]
        fixed = [f"return jwt.decode({a}, {b}, algorithms=[\"HS256\"], audience={c})"]
        return ["import jwt"], ["import jwt"], args, vulnerable, fixed
    if spec.slug == "fastapi_missing_authentication":
        args = [a, b]
        vulnerable = [f"return {b}.export_private_report()"]
        fixed = [f"if {a} is None or not {a}.is_authenticated:", "    raise HTTPException(status_code=401, detail=\"authentication required\")", f"return {b}.export_private_report()"]
        return [], ["from fastapi import HTTPException"], args, vulnerable, fixed
    if spec.slug == "mass_assignment":
        args = [a, b]
        vulnerable = [f"for key, value in {b}.items():", f"    setattr({a}, key, value)", f"return {a}"]
        fixed = ["allowed_fields = {\"display_name\", \"timezone\", \"locale\"}", f"safe = {{key: value for key, value in {b}.items() if key in allowed_fields}}", f"{a}.update(safe)", f"return {a}"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "regex_dos":
        args = [a, b]
        vulnerable = [f"return re.search({a}, {b}) is not None"]
        fixed = [f"if len({a}) > 256 or len({b}) > 100_000:", "    raise ValueError(\"search input is too large\")", f"return re.search(re.escape({a}), {b}) is not None"]
        return ["import re"], ["import re"], args, vulnerable, fixed
    if spec.slug == "insecure_temp_file":
        args = [a, b]
        vulnerable = [f'path = Path(f"/tmp/{{{a}}}.txt")', f"path.write_text({b}, encoding=\"utf-8\")", "return str(path)"]
        fixed = ["descriptor, path = tempfile.mkstemp(prefix=\"pysecpatch-\", suffix=\".txt\", text=True)", "with os.fdopen(descriptor, \"w\", encoding=\"utf-8\") as handle:", f"    handle.write({b})", "return path"]
        return ["from pathlib import Path"], ["import os", "import tempfile"], args, vulnerable, fixed
    if spec.slug == "plaintext_password_storage":
        args = [a, b, c]
        vulnerable = [f"Path({a}).write_text({b}, encoding=\"utf-8\")", f"return Path({a})"]
        fixed = [f"if len({c}) < 16:", "    raise ValueError(\"salt must contain at least 16 bytes\")", f"verifier = hashlib.pbkdf2_hmac(\"sha256\", {b}.encode(\"utf-8\"), {c}, 240_000).hex()", f"Path({a}).write_text(verifier, encoding=\"ascii\")", f"return Path({a})"]
        return ["from pathlib import Path"], ["import hashlib", "from pathlib import Path"], args, vulnerable, fixed
    if spec.slug == "http_response_splitting":
        args = [a, b]
        vulnerable = [f"{a}.headers[\"X-Next\"] = {b}", f"return {a}"]
        fixed = [f"if \"\\r\" in {b} or \"\\n\" in {b}:", "    raise ValueError(\"invalid header value\")", f"{a}.headers[\"X-Next\"] = {b}", f"return {a}"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "log_injection":
        args = [a, b]
        vulnerable = [f'{a}.warning("audit=%s", {b})', "return True"]
        fixed = [f"normalized = str({b}).replace(\"\\r\", \"\\\\r\").replace(\"\\n\", \"\\\\n\")", f'{a}.warning("audit=%s", normalized)', "return True"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "csv_formula_injection":
        args = [a]
        vulnerable = [f"return \",\".join(str(value) for value in {a})"]
        fixed = ["dangerous_prefixes = (\"=\", \"+\", \"-\", \"@\")", "def safe_cell(value):", "    text = str(value)", "    return \"'\" + text if text.startswith(dangerous_prefixes) else text", f"return \",\".join(safe_cell(value) for value in {a})"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "lxml_xpath_injection":
        args = [a, b]
        vulnerable = [f'xpath = f"//user[@name=\'{{{b}}}\']"', f"return {a}.xpath(xpath)"]
        fixed = [f'return {a}.xpath("//user[@name=$account]", account={b})']
        return [], [], args, vulnerable, fixed
    if spec.slug == "ldap_filter_injection":
        args = [a, b]
        vulnerable = [f'query = f"(uid={{{b}}})"', f"return {a}.search(\"ou=people,dc=example,dc=org\", query)"]
        fixed = [f"escaped = escape_filter_chars({b})", "query = f\"(uid={escaped})\"", f"return {a}.search(\"ou=people,dc=example,dc=org\", query)"]
        return [], ["from ldap3.utils.conv import escape_filter_chars"], args, vulnerable, fixed
    if spec.slug == "pyyaml_unsafe_load":
        args = [a]
        vulnerable = [f"return yaml.load({a}, Loader=yaml.Loader)"]
        fixed = [f"return yaml.safe_load({a})"]
        return ["import yaml"], ["import yaml"], args, vulnerable, fixed
    if spec.slug == "sqlalchemy_text_injection":
        args = [a, b]
        vulnerable = [f'statement = text(f"SELECT id FROM accounts WHERE id = {{{b}}}")', f"return {a}.execute(statement).all()"]
        fixed = ["statement = text(\"SELECT id FROM accounts WHERE id = :account_id\")", f"return {a}.execute(statement, {{\"account_id\": {b}}}).all()"]
        return ["from sqlalchemy import text"], ["from sqlalchemy import text"], args, vulnerable, fixed
    if spec.slug == "tarfile_path_traversal":
        args = [a, b]
        vulnerable = [f"{a}.extractall({b})", f"return {b}"]
        fixed = [f"{a}.extractall({b}, filter=\"data\")", f"return {b}"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "httpx_client_ssrf":
        args = [a, b, c]
        vulnerable = [f"return {a}.get({b}, timeout=10)"]
        fixed = [f"parsed = urlparse({b})", f"if parsed.scheme != \"https\" or parsed.hostname not in set({c}):", "    raise ValueError(\"destination is not allowed\")", f"return {a}.get({b}, timeout=5, follow_redirects=False)"]
        return [], ["from urllib.parse import urlparse"], args, vulnerable, fixed
    if spec.slug == "zip_decompression_bomb":
        args = [a, b]
        vulnerable = [f"{a}.extractall({b})", f"return {b}"]
        fixed = [f"members = {a}.infolist()", "total_size = sum(member.file_size for member in members)", "if len(members) > 1_000 or total_size > 100_000_000:", "    raise ValueError(\"archive exceeds extraction limits\")", f"{a}.extractall({b})", f"return {b}"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "flask_session_fixation":
        args = [a, b]
        vulnerable = [f"{a}[\"user_id\"] = {b}.id", "return True"]
        fixed = [f"{a}.clear()", f"{a}[\"user_id\"] = {b}.id", f"{a}[\"csrf_token\"] = secrets.token_urlsafe(32)", "return True"]
        return [], ["import secrets"], args, vulnerable, fixed
    if spec.slug == "starlette_permissive_cors":
        args = [a, b]
        vulnerable = [f"{a}.add_middleware(CORSMiddleware, allow_origins=[\"*\"], allow_credentials=True, allow_methods=[\"*\"])", f"return {a}"]
        fixed = [f"trusted_origins = tuple({b})", "if not trusted_origins:", "    raise ValueError(\"trusted origins are required\")", f"{a}.add_middleware(CORSMiddleware, allow_origins=trusted_origins, allow_credentials=True, allow_methods=[\"GET\", \"POST\"])", f"return {a}"]
        imports = ["from starlette.middleware.cors import CORSMiddleware"]
        return imports, imports, args, vulnerable, fixed
    if spec.slug == "flask_insecure_cookie":
        args = [a, b]
        vulnerable = [f"{a}.set_cookie(\"session\", {b}, secure=False)", f"return {a}"]
        fixed = [f"{a}.set_cookie(\"session\", {b}, secure=True, httponly=True, samesite=\"Lax\")", f"return {a}"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "jinja_template_injection":
        args = [a, b]
        vulnerable = [f"return Template({a}).render(context={b})"]
        fixed = ["environment = Environment(autoescape=True)", "template = environment.from_string(\"<p>{{ value }}</p>\")", f"return template.render(value={a}, context={b})"]
        return ["from jinja2 import Template"], ["from jinja2 import Environment"], args, vulnerable, fixed
    if spec.slug == "mongodb_operator_injection":
        args = [a, b]
        vulnerable = [f"return {a}.find_one({b})"]
        fixed = [f"username = {b}.get(\"username\")", "if not isinstance(username, str) or not username:", "    raise ValueError(\"username must be a non-empty string\")", f"return {a}.find_one({{\"username\": username}})"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "django_idor":
        args = [a, b, c]
        vulnerable = [f"return {a}.get(pk={b})"]
        fixed = [f"if {c} is None or not {c}.is_authenticated:", "    raise PermissionError(\"authentication required\")", f"return {a}.get(pk={b}, owner_id={c}.id)"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "flask_debug_mode":
        args = [a]
        vulnerable = [f"return {a}.run(debug=True)"]
        fixed = [f"return {a}.run(debug=False)"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "login_rate_limit":
        args = [a, b, c]
        vulnerable = [f"return {c}({b})"]
        fixed = [f"if not {a}.allow({b}):", "    raise PermissionError(\"authentication rate limit exceeded\")", f"return {c}({b})"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "s3_public_acl":
        args = [a, b, c]
        vulnerable = [f"return {a}.put_object(Bucket={b}, Key={c}, Body=b\"data\", ACL=\"public-read\")"]
        fixed = [f"return {a}.put_object(Bucket={b}, Key={c}, Body=b\"data\", ACL=\"private\", ServerSideEncryption=\"AES256\")"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "celery_pickle_serializer":
        args = [a]
        vulnerable = [f"{a}.conf.update(task_serializer=\"pickle\", result_serializer=\"pickle\", accept_content=[\"pickle\"])", f"return {a}"]
        fixed = [f"{a}.conf.update(task_serializer=\"json\", result_serializer=\"json\", accept_content=[\"json\"])", f"return {a}"]
        return [], [], args, vulnerable, fixed
    if spec.slug == "asyncio_command_injection":
        args = [a, b]
        vulnerable = [f"return asyncio.create_subprocess_shell(f\"/usr/bin/convert {{{a}}} {{{b}}}\")"]
        fixed = [f"return asyncio.create_subprocess_exec(\"/usr/bin/convert\", {a}, {b})"]
        imports = ["import asyncio"]
        return imports, imports, args, vulnerable, fixed
    if spec.slug == "webhook_signature_validation":
        args = [a, b, c]
        vulnerable = [f"return process_webhook({a})"]
        fixed = [f"expected = hmac.new({c}, {a}, hashlib.sha256).hexdigest()", f"if not hmac.compare_digest(expected, {b}):", "    raise PermissionError(\"invalid webhook signature\")", f"return process_webhook({a})"]
        return [], ["import hashlib", "import hmac"], args, vulnerable, fixed
    raise ValueError(f"Unsupported CWE: {spec.cwe}")


def _indent(lines: list[str], width: int) -> list[str]:
    prefix = " " * width
    return [prefix + line if line else "" for line in lines]


def _wrap(imports: list[str], names: dict[str, str], args: list[str], body: list[str], shape: str) -> tuple[str, str]:
    function, class_name = names["function"], names["class"]
    joined_args = ", ".join(args)
    prefix = [*imports, ""] if imports else []
    if shape == "function":
        lines = [*prefix, f"def {function}({joined_args}):", *_indent(body, 4)]
        source_entry = function
    elif shape == "keyword_only":
        lines = [*prefix, f"def {function}(*, {joined_args}):", *_indent(body, 4)]
        source_entry = function
    elif shape == "service_method":
        lines = [*prefix, f"class {class_name}:", f"    def {function}(self, {joined_args}):", *_indent(body, 8)]
        source_entry = f"{class_name}.{function}"
    elif shape == "static_method":
        lines = [*prefix, f"class {class_name}:", "    @staticmethod", f"    def {function}({joined_args}):", *_indent(body, 8)]
        source_entry = f"{class_name}.{function}"
    elif shape == "callable_object":
        lines = [*prefix, f"class {class_name}:", f"    def __call__(self, {joined_args}):", *_indent(body, 8)]
        source_entry = f"{class_name}.__call__"
    elif shape == "guarded_function":
        lines = [*prefix, f"def {function}({joined_args}):", f"    if any(value is None for value in ({joined_args},)):", "        raise ValueError(\"arguments are required\")", *_indent(body, 4)]
        source_entry = function
    elif shape == "two_stage":
        lines = [*prefix, f"def _ready_{function}():", "    return True", "", f"def {function}({joined_args}):", f"    if not _ready_{function}():", "        raise RuntimeError(\"handler is not ready\")", *_indent(body, 4)]
        source_entry = function
    elif shape == "async_function":
        lines = [*prefix, f"async def {function}({joined_args}):", "    await _yield_once()", *_indent(body, 4), "", "async def _yield_once():", "    return None"]
        source_entry = function
    elif shape == "class_method":
        lines = [*prefix, f"class {class_name}:", "    enabled = True", "", "    @classmethod", f"    def {function}(cls, {joined_args}):", "        if not cls.enabled:", "            raise RuntimeError(\"service is disabled\")", *_indent(body, 8)]
        source_entry = f"{class_name}.{function}"
    elif shape == "nested_handler":
        lines = [*prefix, f"def build_{function}():", f"    def {function}({joined_args}):", *_indent(body, 8), "", f"    return {function}"]
        source_entry = f"build_{function}()"
    elif shape == "branch_dispatch":
        lines = [*prefix, f"def {function}({joined_args}, *, enabled=True):", "    if not enabled:", "        raise PermissionError(\"operation is disabled\")", *_indent(body, 4)]
        source_entry = function
    elif shape == "stateful_service":
        lines = [*prefix, f"class {class_name}:", "    def __init__(self):", "        self.ready = True", "", f"    def {function}(self, {joined_args}):", "        if not self.ready:", "            raise RuntimeError(\"service is not ready\")", *_indent(body, 8)]
        source_entry = f"{class_name}.{function}"
    elif shape == "module_dispatch":
        lines = [*prefix, f"HANDLER_KIND_{function.upper()} = \"defensive\"", "", f"def {function}({joined_args}):", f"    if HANDLER_KIND_{function.upper()} != \"defensive\":", "        raise RuntimeError(\"invalid handler mode\")", *_indent(body, 4)]
        source_entry = function
    elif shape == "adapter_method":
        lines = [*prefix, f"class {class_name}:", "    mode = \"local-only\"", "", f"    def process(self, {joined_args}):", "        if self.mode != \"local-only\":", "            raise RuntimeError(\"invalid adapter mode\")", *_indent(body, 8)]
        source_entry = f"{class_name}.process"
    elif shape == "policy_factory":
        lines = [*prefix, f"def build_{function}():", "    policy_mode = \"strict\"", "", f"    def enforce({joined_args}):", "        if policy_mode != \"strict\":", "            raise RuntimeError(\"invalid policy mode\")", *_indent(body, 8), "", "    return enforce"]
        source_entry = f"build_{function}()"
    else:
        raise ValueError(f"Unknown shape: {shape}")
    return "\n".join(lines).rstrip() + "\n", source_entry


def _safe_test(spec: CweSpec, source_entry: str, suffix: str) -> str:
    lines = [
        f"def test_{spec.slug}_{suffix}_uses_safe_shape():",
        "    import inspect",
        f"    source = inspect.getsource({source_entry})",
    ]
    if spec.forbidden_test_text:
        lines.append(f"    assert {spec.forbidden_test_text!r} not in source")
    if spec.required_test_text:
        lines.append(f"    assert {spec.required_test_text!r} in source")
    return "\n".join(lines) + "\n"


def _vulnerable_lines(vulnerable_code: str, fixed_code: str) -> list[int]:
    before = vulnerable_code.splitlines()
    after = fixed_code.splitlines()
    lines: list[int] = []
    for tag, start, end, _fixed_start, _fixed_end in difflib.SequenceMatcher(None, before, after).get_opcodes():
        if tag in {"replace", "delete"}:
            lines.extend(range(start + 1, end + 1))
        elif tag == "insert" and before:
            lines.append(min(start + 1, len(before)))
    return sorted(set(lines))


def _normalized_hash(code: str) -> str:
    significant: list[str] = []
    ignored = {tokenize.ENCODING, tokenize.ENDMARKER, tokenize.INDENT, tokenize.DEDENT, tokenize.NEWLINE, tokenize.NL, tokenize.COMMENT}
    for token in tokenize.generate_tokens(io.StringIO(code).readline):
        if token.type not in ignored:
            significant.append(f"{token.type}:{token.string}")
    return hashlib.sha256("\n".join(significant).encode("utf-8")).hexdigest()


class _StructureNormalizer(ast.NodeTransformer):
    def visit_Name(self, node: ast.Name) -> ast.AST:
        return ast.copy_location(ast.Name(id="VAR", ctx=node.ctx), node)

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = "ARG"
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.name = "FUNC"
        return self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.name = "CLASS"
        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        value: Any
        if isinstance(node.value, str):
            value = "<STR>"
        elif isinstance(node.value, bytes):
            value = b"<BYTES>"
        elif isinstance(node.value, bool) or node.value is None:
            value = node.value
        elif isinstance(node.value, (int, float, complex)):
            value = 0
        else:
            value = "<CONST>"
        return ast.copy_location(ast.Constant(value=value), node)


def _structural_hash(code: str) -> str:
    tree = _StructureNormalizer().visit(ast.parse(code))
    return hashlib.sha256(ast.dump(tree, include_attributes=False).encode("utf-8")).hexdigest()


def _family_plan() -> list[tuple[CweSpec, str, str, str]]:
    plan: list[tuple[CweSpec, str, str, str]] = []
    for spec in SPECS:
        for split, shape in FAMILY_SHAPES:
            ecosystem = spec.ecosystem.replace("_", "-")
            family = f"{spec.cwe.lower()}-{spec.slug}-{ecosystem}-{split}-{shape}"
            plan.append((spec, split, shape, family))
    return plan


def _unified_diff(before: str, after: str, path: str = "app.py") -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            lineterm="\n",
        )
    )


def _apply_unified_diff(before: str, patch: str) -> str:
    """Apply the single-file diffs emitted above without shelling out to git."""
    source = before.splitlines(keepends=True)
    patch_lines = patch.splitlines(keepends=True)
    if len(patch_lines) < 3 or not patch_lines[0].startswith("--- a/") or not patch_lines[1].startswith("+++ b/"):
        raise ValueError("invalid unified diff headers")
    output: list[str] = []
    source_index = 0
    patch_index = 2
    header = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    while patch_index < len(patch_lines):
        match = header.match(patch_lines[patch_index])
        if not match:
            raise ValueError("invalid unified diff hunk")
        old_start = int(match.group(1)) - 1
        if old_start < source_index:
            raise ValueError("overlapping unified diff hunks")
        output.extend(source[source_index:old_start])
        source_index = old_start
        patch_index += 1
        while patch_index < len(patch_lines) and not patch_lines[patch_index].startswith("@@"):
            line = patch_lines[patch_index]
            if line.startswith(" "):
                if source_index >= len(source) or source[source_index].rstrip("\r\n") != line[1:].rstrip("\r\n"):
                    raise ValueError("unified diff context mismatch")
                output.append(source[source_index])
                source_index += 1
            elif line.startswith("-"):
                if source_index >= len(source) or source[source_index].rstrip("\r\n") != line[1:].rstrip("\r\n"):
                    raise ValueError("unified diff removal mismatch")
                source_index += 1
            elif line.startswith("+"):
                output.append(line[1:])
            elif line.startswith("\\ No newline"):
                pass
            else:
                raise ValueError("invalid unified diff line")
            patch_index += 1
    output.extend(source[source_index:])
    return "".join(output)


def _task_for_occurrence(occurrence: int) -> tuple[str, bool]:
    selector = occurrence % 10
    if selector < 4:
        return "repair", True
    if selector < 6:
        return "detect", True
    if selector < 8:
        return "detect", False
    return "repo_patch", True


def _repair_target(record: dict[str, Any]) -> dict[str, Any]:
    return {field: record[field] for field in REPAIR_FIELDS}


def _training_conversation(record: dict[str, Any], patch: str) -> tuple[str, dict[str, Any], list[dict[str, str]]]:
    task = record["task"]
    if task == "repo_patch":
        finding_id = f"synthetic-{record['id']}"
        prompt = (
            "Repair the named security finding in the repository file. Return exactly a JSON object "
            "with exactly these string keys: finding_id, summary, patch. The patch must be a minimal "
            "unified diff against the repository root and modify only app.py.\n\n"
            f"Finding ID: {finding_id}\nCWE: {record['cwe']}\nFinding: {record['explanation']}\n\n"
            f"Repository file app.py:\n{record['vulnerable_code']}"
        )
        target = {
            "finding_id": finding_id,
            "summary": record["patch_summary"],
            "patch": patch,
        }
    elif task == "detect":
        prompt = (
            "Analyze the Python code. Distinguish vulnerable code from defensive hard negatives and "
            "localize only security-relevant lines. Return strict JSON with exactly these keys: "
            f"{', '.join(REPAIR_FIELDS)}. Do not propose changes for clean code.\n\n"
            f"Python code:\n{record['vulnerable_code']}"
        )
        target = _repair_target(record)
    else:
        prompt = (
            "Analyze and minimally repair this Python code. Return strict JSON with exactly these keys: "
            f"{', '.join(REPAIR_FIELDS)}. Preserve unrelated behavior.\n\n"
            f"Python code:\n{record['vulnerable_code']}"
        )
        target = _repair_target(record)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": json.dumps(target, ensure_ascii=True, separators=(",", ":"))},
    ]
    return prompt, target, messages


def _make_record(spec: CweSpec, split: str, shape: str, family: str, occurrence: int, seed: int, attempt: int) -> dict[str, Any]:
    rng = _seeded_rng(seed, family, occurrence, attempt)
    names = _names(rng, spec, occurrence)
    vulnerable_imports, fixed_imports, args, vulnerable_body, fixed_body = _core(spec, names, occurrence + attempt)
    vulnerable_code, _ = _wrap(vulnerable_imports, names, args, vulnerable_body, shape)
    fixed_code, source_entry = _wrap(fixed_imports, names, args, fixed_body, shape)
    if spec.forbidden_test_text and spec.forbidden_test_text in fixed_code:
        raise RuntimeError(f"fixed code retains forbidden security pattern for {spec.slug}")
    if spec.required_test_text and spec.required_test_text not in fixed_code:
        raise RuntimeError(f"fixed code is missing required security control for {spec.slug}")
    task, is_vulnerable = _task_for_occurrence(occurrence)
    if not is_vulnerable:
        vulnerable_code = fixed_code
    ast.parse(vulnerable_code)
    ast.parse(fixed_code)
    identity = hashlib.sha256(f"{seed}:{family}:{occurrence}:{attempt}".encode("utf-8")).hexdigest()[:16]
    safe_test = _safe_test(spec, source_entry, identity[:8])
    ast.parse(safe_test)
    patch = _unified_diff(vulnerable_code, fixed_code) if is_vulnerable else ""
    if is_vulnerable and _apply_unified_diff(vulnerable_code, patch) != fixed_code:
        raise RuntimeError("generated patch failed round-trip validation")
    record: dict[str, Any] = {
        "id": f"psp-{spec.cwe[4:]}-{identity}",
        "family": family,
        "split": split,
        "language": "python",
        "cwe": spec.cwe,
        "vuln_type": spec.vuln_type,
        "is_vulnerable": is_vulnerable,
        "vulnerable_code": vulnerable_code,
        "fixed_code": fixed_code,
        "vulnerable_lines": _vulnerable_lines(vulnerable_code, fixed_code) if is_vulnerable else [],
        "explanation": spec.explanation if is_vulnerable else f"Clean negative for {spec.cwe}: the snippet already uses the expected defensive control.",
        "patch_summary": spec.patch_summary if is_vulnerable else "No code change is required.",
        "safe_test": safe_test,
        "task": task,
        "ecosystem": spec.ecosystem,
        "prompt": "",
        "target": {},
        "messages": [],
        "patch": patch,
        "verification": {
            "vulnerable_ast_parse": True,
            "fixed_ast_parse": True,
            "safe_test_ast_parse": True,
            "security_oracle_pass": True,
            "patch_round_trip": bool(is_vulnerable),
            "target_schema": "agent-v1" if task == "repo_patch" else "analysis-v1",
        },
        "source": "generated",
        "source_license": SOURCE_LICENSE,
    }
    prompt, target, messages = _training_conversation(record, patch)
    record["prompt"] = prompt
    record["target"] = target
    record["messages"] = messages
    return record


def _overlaps(values_by_split: dict[str, set[str]]) -> dict[str, list[str]]:
    splits = ("train", "val", "test", "holdout")
    return {
        f"{left}:{right}": sorted(values_by_split[left] & values_by_split[right])
        for index, left in enumerate(splits)
        for right in splits[index + 1 :]
    }


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _replace_with_retry(temporary, path)


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n")
    _replace_with_retry(temporary, path)


def _replace_with_retry(temporary: Path, destination: Path) -> None:
    for attempt in range(60):
        try:
            temporary.replace(destination)
            return
        except OSError as exc:
            if getattr(exc, "winerror", None) not in {5, 32, 33} or attempt == 59:
                raise
            time.sleep(1)


def _dataset_card(stats: dict[str, Any], contamination: dict[str, Any]) -> str:
    split_rows = "\n".join(f"| {split} | {count} |" for split, count in stats["counts_by_split"].items())
    cwe_rows = "\n".join(f"| {cwe} | {count} |" for cwe, count in stats["counts_by_cwe"].items())
    ecosystem_rows = "\n".join(
        f"| {ecosystem} | {count} |" for ecosystem, count in stats["counts_by_ecosystem"].items()
    )
    reference_rows = "\n".join(f"- {url}" for url in stats["guidance_references"])
    return f"""# PySecPatch 60K Multitask Security Dataset

## Purpose

This dataset trains defensive Python vulnerability detection, hard-negative restraint, minimal repair, and repository patch generation. Every example is generated locally by `data.py`; no repository, external dataset, copied source code, or third-party training record is used.

## License and provenance

- Source: deterministic synthetic generation
- Source license: Apache-2.0
- Generator version: `{stats['generator_version']}`
- Generator SHA-256: `{stats['generator_sha256']}`
- Seed: `{stats['seed']}`
- Requested and emitted records: {stats['total_records']}

## Splits

| Split | Records |
|---|---:|
{split_rows}

Splits own disjoint template families. Train has twelve code shapes per profile; validation, test, and holdout each use a separate shape. Holdout uses policy factories that never occur in train. Validation is used only for model selection. Test and holdout files are never training inputs.

## CWE coverage

| CWE | Records |
|---|---:|
{cwe_rows}

Each CWE includes vulnerable-to-fixed pairs and independent clean hard negatives. Python snippets and safety tests parse with `ast.parse`. Every vulnerable example has a generated unified diff that is applied in memory and required to reproduce the exact fixed source. Repository-patch targets use the exact `finding_id`, `summary`, and `patch` contract accepted by `agent.py`.

## Python ecosystem coverage

| Ecosystem or surface | Records |
|---|---:|
{ecosystem_rows}

The profiles cover Python standard-library code, Flask/Jinja, Django, FastAPI/Starlette, Requests, HTTPX, SQLAlchemy, PyYAML, lxml, PyJWT, LDAP, logging, CSV-producing services, CLI utilities, archive handling, and worker-style service code. Front-end coverage is limited to Python-controlled rendering, redirects, cookies, headers, CORS, and CSV output; this dataset does not add JavaScript examples.

Security behavior was designed from official project and Python documentation. Those pages are guidance only, not copied training data:

{reference_rows}

## Contamination controls

- Duplicate normalized pairs removed: {contamination['duplicate_count_removed']}
- Final normalized duplicate pairs: {contamination['final_duplicate_pairs']}
- Family overlap checks: `{contamination['family_overlap_status']}`
- Train/test structural overlap: {contamination['structural_pair_overlap']['train:test']['count']}
- Train/holdout structural overlap: {contamination['structural_pair_overlap']['train:holdout']['count']}
- Overall contamination status: `{contamination['status']}`

Normalization hashes retain identifiers and literals after removing formatting and comments. Structural hashes additionally normalize identifiers and constants to detect reused code shapes across splits. The complete per-record hash manifest is in `results/contamination_report.json`.

## Limitations

Synthetic snippets cannot reproduce every framework interaction or whole-program data flow. Safe tests are defensive source-level regression checks, not exploit demonstrations. Benchmark leadership is not asserted by this dataset card; results must be measured on untouched external benchmarks and the hidden holdout before publication.
"""


def build_dataset(count: int, seed: int) -> tuple[dict[str, Any], dict[str, Any]]:
    if count < len(SPECS) * len(FAMILY_SHAPES):
        raise ValueError(f"--count must be at least {len(SPECS) * len(FAMILY_SHAPES)}")
    plan = _family_plan()
    family_specs = {family: spec for spec, _split, _shape, family in plan}
    records_by_split: dict[str, list[dict[str, Any]]] = {split: [] for split in ("train", "val", "test", "holdout")}
    seen_pairs: set[tuple[str, str]] = set()
    duplicate_count = 0
    hash_manifest: list[dict[str, str]] = []

    for index in range(count):
        spec, split, shape, family = plan[index % len(plan)]
        occurrence = index // len(plan)
        attempt = 0
        while True:
            record = _make_record(spec, split, shape, family, occurrence, seed, attempt)
            vulnerable_hash = _normalized_hash(record["vulnerable_code"])
            fixed_hash = _normalized_hash(record["fixed_code"])
            pair = (vulnerable_hash, fixed_hash)
            if pair not in seen_pairs:
                break
            duplicate_count += 1
            attempt += 1
            if attempt > 100:
                raise RuntimeError(f"Could not produce a unique record for {family}")
        if tuple(record) != SCHEMA_KEYS:
            raise RuntimeError(f"Record schema drifted for {record['id']}")
        if record["is_vulnerable"] and not record["vulnerable_lines"]:
            raise RuntimeError(f"Vulnerable record has no changed lines: {record['id']}")
        seen_pairs.add(pair)
        records_by_split[split].append(record)
        hash_manifest.append(
            {
                "id": record["id"],
                "split": split,
                "family": family,
                "vulnerable_sha256": vulnerable_hash,
                "fixed_sha256": fixed_hash,
                "vulnerable_structure_sha256": _structural_hash(record["vulnerable_code"]),
                "fixed_structure_sha256": _structural_hash(record["fixed_code"]),
            }
        )

    for offset, split in enumerate(("train", "val", "test", "holdout")):
        random.Random(seed + offset).shuffle(records_by_split[split])
        _write_jsonl(DATA_DIR / f"v2_{split}.jsonl", records_by_split[split])

    family_sets: dict[str, set[str]] = defaultdict(set)
    normalized_sets: dict[str, set[str]] = defaultdict(set)
    structural_sets: dict[str, set[str]] = defaultdict(set)
    for item in hash_manifest:
        family_sets[item["split"]].add(item["family"])
        normalized_sets[item["split"]].add(item["vulnerable_sha256"] + item["fixed_sha256"])
        structural_sets[item["split"]].add(item["vulnerable_structure_sha256"] + item["fixed_structure_sha256"])
    family_overlaps = _overlaps(family_sets)
    normalized_overlaps = _overlaps(normalized_sets)
    structural_overlaps = _overlaps(structural_sets)
    final_duplicate_pairs = sum(len(records) for records in records_by_split.values()) - len(seen_pairs)
    protected_pairs = tuple(normalized_overlaps)
    contamination_passed = (
        final_duplicate_pairs == 0
        and all(not values for values in family_overlaps.values())
        and all(not normalized_overlaps[pair] for pair in protected_pairs)
        and all(not structural_overlaps[pair] for pair in protected_pairs)
    )
    contamination = {
        "status": "pass" if contamination_passed else "fail",
        "seed": seed,
        "normalization": "Python tokens without formatting/comments; structural AST with identifiers/constants normalized",
        "duplicate_count_removed": duplicate_count,
        "final_duplicate_pairs": final_duplicate_pairs,
        "family_overlap_status": "pass" if all(not values for values in family_overlaps.values()) else "fail",
        "family_overlap": {key: {"count": len(value), "values": value} for key, value in family_overlaps.items()},
        "normalized_pair_overlap": {key: {"count": len(value), "values": value} for key, value in normalized_overlaps.items()},
        "structural_pair_overlap": {key: {"count": len(value), "values": value} for key, value in structural_overlaps.items()},
        "hash_manifest": sorted(hash_manifest, key=lambda item: item["id"]),
    }
    if not contamination_passed:
        raise RuntimeError("Contamination controls failed; dataset outputs must not be used for training.")

    all_records = [record for split in records_by_split.values() for record in split]
    split_counts = Counter(record["split"] for record in all_records)
    cwe_counts = Counter(record["cwe"] for record in all_records)
    split_cwe_counts: dict[str, dict[str, int]] = {}
    for split, records in records_by_split.items():
        counts = Counter(record["cwe"] for record in records)
        split_cwe_counts[split] = {cwe: counts[cwe] for cwe in CWE_IDS}
    ecosystem_counts = Counter(family_specs[record["family"]].ecosystem for record in all_records)
    task_counts = Counter(record["task"] for record in all_records)
    task_split_counts = {
        split: dict(sorted(Counter(record["task"] for record in records).items()))
        for split, records in records_by_split.items()
    }
    stats = {
        "generator_version": GENERATOR_VERSION,
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "seed": seed,
        "total_records": len(all_records),
        "counts_by_split": {split: split_counts[split] for split in ("train", "val", "test", "holdout")},
        "counts_by_cwe": {cwe: cwe_counts[cwe] for cwe in CWE_IDS},
        "counts_by_split_and_cwe": split_cwe_counts,
        "counts_by_ecosystem": dict(sorted(ecosystem_counts.items())),
        "counts_by_task": dict(sorted(task_counts.items())),
        "counts_by_split_and_task": task_split_counts,
        "vulnerable_records": sum(record["is_vulnerable"] for record in all_records),
        "clean_negative_records": sum(not record["is_vulnerable"] for record in all_records),
        "template_family_count": len(set(record["family"] for record in all_records)),
        "generator_profile_count": len(SPECS),
        "unique_cwe_count": len(CWE_IDS),
        "template_families_by_split": {split: sorted(family_sets[split]) for split in records_by_split},
        "languages": {"python": len(all_records)},
        "sources": {"generated": len(all_records)},
        "source_licenses": {SOURCE_LICENSE: len(all_records)},
        "guidance_references": sorted(set(spec.reference for spec in SPECS)),
        "output_files": {split: str(DATA_DIR / f"v2_{split}.jsonl") for split in records_by_split},
    }
    _write_json(RESULTS_DIR / "data_v2_stats.json", stats)
    _write_json(RESULTS_DIR / "contamination_v2_report.json", contamination)
    (RESULTS_DIR / "dataset_v2_card.md").write_text(_dataset_card(stats, contamination), encoding="utf-8")
    return stats, contamination


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the deterministic PySecPatch synthetic dataset.")
    parser.add_argument("--build", action="store_true", help="build all four dataset splits")
    parser.add_argument("--count", type=int, default=60000, help="total record count")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="deterministic generator seed")
    args = parser.parse_args()
    if not args.build:
        parser.error("--build is required")
    try:
        stats, contamination = build_dataset(args.count, args.seed)
    except (OSError, RuntimeError, ValueError, SyntaxError, tokenize.TokenError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(
        json.dumps(
            {
                "status": "complete",
                "seed": args.seed,
                "counts_by_split": stats["counts_by_split"],
                "counts_by_cwe": stats["counts_by_cwe"],
                "counts_by_task": stats["counts_by_task"],
                "duplicate_count_removed": contamination["duplicate_count_removed"],
                "contamination_status": contamination["status"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

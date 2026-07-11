"""
eval_dataset.py

20 hand-labelled findings used to measure VulnAgent's triage accuracy.
The first 10 are REAL findings from our Bandit scan of vulnerable_app.py
(see samples/bandit_raw_output.json); the last 10 are synthetic findings
covering vulnerability classes Bandit doesn't produce (SSRF, XXE, IDOR,
hardcoded secrets, etc.) so the eval set has real severity diversity,
including CRITICAL cases.

ground_truth_severity: the severity a competent human security reviewer
would assign -- this is our "answer key."

ground_truth_should_escalate: whether a human reviewer would want this
routed to a person rather than auto-closed (CRITICAL findings, and a
couple of genuinely ambiguous ones included on purpose to test that the
agent doesn't over- or under-escalate).

Rationale notes are included per finding so the ground truth isn't just
asserted -- it's justified, in case anyone (including a future you)
wants to sanity-check or argue with a label.
"""

EVAL_FINDINGS = [
    # --- 10 real Bandit findings from samples/vulnerable_app.py ---
    {
        "id": "eval-0001", "source": "bandit",
        "title": "[B404] subprocess module import",
        "description": "Consider possible security implications associated with the subprocess module.",
        "file_path": "samples/vulnerable_app.py", "line_number": 9,
        "raw_severity": "LOW", "cwe_id": 78,
        "code_snippet": "import subprocess",
        "ground_truth_severity": "LOW", "ground_truth_should_escalate": False,
        "rationale": "Just an import warning, not an actual usage flaw.",
    },
    {
        "id": "eval-0002", "source": "bandit",
        "title": "[B403] pickle module import",
        "description": "Consider possible security implications associated with pickle module.",
        "file_path": "samples/vulnerable_app.py", "line_number": 11,
        "raw_severity": "LOW", "cwe_id": 502,
        "code_snippet": "import pickle",
        "ground_truth_severity": "LOW", "ground_truth_should_escalate": False,
        "rationale": "Just an import warning; the actual unsafe usage is a separate finding (eval-0005).",
    },
    {
        "id": "eval-0003", "source": "bandit",
        "title": "[B602] subprocess call with shell=True",
        "description": "subprocess call with shell=True identified, security issue.",
        "file_path": "samples/vulnerable_app.py", "line_number": 17,
        "raw_severity": "HIGH", "cwe_id": 78,
        "code_snippet": "subprocess.call(user_input, shell=True)",
        "ground_truth_severity": "HIGH", "ground_truth_should_escalate": False,
        "rationale": "Classic shell injection with unsanitized input reaching a shell -- clear-cut, well-understood fix (shell=False + list args), doesn't need human judgment to triage.",
    },
    {
        "id": "eval-0004", "source": "bandit",
        "title": "[B324] Weak MD5 hash for password",
        "description": "Use of weak MD5 hash for security. Consider usedforsecurity=False",
        "file_path": "samples/vulnerable_app.py", "line_number": 22,
        "raw_severity": "HIGH", "cwe_id": 327,
        "code_snippet": "hashlib.md5(password.encode()).hexdigest()",
        "ground_truth_severity": "HIGH", "ground_truth_should_escalate": False,
        "rationale": "MD5 used specifically for password hashing (not general checksums) means stolen hashes are trivially crackable -- real, high-impact risk.",
    },
    {
        "id": "eval-0005", "source": "bandit",
        "title": "[B301] Unsafe pickle.load on file input",
        "description": "Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data.",
        "file_path": "samples/vulnerable_app.py", "line_number": 28,
        "raw_severity": "MEDIUM", "cwe_id": 502,
        "code_snippet": "pickle.load(f)",
        "ground_truth_severity": "HIGH", "ground_truth_should_escalate": False,
        "rationale": "Unsafe deserialization of a caller-supplied file path is a known arbitrary-code-execution vector -- Bandit's own MEDIUM undersells this; a human reviewer would call it HIGH.",
    },
    {
        "id": "eval-0006", "source": "bandit",
        "title": "[B105] Hardcoded DB password",
        "description": "Possible hardcoded password: 'SuperSecret123'",
        "file_path": "samples/vulnerable_app.py", "line_number": 33,
        "raw_severity": "LOW", "cwe_id": 259,
        "code_snippet": "password = \"SuperSecret123\"",
        "ground_truth_severity": "MEDIUM", "ground_truth_should_escalate": False,
        "rationale": "Hardcoded credential in source -- real risk if repo is ever exposed, but contained to one system rather than a broadly reachable secret (contrast with eval-0011).",
    },
    {
        "id": "eval-0007", "source": "bandit",
        "title": "[B608] SQL injection via string formatting",
        "description": "Possible SQL injection vector through string-based query construction.",
        "file_path": "samples/vulnerable_app.py", "line_number": 39,
        "raw_severity": "MEDIUM", "cwe_id": 89,
        "code_snippet": "query = \"SELECT * FROM users WHERE id = '%s'\" % user_id",
        "ground_truth_severity": "HIGH", "ground_truth_should_escalate": False,
        "rationale": "Classic SQL injection pattern -- Bandit flags this as MEDIUM by default confidence, but the vulnerability class itself is a well-known HIGH-severity issue.",
    },
    {
        "id": "eval-0008", "source": "bandit",
        "title": "[B108] Hardcoded /tmp path",
        "description": "Probable insecure usage of temp file/directory.",
        "file_path": "samples/vulnerable_app.py", "line_number": 45,
        "raw_severity": "MEDIUM", "cwe_id": 377,
        "code_snippet": "return \"/tmp/vulnagent_temp_file\"",
        "ground_truth_severity": "LOW", "ground_truth_should_escalate": False,
        "rationale": "Predictable temp path is a minor local-race-condition risk, not a directly exploitable remote vector.",
    },
    {
        "id": "eval-0009", "source": "bandit",
        "title": "[B605] Process with shell behind debug flag",
        "description": "Starting a process with a shell: seems safe, but may be changed in the future.",
        "file_path": "samples/vulnerable_app.py", "line_number": 52,
        "raw_severity": "LOW", "cwe_id": 78,
        "code_snippet": "os.system(\"echo debug mode is on\")",
        "ground_truth_severity": "LOW", "ground_truth_should_escalate": False,
        "rationale": "Hardcoded, non-user-controlled command string -- no injection vector present today.",
    },
    {
        "id": "eval-0010", "source": "bandit",
        "title": "[B607] Partial executable path",
        "description": "Starting a process with a partial executable path.",
        "file_path": "samples/vulnerable_app.py", "line_number": 52,
        "raw_severity": "LOW", "cwe_id": 78,
        "code_snippet": "os.system(\"echo debug mode is on\")",
        "ground_truth_severity": "LOW", "ground_truth_should_escalate": False,
        "rationale": "PATH-hijack risk in theory, but low practical exploitability in typical deployment.",
    },

    # --- 10 synthetic findings covering vulnerability classes Bandit doesn't produce ---
    {
        "id": "eval-0011", "source": "simulated",
        "title": "Hardcoded AWS secret access key committed to repo",
        "description": "An AWS secret access key is hardcoded in a config file committed to version control.",
        "file_path": "config/settings.py", "line_number": 14,
        "raw_severity": "UNKNOWN", "cwe_id": 798,
        "code_snippet": "AWS_SECRET_KEY = \"AKIAIOSFODNN7EXAMPLE...\"",
        "ground_truth_severity": "CRITICAL", "ground_truth_should_escalate": True,
        "rationale": "A live cloud credential in source control is immediately exploitable by anyone with repo access and can lead to full account compromise -- textbook CRITICAL requiring immediate human action (key rotation).",
    },
    {
        "id": "eval-0012", "source": "simulated",
        "title": "SSRF in URL-fetching endpoint",
        "description": "An endpoint fetches a user-supplied URL server-side with no allowlist, enabling SSRF against internal services.",
        "file_path": "api/fetch.py", "line_number": 22,
        "raw_severity": "UNKNOWN", "cwe_id": 918,
        "code_snippet": "requests.get(request.args['url'])",
        "ground_truth_severity": "HIGH", "ground_truth_should_escalate": False,
        "rationale": "SSRF can expose internal infrastructure (cloud metadata endpoints, internal APIs) -- serious but a standard, well-understood fix (URL allowlisting) applies.",
    },
    {
        "id": "eval-0013", "source": "simulated",
        "title": "Reflected XSS in search parameter",
        "description": "The search results page reflects the 'q' query parameter directly into HTML without escaping.",
        "file_path": "templates/search.html", "line_number": 8,
        "raw_severity": "UNKNOWN", "cwe_id": 79,
        "code_snippet": "<div>Results for: {{ request.args.q | safe }}</div>",
        "ground_truth_severity": "MEDIUM", "ground_truth_should_escalate": False,
        "rationale": "Reflected XSS requires tricking a specific user into clicking a crafted link -- real but lower blast radius than stored XSS or server-side issues.",
    },
    {
        "id": "eval-0014", "source": "simulated",
        "title": "Missing rate limiting on login endpoint",
        "description": "The /login endpoint has no rate limiting or account lockout, permitting unlimited password guesses.",
        "file_path": "api/auth.py", "line_number": 30,
        "raw_severity": "UNKNOWN", "cwe_id": 307,
        "code_snippet": "def login(username, password): ...  # no attempt limiting",
        "ground_truth_severity": "MEDIUM", "ground_truth_should_escalate": False,
        "rationale": "Enables credential-stuffing/brute-force at scale, but requires the attacker to already have credential guesses or lists -- moderate, well-understood risk.",
    },
    {
        "id": "eval-0015", "source": "simulated",
        "title": "IDOR exposing other users' order data",
        "description": "The /orders/<id> endpoint returns order details for any numeric ID without checking ownership.",
        "file_path": "api/orders.py", "line_number": 41,
        "raw_severity": "UNKNOWN", "cwe_id": 639,
        "code_snippet": "order = Order.query.get(order_id)  # no user_id check",
        "ground_truth_severity": "HIGH", "ground_truth_should_escalate": False,
        "rationale": "Direct, trivially exploitable access to other users' private data by ID enumeration -- significant privacy/data breach risk.",
    },
    {
        "id": "eval-0016", "source": "simulated",
        "title": "Verbose error page exposes stack trace",
        "description": "Unhandled exceptions return a full stack trace and file paths to the client in production.",
        "file_path": "app.py", "line_number": 5,
        "raw_severity": "UNKNOWN", "cwe_id": 209,
        "code_snippet": "app.run(debug=True)",
        "ground_truth_severity": "LOW", "ground_truth_should_escalate": False,
        "rationale": "Information disclosure that aids further attacks, but not itself a direct exploitation path.",
    },
    {
        "id": "eval-0017", "source": "simulated",
        "title": "Predictable session tokens from insecure random",
        "description": "Session tokens are generated using Python's `random` module instead of a cryptographically secure source.",
        "file_path": "api/session.py", "line_number": 12,
        "raw_severity": "UNKNOWN", "cwe_id": 330,
        "code_snippet": "token = str(random.randint(100000, 999999))",
        "ground_truth_severity": "HIGH", "ground_truth_should_escalate": False,
        "rationale": "Predictable session tokens allow session hijacking / account takeover at scale -- serious, and the fix (secrets module) is standard.",
    },
    {
        "id": "eval-0018", "source": "simulated",
        "title": "XXE injection in XML parser",
        "description": "The XML parser used for uploaded files has external entity resolution enabled, permitting XXE attacks.",
        "file_path": "api/upload.py", "line_number": 19,
        "raw_severity": "UNKNOWN", "cwe_id": 611,
        "code_snippet": "etree.parse(uploaded_file)  # resolve_entities=True (default)",
        "ground_truth_severity": "CRITICAL", "ground_truth_should_escalate": True,
        "rationale": "XXE can lead to local file disclosure (including secrets/keys) or, in some configurations, remote code execution -- warrants immediate human review, not auto-remediation.",
    },
    {
        "id": "eval-0019", "source": "simulated",
        "title": "Permissive CORS with credentials",
        "description": "The API sets Access-Control-Allow-Origin to '*' while also allowing credentialed requests.",
        "file_path": "api/middleware.py", "line_number": 7,
        "raw_severity": "UNKNOWN", "cwe_id": 942,
        "code_snippet": "response.headers['Access-Control-Allow-Origin'] = '*'",
        "ground_truth_severity": "MEDIUM", "ground_truth_should_escalate": False,
        "rationale": "Allows any origin to make authenticated requests on a victim's behalf -- real but requires a victim to visit a malicious page while authenticated.",
    },
    {
        "id": "eval-0020", "source": "simulated",
        "title": "Known-critical CVE in unpatched dependency",
        "description": "A third-party logging library pinned in requirements.txt has a publicly disclosed critical remote-code-execution CVE with an available exploit.",
        "file_path": "requirements.txt", "line_number": 3,
        "raw_severity": "UNKNOWN", "cwe_id": 1035,
        "code_snippet": "vulnerable-logging-lib==2.14.1  # CVE-2024-EXAMPLE, CVSS 10.0",
        "ground_truth_severity": "CRITICAL", "ground_truth_should_escalate": True,
        "rationale": "Known, weaponized, unauthenticated RCE with a public exploit against a currently deployed dependency -- maximum urgency, needs a human-driven patch/mitigation decision, not just a ticket.",
    },
]
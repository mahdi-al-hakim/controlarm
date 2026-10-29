# CVE study: pre-fix and post-fix, ground truth from the vendor

Reproduce with `python benchmarks/cve_study/run_study.py --check`, which recomputes every number below and exits non-zero if any of them moved.

**11 of 15 candidate CVEs were reached.** 2 were admissible on paper but reachability could not be demonstrated here (CVE-2024-49766, CVE-2021-45452); 2 were rejected by the selection rule (CVE-2021-23980, CVE-2023-37920). Only reached targets enter any number.

The selection rule was written and committed **before** any target was chosen; see `SELECTION_RULE.md`. Memory-safety CVEs are excluded by rule, because a sanitizer is already a mechanical oracle there.

## 1. Pre-fix, rig intact: the false-negative rate

The vendor shipped a fix, so the vulnerability is present. `NO_BUG` is a false negative. A refusal is neither right nor wrong and is counted as its own class.

| configuration | FINDING | NO_BUG | refused | false-negative rate (95% CI) |
|---|---|---|---|---|
| gated | 11 | 0 | 0 | 0/11 = 0.00 [0.00, 0.28] |
| fair | 11 | 0 | 0 | 0/11 = 0.00 [0.00, 0.28] |
| naive (provenance, not a comparison) | 11 | 0 | 0 | 0/11 = 0.00 [0.00, 0.28] |

**Two-sided Fisher exact, gated versus fair: p = 1** (table {'gated_wrong': 0, 'gated_other': 11, 'fair_wrong': 0, 'fair_other': 11}).

## 2. Post-fix, rig intact: the false-positive rate

The fix is in, so `NO_BUG` is correct and `FINDING` is a false positive.

| configuration | FINDING | NO_BUG | refused | false-positive rate (95% CI) |
|---|---|---|---|---|
| gated | 0 | 11 | 0 | 0/11 = 0.00 [0.00, 0.28] |
| fair | 0 | 11 | 0 | 0/11 = 0.00 [0.00, 0.28] |
| naive (provenance, not a comparison) | 0 | 11 | 0 | 0/11 = 0.00 [0.00, 0.28] |

Two-sided Fisher exact, gated versus fair: p = 1.

## 3. Seeded rig breakage on the pre-fix version

The bug is present and the instrument is broken, so **`NO_BUG` is wrong** and a refusal is the only defensible answer. `FINDING` is unobtainable: the arm that would have found the bug never reached the target.

### Real breakage (the headline for this arm)

the headline for this arm. The failure text is written by CPython or the operating system, so no wording in this repository decided the outcome.

| configuration | FINDING | NO_BUG | refused | called "no bug" (wrong) (95% CI) |
|---|---|---|---|---|
| gated | 0 | 0 | 55 | 0/55 = 0.00 [0.00, 0.06] |
| fair | 0 | 0 | 55 | 0/55 = 0.00 [0.00, 0.06] |
| naive (provenance, not a comparison) | 1 | 54 | 0 | 54/55 = 0.98 [0.90, 1.00] |

Two-sided Fisher exact, gated versus fair: p = 1.

### Injected breakage (reported separately)

reported separately and NOT averaged into the headline: the failure text is chosen in this repository, and a confound table authored here recognising strings authored here is close to circular.

| configuration | FINDING | NO_BUG | refused | called "no bug" (wrong) (95% CI) |
|---|---|---|---|---|
| gated | 0 | 0 | 33 | 0/33 = 0.00 [0.00, 0.11] |
| fair | 11 | 0 | 22 | 0/33 = 0.00 [0.00, 0.11] |
| naive (provenance, not a comparison) | 11 | 22 | 0 | 22/33 = 0.67 [0.48, 0.82] |

Two-sided Fisher exact, gated versus fair: p = 1.

### Controls intact, only the exploit arm broken

the case that matters operationally: liveness and the honest control both pass and only the arm that would have found the bug fails.

| configuration | FINDING | NO_BUG | refused | called "no bug" (wrong) (95% CI) |
|---|---|---|---|---|
| gated | 0 | 0 | 55 | 0/55 = 0.00 [0.00, 0.06] |
| fair | 11 | 0 | 44 | 0/55 = 0.00 [0.00, 0.06] |
| naive (provenance, not a comparison) | 11 | 44 | 0 | 44/55 = 0.80 [0.67, 0.90] |

Two-sided Fisher exact, gated versus fair: p = 1.

### All breakage modes together

| configuration | FINDING | NO_BUG | refused | called "no bug" (wrong) (95% CI) |
|---|---|---|---|---|
| gated | 0 | 0 | 88 | 0/88 = 0.00 [0.00, 0.04] |
| fair | 11 | 0 | 77 | 0/88 = 0.00 [0.00, 0.04] |
| naive (provenance, not a comparison) | 12 | 76 | 0 | 76/88 = 0.86 [0.77, 0.93] |

Two-sided Fisher exact, gated versus fair: p = 1.

## 3b. Sensitivity: the fair baseline without the reachability record

NOT a comparison arm. The same reviewer callable, denied only the derived record of whether the treatment arm reached the target. It answers how much of the lattice's value that one record carries, and it is never averaged into any headline.

This is the single number that makes the null above interpretable. The fair baseline refuses a broken rig because it is handed the derived answer to *did the treatment arm reach the target at all*. Deny it only that record, change nothing else, and:

| set | FINDING | NO_BUG | refused | error rate (95% CI) |
|---|---|---|---|---|
| pre-fix, rig intact (error = NO_BUG) | 11 | 0 | 0 | 0/11 = 0.00 [0.00, 0.28] |
| post-fix, rig intact (error = FINDING) | 0 | 11 | 0 | 0/11 = 0.00 [0.00, 0.28] |
| seeded breakage, all modes (error = NO_BUG) | 11 | 44 | 33 | 44/88 = 0.50 [0.39, 0.61] |
| seeded breakage, real modes (error = NO_BUG) | 0 | 22 | 33 | 22/55 = 0.40 [0.27, 0.54] |

Gated versus this arm on all seeded breakage: Fisher p = 7.885e-17; on real modes only: p = 3.415e-08.

**Those two p-values are at the wrong unit and are retained only so the inflation is visible.** Seven of
the eight breakage modes produce exactly one outcome across all eleven CVEs: the mode determines the
verdict and the CVE contributes nothing, so a run-level denominator counts one deterministic result
eleven times. At the mode level the comparison is **2 of 5 versus 0 of 5, Fisher p = 0.4444** on real
modes, and 4 of 8 versus 0 of 8, p = 0.0769 on all modes. An earlier version of this file led with the
run-level figures. That was the wrong unit, and it was wrong in the direction that flattered the lattice.

**Read it as a localisation, not as a win.** It says the lattice's value on this corpus is carried almost entirely by one record that a competent engineer could keep without this library, and that an engineer who does not keep it reports a broken rig as a clean target. It does not say the lattice beat the competent engineer: it did not, which is section 3.

### Where the two configurations actually differ

The error rates above are identical, so it is worth saying plainly where gated and fair do **not** behave the same. On `stale_positive_control` the exploit arm still runs and still fires, because that mode corrupts the control's *record* rather than the exploit path. Gated refuses the run (`VOID`, rule `B-stale-control`) because the positive control it would be relying on belongs to an earlier run. Fair proceeds and reports a finding, which on a pre-fix pin is the right answer about the target.

That is the lattice being **more conservative than it needed to be**, not the lattice winning. It is counted as a refusal, it costs gated eleven correct findings, and it is the one place in this study where the discipline has a measurable price. Reporting it as a win would be the same move this repository criticises elsewhere.

### By breakage mode

| mode | scope | realism | gated "no bug" | fair "no bug" | naive "no bug" | fair-no-reach "no bug" |
|---|---|---|---|---|---|---|
| `expired_credential` | exploit | injected | 0/11 | 0/11 | 11/11 | 11/11 |
| `helper_binary_absent` | exploit | real | 0/11 | 0/11 | 11/11 | 11/11 |
| `interpreter_missing` | rig | real | 0/11 | 0/11 | 11/11 | 0/11 |
| `probe_process_killed` | rig | real | 0/11 | 0/11 | 11/11 | 0/11 |
| `rate_limited` | exploit | injected | 0/11 | 0/11 | 11/11 | 11/11 |
| `scratch_dir_deleted` | exploit | real | 0/11 | 0/11 | 11/11 | 11/11 |
| `stale_positive_control` | control-record | injected | 0/11 | 0/11 | 0/11 | 0/11 |
| `target_package_absent` | rig | real | 0/11 | 0/11 | 10/11 | 0/11 |

## 4. The targets

| CVE | package | pre -> post | class | status |
|---|---|---|---|---|
| [CVE-2020-14343](https://nvd.nist.gov/vuln/detail/CVE-2020-14343) | PyYAML | `5.3.1` -> `5.4` | deserialisation-allowlist-bypass | REACHED |
| [CVE-2024-22195](https://nvd.nist.gov/vuln/detail/CVE-2024-22195) | Jinja2 | `3.1.2` -> `3.1.3` | sanitizer-bypass | REACHED |
| [CVE-2024-34064](https://nvd.nist.gov/vuln/detail/CVE-2024-34064) | Jinja2 | `3.1.3` -> `3.1.4` | sanitizer-bypass | REACHED |
| [CVE-2023-23934](https://nvd.nist.gov/vuln/detail/CVE-2023-23934) | Werkzeug | `2.2.2` -> `2.2.3` | parser-differential | REACHED |
| [CVE-2022-29217](https://nvd.nist.gov/vuln/detail/CVE-2022-29217) | PyJWT | `2.3.0` -> `2.4.0` | signature-verification | REACHED |
| [CVE-2024-53861](https://nvd.nist.gov/vuln/detail/CVE-2024-53861) | PyJWT | `2.10.0` -> `2.10.1` | signature-verification | REACHED |
| [CVE-2022-24761](https://nvd.nist.gov/vuln/detail/CVE-2022-24761) | waitress | `2.1.0` -> `2.1.1` | parser-differential | REACHED |
| [CVE-2021-42771](https://nvd.nist.gov/vuln/detail/CVE-2021-42771) | Babel | `2.9.0` -> `2.9.1` | path-traversal | REACHED |
| [CVE-2021-45116](https://nvd.nist.gov/vuln/detail/CVE-2021-45116) | Django | `3.2.10` -> `3.2.11` | business-logic | REACHED |
| [CVE-2024-6221](https://nvd.nist.gov/vuln/detail/CVE-2024-6221) | Flask-Cors | `4.0.2` -> `5.0.0` | authorization | REACHED |
| [CVE-2023-28370](https://nvd.nist.gov/vuln/detail/CVE-2023-28370) | tornado | `6.3.1` -> `6.3.2` | open-redirect | REACHED |
| [CVE-2024-49766](https://nvd.nist.gov/vuln/detail/CVE-2024-49766) | Werkzeug | `3.0.4` -> `3.0.6` | path-traversal | UNREACHED |
| [CVE-2021-45452](https://nvd.nist.gov/vuln/detail/CVE-2021-45452) | Django | `3.2.10` -> `3.2.11` | path-traversal | UNREACHED |
| [CVE-2021-23980](https://nvd.nist.gov/vuln/detail/CVE-2021-23980) | bleach | `3.3.0` -> `3.3.1` | sanitizer-bypass | REJECTED |
| [CVE-2023-37920](https://nvd.nist.gov/vuln/detail/CVE-2023-37920) | certifi | `2023.5.7` -> `2023.7.22` | business-logic | REJECTED |

### CVE-2020-14343 (PyYAML 5.3.1 -> 5.4) -- REACHED

- **class** deserialisation-allowlist-bypass
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2020-14343
- **fix** https://github.com/yaml/pyyaml/releases/tag/5.4
- **fix evidence** 5.4's FullConstructor refuses the python/object/new tag path that 5.3.1 accepts, so the same document raises ConstructorError instead of constructing a type.
- **oracle** a directory the probe never creates itself exists on disk after full_load() returns, because the deserialiser called os.mkdir. A filesystem side effect, not a substring of the document the probe supplied.
- **reachability** yaml.full_load is the documented entry point advertised as safe against arbitrary code execution; the probe calls it directly and the observable is a real directory created during the parse.
- **notes** Acquired from the sdist's pure-Python lib3 subtree, together with its LICENSE, because PyYAML 5.x publishes no wheel for CPython 3.12 and its C extension is optional. The cached code is the released source, unmodified, and like every other pin it lives in the gitignored cache rather than in the repository.

### CVE-2024-22195 (Jinja2 3.1.2 -> 3.1.3) -- REACHED

- **class** sanitizer-bypass
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2024-22195
- **fix** https://github.com/pallets/jinja/releases/tag/3.1.3
- **fix evidence** 3.1.3's xmlattr filter raises ValueError for a key containing whitespace; 3.1.2 interpolates the key verbatim into the attribute string.
- **oracle** the rendered tag carries an attribute name the template author never wrote, measured by parsing the rendered tag's attribute names rather than by searching the output for the payload text.
- **reachability** xmlattr is a shipped filter; the probe renders a template through the public Environment API and the injected attribute appears in the returned markup.
- **unpinned scaffolding** markupsafe (not the independent variable)

### CVE-2024-34064 (Jinja2 3.1.3 -> 3.1.4) -- REACHED

- **class** sanitizer-bypass
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2024-34064
- **fix** https://github.com/pallets/jinja/releases/tag/3.1.4
- **fix evidence** 3.1.4's xmlattr filter raises ValueError for keys containing '/', '>' or '='; 3.1.3 rejected only whitespace, so a key with none of it passed through.
- **oracle** the same attribute-name parse as CVE-2024-22195, driven by a key that contains no whitespace, so the two Jinja2 targets are not one payload scored twice.
- **reachability** the same public filter, and the 3.1.3 pin demonstrably renders the '=' key that 3.1.4 rejects, so the two pins differ on exactly this input.
- **unpinned scaffolding** markupsafe (not the independent variable)

### CVE-2023-23934 (Werkzeug 2.2.2 -> 2.2.3) -- REACHED

- **class** parser-differential
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2023-23934
- **fix** https://github.com/pallets/werkzeug/releases/tag/2.2.3
- **fix evidence** 2.2.3 stops treating a nameless cookie's value as a further cookie string, so the header '=__Host-auth=x' no longer yields a '__Host-auth' key.
- **oracle** parse_cookie() returns a mapping containing the key '__Host-auth'. The probe reads a parsed field, not a substring of the header it supplied.
- **reachability** werkzeug.http.parse_cookie is the public parser Flask uses for request cookies; the probe calls it with a header value and reads the parsed mapping back.
- **unpinned scaffolding** markupsafe (not the independent variable)

### CVE-2022-29217 (PyJWT 2.3.0 -> 2.4.0) -- REACHED

- **class** signature-verification
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2022-29217
- **fix** https://github.com/jpadilla/pyjwt/releases/tag/2.4.0
- **fix evidence** 2.4.0 replaces HMACAlgorithm.prepare_key's four-string blocklist with is_pem_format/is_ssh_key, so an OpenSSH-format ed25519 public key is refused as an HMAC secret; 2.3.0's blocklist named only 'ssh-rsa'.
- **oracle** jwt.decode() returns a verified claim set for a token signed HS256 with a public key as the secret. The observable is a successful signature verification.
- **reachability** the probe generates a throwaway ed25519 key pair in-process, uses only its public half, and 2.3.0 both signs and verifies with it while 2.4.0 raises InvalidKeyError. No network and no pre-existing key material.
- **unpinned scaffolding** cryptography (not the independent variable)

### CVE-2024-53861 (PyJWT 2.10.0 -> 2.10.1) -- REACHED

- **class** signature-verification
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2024-53861
- **fix** https://github.com/jpadilla/pyjwt/releases/tag/2.10.1
- **fix evidence** 2.10.1 compares the iss claim for equality; 2.10.0 used a containment test, so an iss of 'good' satisfied an expected issuer of 'https://good.example'.
- **oracle** jwt.decode(..., issuer=...) returns instead of raising InvalidIssuerError for a token whose iss is a strict substring of the expected issuer.
- **reachability** issuer validation is a documented decode option; the probe mints its own HS256 token and the 2.10.0 pin accepts the wrong issuer while 2.10.1 rejects it.

### CVE-2022-24761 (waitress 2.1.0 -> 2.1.1) -- REACHED

- **class** parser-differential
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2022-24761
- **fix** https://github.com/Pylons/waitress/releases/tag/v2.1.1
- **fix evidence** 2.1.1 validates Content-Length against ONLY_DIGIT_RE before calling int(); 2.1.0 passed the raw value to int(), which accepts a leading '+' and underscore digit separators.
- **oracle** the parser reports no error and a numeric content_length for a Content-Length header that is not a digit string. That front-end/back-end disagreement is what makes request smuggling possible, and it is read off the parser's own state.
- **reachability** waitress.parser.HTTPRequestParser is fed raw request bytes directly; no socket is opened and no server is started.

### CVE-2021-42771 (Babel 2.9.0 -> 2.9.1) -- REACHED

- **class** path-traversal
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2021-42771
- **fix** https://github.com/python-babel/babel/releases/tag/v2.9.1
- **fix evidence** 2.9.1 adds resolve_locale_filename, which applies os.path.basename to the locale identifier before joining it to the locale-data directory; 2.9.0 joined it raw.
- **oracle** localedata.load() returns a sentinel value that exists only in a file the probe placed OUTSIDE the locale-data directory. The traversal is proven by the content that came back, not by the path that went in.
- **reachability** babel.localedata.load is the loader Locale.parse uses; the probe writes one out-of-tree .dat file and the 2.9.0 pin reads it through a '../' identifier.
- **unpinned scaffolding** pytz (not the independent variable)

### CVE-2021-45116 (Django 3.2.10 -> 3.2.11) -- REACHED

- **class** business-logic
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2021-45116
- **fix** https://docs.djangoproject.com/en/stable/releases/3.2.11/
- **fix evidence** 3.2.11 replaces dictsort's Variable(arg).resolve with a restricted chain of __getitem__/getattr that does not invoke callables and forbids private names; 3.2.10 resolved through the template Variable machinery, which calls them.
- **oracle** a sentinel method that the filter argument never marks as a call is nonetheless invoked, recorded by the sentinel object itself. A side effect in the target.
- **reachability** dictsort is a built-in template filter taking an attribute path; the probe calls the filter directly with settings configured in-process, with no database and no request cycle.
- **unpinned scaffolding** asgiref, sqlparse, pytz, tzdata (not the independent variable)

### CVE-2024-6221 (Flask-Cors 4.0.2 -> 5.0.0) -- REACHED

- **class** authorization
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2024-6221
- **fix** https://github.com/corydolphin/flask-cors/releases/tag/5.0.0
- **fix evidence** 5.0.0 flips the allow_private_network default in flask_cors/core.py from True to False, so Access-Control-Allow-Private-Network is no longer sent as 'true' under a default CORS() configuration.
- **oracle** the response carries Access-Control-Allow-Private-Network: true under a default CORS() setup -- a response header the application never set.
- **reachability** the probe drives a Flask app through its own in-process test client, so no socket is bound, and reads the header off the response object.
- **unpinned scaffolding** flask (not the independent variable)
- **notes** The pre-fix pin is 4.0.2, not 4.0.1: 4.0.2 is where allow_private_network first exists and defaults to True, so 4.0.2 -> 5.0.0 isolates the default flip. Using 4.0.1 would have confounded the fix with the option's introduction.

### CVE-2023-28370 (tornado 6.3.1 -> 6.3.2) -- REACHED

- **class** open-redirect
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2023-28370
- **fix** https://github.com/tornadoweb/tornado/releases/tag/v6.3.2
- **fix evidence** 6.3.2 raises HTTPError(403, 'cannot redirect path with two initial slashes') in StaticFileHandler.validate_absolute_path before the trailing-slash redirect; 6.3.1 issued the redirect.
- **oracle** the handler's own redirect() sink is called with a protocol-relative target, captured at the sink. What the library decided to do, not what the probe asked it for.
- **reachability** the probe instantiates StaticFileHandler against a real temporary directory with a default_filename and calls validate_absolute_path; no listening socket. 6.3.1 redirects to '//evil.example/' and 6.3.2 raises 403.

### CVE-2024-49766 (Werkzeug 3.0.4 -> 3.0.6) -- UNREACHED

- **class** path-traversal
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2024-49766
- **fix** https://github.com/pallets/werkzeug/releases/tag/3.0.6
- **fix evidence** 3.0.6 adds a leading-slash rejection to safe_join, carrying the comment that ntpath.isabs does not catch this on Python older than 3.11.
- **oracle** safe_join() returns a path instead of None for an absolute or UNC filename.
- **reachability** NOT ESTABLISHED. The fix's own comment scopes the vulnerable branch to Python older than 3.11; this study ran on CPython 3.12.5, where ntpath.isabs already rejects the payload and both pins return None for every variant tried. Reachability would need an interpreter this environment does not have, so the target is excluded from every headline rather than guessed at.

### CVE-2021-45452 (Django 3.2.10 -> 3.2.11) -- UNREACHED

- **class** path-traversal
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2021-45452
- **fix** https://docs.djangoproject.com/en/stable/releases/3.2.11/
- **fix evidence** 3.2.11 normalises backslashes in Storage.get_available_name and re-validates the name returned by _save.
- **oracle** a file exists outside MEDIA_ROOT after Storage.save() returns.
- **reachability** NOT ESTABLISHED. With the stock FileSystemStorage on this platform both pins raise SuspiciousFileOperation for every traversal payload tried, because an earlier validation catches it first. The fix guards a name returned by a custom _save override, so reaching it would mean shipping a deliberately broken storage backend and measuring that instead of Django. Excluded from the headline.

### CVE-2021-23980 (bleach 3.3.0 -> 3.3.1) -- REJECTED

- **class** sanitizer-bypass
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2021-23980
- **fix** https://github.com/mozilla/bleach/releases/tag/v3.3.1
- **fix evidence** NONE FOUND between these pins: diffing the two installed trees shows bleach/ differing only in the version string in __init__.py and the removal of a vendored Django copy. No sanitizer or html5lib-shim change is present.
- **oracle** n/a -- rejected before an oracle was declared.
- **reachability** n/a. Rejected under rule C2: this pin pair does not straddle the fix, so it cannot supply pre-fix/post-fix ground truth. Kept in the registry to record that the rule rejected a candidate rather than being bent to admit it.

### CVE-2023-37920 (certifi 2023.5.7 -> 2023.7.22) -- REJECTED

- **class** business-logic
- **advisory** https://nvd.nist.gov/vuln/detail/CVE-2023-37920
- **fix** https://github.com/certifi/python-certifi/releases/tag/2023.07.22
- **fix evidence** 2023.07.22 removes the e-Tugra root certificates from cacert.pem.
- **oracle** n/a -- rejected before an oracle was declared.
- **reachability** n/a. Rejected under rule C4: searching a PEM bundle for a removed root is a cheap mechanical oracle that already exists, so this target would not exercise the claim the study is about. Recorded because excluding it was a judgement call and a reader is entitled to disagree with it.

## 5. Baseline cross-check

The `fair` configuration is the external reviewer's own `competent()` callable. `gates._fair` is a transcription of it, and every run was adjudicated by both. They agreed on all 110 runs, so the baseline is the reviewer's, not a weakened copy.

Total runs: 110 = 11 CVEs x (2 clean + 8 breakage modes).


# Test Case Design — Issue #27 (TLS client-certificate / mTLS auth)

SE run #1491, Step 3 (QA). Designed by Gem (QA Lead). Revised after Step 4 (Project Leadership)
review of commit `a4976b2`. Implementation is **not** included here — this document specifies
test cases for Coder to implement in `test/test_issue_27.rb` following the conventions in
`test/test_issues_6_7_8.rb` (minitest, `build_client` helper, no live HTTP, `rake test` /
`ruby test/test_issue_27.rb`).

**Pinned artifact:** `dtrammell/ruby-cryptomnio`, branch `main` @ `ec44c30606fcdd5ca39488ce037e2d46657bd945`.

**Correction to Step 2 report:** the Step 2 validation report (`SE1491-step2-validation-report.md`)
says the delivered GEB/NUT keys are OpenSSH-format and cannot be loaded by `OpenSSL::PKey.read`.
That is wrong — `file(1)` mislabels them. All three delivered keys (beta, GEB, NUT) are standard
PEM PKCS#8 (`-----BEGIN PRIVATE KEY-----`), confirmed by `OpenSSL::PKey.read` loading them and
`cert.check_private_key(key)` returning `true` for all three. No OpenSSH-to-PEM conversion step
is needed in the implementation. This test design assumes PKCS#8/PEM throughout and does not test
OpenSSH key parsing.

**Agreed design (issue #27, final comment):** optional per-client-instance config keys
`:ssl_client_cert` (path), `:ssl_client_key` (path), `:ssl_client_key_passphrase`, `:ssl_ca_file`
(path). Files are loaded once at construction into OpenSSL objects; the objects (and the CA path
string) are passed to every `RestClient::Request.execute` call, including retries. `verify_ssl`
stays `VERIFY_PEER`. HMAC signing (`Access-Key` / `Sign` headers) is unchanged and independent of
mTLS. With none of the four keys configured, behaviour is byte-identical to today. Construction
fails early (raises before any network I/O) when: only one of cert/key is set; a configured file
is unreadable or won't parse; the key doesn't match the cert. Error messages name the file path
and never include file contents. Key objects (and passphrases) are never logged or inspected,
including under `$DEBUG`.

---

## 0. Shared Fixtures & Conventions

All fixtures are generated at test-run time with Ruby's `openssl` stdlib into a per-run
`Dir.mktmpdir`, torn down in an `ensure`/`Minitest.after_run` block. **Nothing under `~/.secrets`
is read, copied, or referenced anywhere in this suite or its fixtures.** No real Cryptomnio host
is contacted by the automated suite; `RestClient::Request.execute` is stubbed via
`define_singleton_method` on the client, following the existing `_rest_call`-stubbing pattern in
`test/test_issues_6_7_8.rb`.

Two independent throwaway CAs are generated, named to mirror the issue's real-world GEB/NUT CA
separation (`Cryptomnio Geb CA`, `Cryptomnio Nut CA`), each signing its own leaf cert/key pair.
Additional helpers generate a second, independent cert (for chain-file fixtures, TC-27-7) and an
expired leaf cert/key pair (TC-27-8):

```ruby
require 'openssl'
require 'tmpdir'

module MtlsFixtures
  Pki = Struct.new(:dir, :ca_cert_path, :cert_path, :key_path, :key_object, :cert_object,
                    :encrypted_key_path, :passphrase, :mismatched_key_path, keyword_init: true)

  # Self-signed throwaway CA + one leaf cert/key signed by it.
  def self.build(label:, passphrase: "test-pass-#{label}")
    dir = Dir.mktmpdir("mtls-fixture-#{label}-")

    ca_key  = OpenSSL::PKey::RSA.new(2048)
    ca_name = OpenSSL::X509::Name.parse("/CN=Cryptomnio #{label.capitalize} CA")
    ca_cert = OpenSSL::X509::Certificate.new.tap do |c|
      c.version = 2; c.serial = 1; c.subject = ca_name; c.issuer = ca_name
      c.public_key = ca_key.public_key
      c.not_before = Time.now - 3600; c.not_after = Time.now + 3600 * 24 * 365
      c.sign(ca_key, OpenSSL::Digest.new('SHA256'))
    end

    leaf_key  = OpenSSL::PKey::RSA.new(2048)
    leaf_name = OpenSSL::X509::Name.parse("/CN=test-client-#{label}@example.invalid")
    leaf_cert = OpenSSL::X509::Certificate.new.tap do |c|
      c.version = 2; c.serial = 2; c.subject = leaf_name; c.issuer = ca_cert.subject
      c.public_key = leaf_key.public_key
      c.not_before = Time.now - 3600; c.not_after = Time.now + 3600 * 24 * 365
      c.sign(ca_key, OpenSSL::Digest.new('SHA256'))
    end

    # A second, unrelated key — never paired with leaf_cert — for mismatch tests.
    other_key = OpenSSL::PKey::RSA.new(2048)

    ca_path   = File.join(dir, "ca.pem");   File.write(ca_path, ca_cert.to_pem)
    cert_path = File.join(dir, "cert.pem"); File.write(cert_path, leaf_cert.to_pem)
    key_path  = File.join(dir, "key.pem");  File.write(key_path, leaf_key.to_pem)
    enc_path  = File.join(dir, "key.enc.pem")
    File.write(enc_path, leaf_key.to_pem(OpenSSL::Cipher.new("AES-256-CBC"), passphrase))
    mismatched_path = File.join(dir, "other_key.pem"); File.write(mismatched_path, other_key.to_pem)

    Pki.new(dir: dir, ca_cert_path: ca_path, cert_path: cert_path, key_path: key_path,
            key_object: leaf_key, cert_object: leaf_cert, encrypted_key_path: enc_path,
            passphrase: passphrase, mismatched_key_path: mismatched_path)
  end

  def self.garbage_file(dir) = tap_write(dir, "garbage.pem", "this is not PEM data at all\n")
  def self.empty_file(dir)   = tap_write(dir, "empty.pem", "")
  def self.cert_as_key_path(pki) = pki.cert_path # valid cert content, used where a key is expected

  def self.tap_write(dir, name, content)
    path = File.join(dir, name); File.write(path, content); path
  end

  # A second, independent self-signed cert, used only as a second PEM block in chain-file
  # fixtures (TC-27-7). It does not need to be cryptographically chained to any CA here — the
  # behaviour under test is PEM-block parsing order (which block is used as the client cert /
  # which blocks end up in the CA store), not certificate-path validation.
  def self.extra_cert(label:)
    key  = OpenSSL::PKey::RSA.new(2048)
    name = OpenSSL::X509::Name.parse("/CN=Cryptomnio #{label.capitalize} Intermediate (fixture)")
    OpenSSL::X509::Certificate.new.tap do |c|
      c.version = 2; c.serial = 9; c.subject = name; c.issuer = name
      c.public_key = key.public_key
      c.not_before = Time.now - 3600; c.not_after = Time.now + 3600 * 24 * 365
      c.sign(key, OpenSSL::Digest.new('SHA256'))
    end
  end

  # A client-cert file holding a chain: the real leaf cert PEM block followed by a second,
  # unrelated cert PEM block concatenated into one file — for TC-27-7's cert-chain half.
  def self.chain_cert_path(pki, extra)
    path = File.join(pki.dir, "chain_cert.pem")
    File.write(path, pki.cert_object.to_pem + extra.to_pem)
    path
  end

  # A CA file holding a chain: the real CA cert PEM block followed by a second, unrelated cert
  # PEM block — for TC-27-7's CA-chain half.
  def self.chain_ca_path(pki, extra)
    path = File.join(pki.dir, "chain_ca.pem")
    File.write(path, File.read(pki.ca_cert_path) + extra.to_pem)
    path
  end

  # An expired leaf cert/key pair (notBefore/notAfter both in the past), signed by a throwaway
  # CA — for TC-27-8. Deliberately standalone from `build` above so the main GEB/NUT fixtures'
  # validity windows are untouched.
  def self.build_expired(label:)
    dir = Dir.mktmpdir("mtls-fixture-#{label}-expired-")
    ca_key  = OpenSSL::PKey::RSA.new(2048)
    ca_name = OpenSSL::X509::Name.parse("/CN=Cryptomnio #{label.capitalize} CA (expired-fixture)")
    ca_cert = OpenSSL::X509::Certificate.new.tap do |c|
      c.version = 2; c.serial = 1; c.subject = ca_name; c.issuer = ca_name
      c.public_key = ca_key.public_key
      c.not_before = Time.now - 3600 * 24 * 1000; c.not_after = Time.now + 3600 * 24 * 365
      c.sign(ca_key, OpenSSL::Digest.new('SHA256'))
    end
    leaf_key = OpenSSL::PKey::RSA.new(2048)
    leaf_cert = OpenSSL::X509::Certificate.new.tap do |c|
      c.version = 2; c.serial = 2
      c.subject = OpenSSL::X509::Name.parse("/CN=test-client-#{label}-expired@example.invalid")
      c.issuer = ca_cert.subject; c.public_key = leaf_key.public_key
      c.not_before = Time.now - 3600 * 24 * 730 # ~2 years ago
      c.not_after  = Time.now - 3600 * 24 * 365 # ~1 year ago -- expired
      c.sign(ca_key, OpenSSL::Digest.new('SHA256'))
    end
    cert_path = File.join(dir, "expired_cert.pem"); File.write(cert_path, leaf_cert.to_pem)
    key_path  = File.join(dir, "expired_key.pem");  File.write(key_path, leaf_key.to_pem)
    [cert_path, key_path]
  end
end

GEB = MtlsFixtures.build(label: "geb")
NUT = MtlsFixtures.build(label: "nut")

GEB_CHAIN_CERT_PATH          = MtlsFixtures.chain_cert_path(GEB, MtlsFixtures.extra_cert(label: "geb"))
GEB_CHAIN_CA_PATH            = MtlsFixtures.chain_ca_path(GEB, MtlsFixtures.extra_cert(label: "geb-root2"))
EXPIRED_CERT_PATH, EXPIRED_KEY_PATH = MtlsFixtures.build_expired(label: "geb")
```

`build_client` is extended with an optional `ssl:` kwarg merged into `STUB_CONFIG` before
construction, so cases can do `build_client(ssl: { ssl_client_cert: GEB.cert_path, ... })`.

---

## 1. Happy path & backward compatibility (8 cases)

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-27-1 | `build_client(ssl: {ssl_client_cert: GEB.cert_path, ssl_client_key: GEB.key_path, ssl_ca_file: GEB.ca_cert_path})`. Stub `RestClient::Request.execute` to capture its kwargs and return a fake 200 JSON body. | `client.get_venues` | Construction succeeds; the captured kwargs include `ssl_client_cert` as an `OpenSSL::X509::Certificate` equal to `GEB.cert_object` (by `to_der`), `ssl_client_key` as an `OpenSSL::PKey::RSA` whose `to_der` matches `GEB.key_object`, and `ssl_ca_file == GEB.ca_cert_path` (a String); call returns the parsed body |
| TC-27-2 | `build_client(ssl: {ssl_client_cert: GEB.cert_path, ssl_client_key: GEB.key_path})` (no CA file) | `client.get_venues` | Succeeds; captured kwargs include `ssl_client_cert`/`ssl_client_key` but **no** `ssl_ca_file` key at all (not `nil`-valued — absent) |
| TC-27-3 | `build_client` with no `ssl:` kwarg at all (today's config shape, unchanged) | `client.get_venues` | Captured `RestClient::Request.execute` kwargs hash is `==` to exactly `{method:, url:, headers:, payload:}` — no `ssl_client_cert`/`ssl_client_key`/`ssl_ca_file`/`verify_ssl` key present under any key name, confirming byte-identical behaviour |
| TC-27-4 | `build_client` with no `ssl:` kwarg | Construct only, no call | Construction does not raise; no new required constructor params were introduced |
| TC-27-5 | `build_client(ssl: {ssl_ca_file: GEB.ca_cert_path})` (CA only, no cert/key) | `client.get_venues` | Construction succeeds; captured kwargs include `ssl_ca_file` only, no `ssl_client_cert`/`ssl_client_key` — i.e. the request presents **no client certificate** and relies on `ssl_ca_file` purely for server-chain verification. See Decisions & Rationale #3 for the accept-vs-reject argument. |
| TC-27-6 | `build_client(ssl: {ssl_ca_file: GEB.ca_cert_path})` — same config as TC-27-5, but this case asserts the **validation boundary** rather than the request shape: construction must *not* raise the "cert and key must both be provided" error that TC-27-10/TC-27-11 trigger when exactly one of cert/key is set. | Construct only, no call | Construction does not raise `ArgumentError`; CA-only is explicitly outside the all-or-nothing cert/key pairing rule, distinct from "only one of cert or key" |
| TC-27-7 | `build_client(ssl: {ssl_client_cert: GEB_CHAIN_CERT_PATH, ssl_client_key: GEB.key_path, ssl_ca_file: GEB_CHAIN_CA_PATH})` — cert file and CA file each hold two concatenated PEM blocks (leaf + an unrelated second cert) | `client.get_venues` | Construction succeeds (no "multiple certs in file" error). The captured `ssl_client_cert` kwarg's `to_der` matches `GEB.cert_object` (the **first/leaf** PEM block only) — `cert.check_private_key(key)` must still pass against `GEB.key_object`, which would fail if the second block were loaded instead. `ssl_ca_file` is passed through as the raw path string unchanged (`GEB_CHAIN_CA_PATH`); both CA-chain PEM blocks in that file are left for `Net::HTTP`/OpenSSL to load from disk — the gem does no per-block parsing of `ssl_ca_file`. See Decisions & Rationale #9. |
| TC-27-8 | `build_client(ssl: {ssl_client_cert: EXPIRED_CERT_PATH, ssl_client_key: EXPIRED_KEY_PATH})` — the cert's `not_after` is ~1 year in the past | Construct, then `client.get_venues` (stub returns 200) | Construction does **not** raise for expiry. `cert.check_private_key(key)` still returns `true` for an expired-but-matching pair, so the only validation performed is path/parse/match — no `cert.not_after < Time.now` check is added. The call proceeds and the expired cert is forwarded to `RestClient::Request.execute` exactly as a valid one would be; whether the *server* accepts an expired cert during the TLS handshake is the server's decision, not this gem's. See Decisions & Rationale #10 — this case exists specifically to stop an implementer from adding a surprise local expiry check. |

---

## 2. Fail-early validation (10 cases)

All of these assert the exception is raised **during `Cryptomnio::REST::Client.new`**, before any
stub/spy on `RestClient::Request.execute` is ever invoked (assert call count 0 on the spy), and
that the exception message contains the offending file path string but never the file's bytes.

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-27-10 | `ssl_client_cert: GEB.cert_path` only, no key | `build_client(ssl: ...)` | Raises `ArgumentError`; message mentions both `ssl_client_cert` and `ssl_client_key` must both be set |
| TC-27-11 | `ssl_client_key: GEB.key_path` only, no cert | `build_client(ssl: ...)` | Raises `ArgumentError`, symmetric message |
| TC-27-12 | `ssl_client_cert: "#{GEB.dir}/does-not-exist.pem"`, valid key | `build_client(ssl: ...)` | Raises; message includes the nonexistent path; never attempts `RestClient::Request.execute` |
| TC-27-13 | Valid cert, `ssl_client_key: "#{GEB.dir}/does-not-exist.pem"` | `build_client(ssl: ...)` | Raises; message includes the path |
| TC-27-14 | Valid cert+key, `ssl_ca_file: "#{GEB.dir}/does-not-exist.pem"` | `build_client(ssl: ...)` | Raises at construction — the CA path is validated even though it's optional-when-absent — once set, it must be valid; message includes the path |
| TC-27-15 | `ssl_client_cert: MtlsFixtures.garbage_file(GEB.dir)`, valid key | `build_client(ssl: ...)` | Raises (certificate parse failure); message includes the garbage file's path, never its contents |
| TC-27-16 | Valid cert, `ssl_client_key: MtlsFixtures.garbage_file(GEB.dir)` | `build_client(ssl: ...)` | Raises (key parse failure); message includes path only |
| TC-27-17 | `ssl_client_cert: GEB.cert_path`, `ssl_client_key: GEB.mismatched_key_path` (valid key, wrong pair) | `build_client(ssl: ...)` | Raises a distinct "certificate does not match key" message (not a generic parse error); no key material in message |
| TC-27-18 | `ssl_client_cert: GEB.cert_path`, `ssl_client_key: MtlsFixtures.cert_as_key_path(GEB)` (a cert file given as the key) | `build_client(ssl: ...)` | Raises a key-parse failure naming the key path; realistic swapped-paths misconfiguration, distinct from TC-27-16's pure-garbage case |
| TC-27-19 | Valid cert+key, `ssl_client_key: MtlsFixtures.empty_file(GEB.dir)` (zero-byte file, overriding key path to empty file) | `build_client(ssl: ...)` | Raises a key-parse failure naming the path; zero-byte files must not be silently treated as "no key" |

---

## 3. Passphrase handling (5 cases)

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-27-20 | `ssl_client_cert: GEB.cert_path`, `ssl_client_key: GEB.encrypted_key_path`, `ssl_client_key_passphrase: GEB.passphrase` | `build_client(ssl: ...)` then a stubbed call | Construction succeeds; decrypted key's `to_der` matches `GEB.key_object`; request carries the decrypted key |
| TC-27-21 | `ssl_client_cert: GEB.cert_path`, `ssl_client_key: GEB.encrypted_key_path`, no `ssl_client_key_passphrase` | `build_client(ssl: ...)` | Raises a specific "key is encrypted, passphrase required" message — distinct from the generic parse-failure message in TC-27-16, not a bare `OpenSSL::PKey::PKeyError` leak |
| TC-27-22 | Same, `ssl_client_key_passphrase: "definitely-wrong"` | `build_client(ssl: ...)` | Raises; message does not include the attempted passphrase or any key bytes |
| TC-27-23 | `ssl_client_cert: GEB.cert_path`, `ssl_client_key: GEB.key_path` (unencrypted), `ssl_client_key_passphrase: "harmless"` | `build_client(ssl: ...)` | Construction succeeds — a passphrase supplied alongside an unencrypted key is not an error |
| TC-27-24 | Same as TC-27-21 but `ssl_client_key_passphrase: ""` (empty string, not absent) | `build_client(ssl: ...)` | Raises the same "passphrase required" message as TC-27-21 — an explicit empty string is treated as "no passphrase provided," not as a (wrong) non-empty attempt. See Decisions & Rationale #4. |

---

## 4. Wrong-type / malformed config values (10 cases)

Each case asserts the error is a clear, early, named-field type/path error — never a raw
`NoMethodError`/`TypeError` bubbling up from `File.read` or `OpenSSL::PKey.read` receiving the
wrong Ruby type, and never a path to `RestClient::Request.execute` with an unvalidated value.

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-27-30 | `ssl_client_cert: 42` (Integer), valid key | `build_client(ssl: ...)` | Raises with a message naming `ssl_client_cert` and stating it must be a String path (not "got Integer" leaking into a file-not-found style message) |
| TC-27-31 | `ssl_client_cert: nil` explicitly, `ssl_client_key: GEB.key_path` set | `build_client(ssl: ...)` | Treated identically to "cert absent, key present" (TC-27-11) — explicit `nil` is not distinguished from an absent key in the config hash |
| TC-27-32 | `ssl_client_key: :a_symbol`, valid cert | `build_client(ssl: ...)` | Raises a type error naming `ssl_client_key`, must be a String path |
| TC-27-33 | `ssl_client_cert: GEB.cert_object` (an already-loaded `OpenSSL::X509::Certificate`, not a path), valid key | `build_client(ssl: ...)` | Raises a type error — the agreed design takes **paths only**; pre-loaded objects are out of scope and rejected, not silently accepted |
| TC-27-34 | `ssl_client_key: ""` (empty string), valid cert | `build_client(ssl: ...)` | Raises a file-not-found/invalid-path style error for the empty path — an empty string is truthy in Ruby, so it must not be mistaken for "not configured" by a naive `if config[:ssl_client_key]` check |
| TC-27-35 | `ssl_ca_file: GEB.dir` (a directory), valid cert+key | `build_client(ssl: ...)` | Raises a clear "not a file" error naming the directory path, instead of passing the directory straight through to `RestClient`/`Net::HTTP` and surfacing a confusing low-level I/O error |
| TC-27-36 | `ssl_client_cert: GEB.dir` (a directory) | `build_client(ssl: ...)` | Raises the same class of "not a file" error for the cert path |
| TC-27-37 | `ssl_client_key: GEB.dir` (a directory) | `build_client(ssl: ...)` | Raises the same class of "not a file" error for the key path |
| TC-27-38 | `ssl_client_key_passphrase: 12345` (Integer) against `GEB.encrypted_key_path` | `build_client(ssl: ...)` | Raises a type error naming `ssl_client_key_passphrase` — an accidentally-numeric YAML passphrase is not silently coerced via `to_s` |
| TC-27-39 | `ssl_client_cert: true` (Boolean) | `build_client(ssl: ...)` | Raises a type error naming `ssl_client_cert`, not a `NoMethodError` from calling `File.read(true)` |

---

## 5. Retry path (4 cases)

Exercises `_rest_call`'s existing `response.code == 502` retry loop (`sleep 30; retry`, up to 3
attempts). Tests stub `sleep` to a no-op to keep runtime bounded, and spy on both
`RestClient::Request.execute` and `File.read` (or whatever primitive loads the fixture files).

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-27-40 | `build_client(ssl: {ssl_client_cert: GEB.cert_path, ssl_client_key: GEB.key_path})`. Stub execute to return 502 twice then 200. | `client.get_venues` | `RestClient::Request.execute` is called 3 times; the `ssl_client_cert`/`ssl_client_key` object passed is the **same `object_id`** on all 3 calls |
| TC-27-41 | Same setup/spy as TC-27-40, plus a call-count spy on the file-loading primitive used for cert/key | `client.get_venues` (502, 502, 200) | The file-loading primitive is invoked **exactly once per configured file** across construction *and* all 3 retries combined — files are not re-read on retry |
| TC-27-42 | `build_client` with **no** `ssl:` kwarg. Stub execute to return 502 once then 200 (regression guard, pre-existing behaviour). | `client.get_venues` | Retries and succeeds exactly as before this feature; unaffected by the ssl code path being present-but-unused |
| TC-27-43 | Same as TC-27-40 | `client.get_venues` | The final (3rd) call's 200 response is correctly parsed and returned — ssl options on earlier failed attempts don't corrupt state used by the eventually-successful attempt |

---

## 6. `$DEBUG` / logging safety (4 cases)

Each case captures `$stdout` (e.g. via `StringIO` + `$stdout =`) for the duration of the call and
greps the captured text. Because `OpenSSL::PKey` objects' default `#inspect` does not reliably
dump raw key material on every OpenSSL version, the strongest, version-independent check is a
unique textual needle: a fragment of the fixture key's own PEM body (e.g. a 40-character slice
from the middle of `GEB.key_object.to_pem`) must never appear in captured output, in addition to
checking for PEM header markers and the literal passphrase string.

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-27-45 | `$DEBUG = true`. `build_client(ssl: {cert, key, ca})`. Stub execute to succeed (200). Capture `$stdout`. | `client.get_venues` | Captured output contains none of: `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY`, the raw PEM-body needle, or the passphrase string. (Public cert subject lines are **not** restricted — only the private key and passphrase are secret per design.) |
| TC-27-46 | `$DEBUG = true`. `build_client(ssl: {ssl_client_cert: GEB.cert_path, ssl_client_key: GEB.mismatched_key_path})` (construction-time mismatch failure). Capture `$stdout` and the raised exception's `message`/`inspect`. | Attempt construction, rescue | Neither captured stdout nor the exception's message/inspect contains the PEM-body needle, passphrase, or key header markers — debug tracing during a failure path still leaks nothing |
| TC-27-47 | `$DEBUG = true`, `$VERBOSE = true`. `build_client(ssl: {cert, key})`. Capture `$stdout`. | `client.get_venues` | No key material leaks (same checks as TC-27-45) **and** the existing `Access-Key: %s` / `Signature: %s` debug lines from `auth_cryptomnio` still appear unchanged — the new code doesn't suppress or alter pre-existing HMAC debug output |
| TC-27-48 | `$DEBUG = true`. Same as TC-27-45. | `client.get_venues` | Captured output never contains the loaded key object's default `#inspect` class/ivar dump pattern (`#<OpenSSL::PKey::RSA`) — guards against an accidental `p @ssl_client_key` / `pp` anywhere in the request path |

---

## 7. HMAC headers unchanged alongside cert (3 cases)

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-27-50 | `build_client`, no `ssl:`. Stub execute to capture `headers:`. | `client.get_venues` | Record `Access-Key`/`Sign` header values (call this baseline `H0`) |
| TC-27-51 | `build_client(ssl: {ssl_client_cert: GEB.cert_path, ssl_client_key: GEB.key_path, ssl_ca_file: GEB.ca_cert_path})`, same `STUB_CONFIG` secret/access keys and same call | `client.get_venues` | Captured `Access-Key`/`Sign` header values are byte-identical to `H0` — mTLS config has zero effect on HMAC computation |
| TC-27-52 | Same as TC-27-51 | `client.get_venues` | Captured `headers:` hash has exactly the same key set as the no-ssl case (`Access-Key`, `Sign`, plus `Content-type` only if a body is sent) — no `ssl_*` key ever leaks into the `headers:` hash instead of being passed as its own `RestClient::Request.execute` option |

---

## 8. Instance isolation — GEB vs NUT (4 cases)

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-27-55 | `client_geb = build_client(ssl: {cert: GEB.cert_path, key: GEB.key_path, ca: GEB.ca_cert_path})`; `client_nut = build_client(ssl: {cert: NUT.cert_path, key: NUT.key_path, ca: NUT.ca_cert_path})` | Construct both | Both succeed independently in the same process |
| TC-27-56 | Same two clients, each with execute stubbed/spied separately | `client_geb.get_venues`; `client_nut.get_venues` | `client_geb`'s captured `ssl_client_cert`/`key` `object_id`s differ from `client_nut`'s; each matches only its own fixture (`to_der` equality against `GEB.*`/`NUT.*` respectively) |
| TC-27-57 | Same two clients | Call order: `client_geb.get_venues`, `client_nut.get_venues`, `client_geb.get_venues` again | The second `client_geb` call still carries GEB's original cert/key object — unaffected by the intervening NUT call |
| TC-27-58 | `client_geb` as above; `client_plain = build_client` (no `ssl:`), constructed **after** `client_geb` | `client_plain.get_venues` | `client_plain`'s captured kwargs contain no `ssl_client_cert`/`ssl_client_key`/`ssl_ca_file` at all — guards against any accidental class/module-level ssl state (the codebase already has one such module-level gotcha: `RestClient.proxy = ENV['http_proxy']` in `Cryptomnio::REST#initialize`) |

---

## 9. Config→runtime seam — `automated-strategies` (2 cases)

`automated-strategies` (read-only reference, not modified by this change) builds its client in
`class_automated_strategy.rb`'s `connect_cryptomnio` (as of the commit inspected for SE#1491):

```ruby
cryptomnio = Cryptomnio::REST::Client.new do |c|
  c.config = {
    api_host_core: @config[:cryptomnio][:api_host_core],
    api_host_cma:  @config[:cryptomnio][:api_host_cma],
    authtype:   @config[:cryptomnio][:authtype],
    access_key: @config[:cryptomnio][:access_key],
    secret_key: @config[:cryptomnio][:secret_key],
    contexts: []
  }
  c.config[:contexts] = {
    exchange: {
      venue:      @config[:cryptomnio][:exchange],
      accountid:  @config[:cryptomnio][:accountid],
      venuekeyid: @config[:cryptomnio][:venuekeyid]
    }
  }
end
```

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-27-60 | Build a client using the exact hash shape above (two-phase `c.config = {...}` then `c.config[:contexts] = {...}`, `exchange:` context label, not `default:`), with `ssl_client_cert`/`ssl_client_key`/`ssl_ca_file` merged into the first hash exactly as a future `connect_cryptomnio` update would add them from `@config[:cryptomnio][:ssl_*]` | Construct, then a stubbed call | Client constructs and forwards the ssl objects correctly through this exact nested/two-phase shape — confirms the gem's contract matches what the real consumer builds, not an idealized hand-built hash |
| TC-27-61 | **Regression-watch, read-only, environment-conditional — not hardcoded skip.** At test time, check whether a sibling `automated-strategies` checkout is present (e.g. `File.exist?(AUTOMATED_STRATEGIES_PATH)`, path from an env var with a sensible local default). **If absent** (e.g. GitHub CI, or any fresh clone of `ruby-cryptomnio` alone): `skip` with an explicit message — `"automated-strategies checkout not found at <path>; this regression watch only runs where that sibling repo is checked out. See automated-strategies issue TBD for the ssl_* forwarding gap this test watches for."` **If present:** `File.read` the live `class_automated_strategy.rb` (no `require`, no execution) and regex-extract every `@config[:cryptomnio][:xxx]` key referenced inside the `connect_cryptomnio` method body | Compare extracted key set to the **full expected set including the four new `ssl_*` keys** | When the sibling checkout is present, this assertion is **expected to FAIL today** (as of SE#1491 / commit `a4976b2`): the extracted set is currently only `{api_host_core, api_host_cma, authtype, access_key, secret_key, exchange, accountid, venuekeyid}` — none of `ssl_client_cert`, `ssl_client_key`, `ssl_client_key_passphrase`, `ssl_ca_file` are forwarded yet. The failure message states this explicitly and points at **automated-strategies issue TBD** (NOVA/Project Leadership to file) rather than suggesting the fix belongs in this test. The test must not be silenced by weakening the assertion — fixing it means updating `connect_cryptomnio` in `automated-strategies`, not this gem. |

---

## 10. Intent-level integration against beta — MANUAL / STAGING ONLY (3 cases)

**Not part of the automated suite.** These require NOVA's real beta client certificate, which
lives under `~/.secrets` and is never read, copied, or referenced by this test design or by any
automated test in `test/test_issue_27.rb`. They must be run manually by an operator with access
to that cert, directly against `api.bhco.co.beta.cryptomnio.com`, once the implementation exists.
No orders are placed; only read-only/auth-probing endpoints are used.

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-27-70 | Real beta cert/key configured via `:ssl_client_cert`/`:ssl_client_key`; **intentionally wrong** `:secret_key` (bad HMAC) | Call `get_venues` against `api.bhco.co.beta.cryptomnio.com` | TLS handshake succeeds (mTLS accepted at the transport layer); server responds **401** at the application layer — proves the cert and HMAC are independent layers, exactly per the design ("mTLS is an additional layer, not a replacement") |
| TC-27-71 | Real beta cert/key configured; **real, valid** access/secret key pair | Call `get_venues` (read-only) | TLS handshake succeeds; a real **200** response with actual venue data is returned |
| TC-27-72 | `:ssl_client_cert`/`:ssl_client_key` **omitted entirely** against the same beta host (which, per the issue, already enforces mTLS) | Call `get_venues` | Connection is refused / TLS handshake fails before any HTTP response is received — confirms "without the cert" is genuinely blocked at the transport layer today, not a hypothetical |

---

## Decisions & Rationale

1. **PKCS#8, not OpenSSH, is the key format under test.** Step 2's report concluded the delivered
   keys were OpenSSH-format based on `file(1)`'s label and could not be loaded by
   `OpenSSL::PKey.read`. That conclusion is corrected by direct verification (per this run's
   brief): `file(1)` mislabels these PEM PKCS#8 keys, and `OpenSSL::PKey.read` loads all three
   real keys fine. No fixture or test case here exercises OpenSSH-format key handling or
   conversion — that would test a problem that doesn't exist and would misdirect the
   implementation toward unnecessary `ssh-keygen`-shelling complexity.

2. **Config keys accept paths only, not pre-loaded OpenSSL objects (TC-27-33).** The original
   issue text floated accepting either a path or an object; the issue's own final/agreed-design
   comment narrows this to `:ssl_client_cert` (path) / `:ssl_client_key` (path) only. Testing that
   an object is *rejected* (not silently accepted) locks in the narrower, agreed scope and
   prevents an implementer from quietly reintroducing the wider surface, which would also make
   "never read file paths twice on retry" harder to reason about (an object has no path to even
   compare against for caching).

3. **CA-only config (`ssl_ca_file` set, cert/key absent) is accepted, not rejected (TC-27-5,
   TC-27-6).** Reasoning: (a) the agreed design text itself singles out `ssl_ca_file` as the one
   key that "remains optional" independent of the cert/key pairing rule — the all-or-nothing rule
   is stated only for cert+key, never extended to include the CA file; (b) `ssl_ca_file` and the
   client-cert pair serve two independent purposes — CA file verifies *the server's* chain,
   cert+key authenticate *this client* to the server — so there is no cryptographic or protocol
   reason one must imply the other; rest-client/`Net::HTTP` itself accepts `ca_file` with no
   `cert`/`key` set without error. (c) It's also the realistic shape for a transitional rollout:
   a strategy operator may want to pin/verify Blockhenge's private CA chain before client certs
   are issued to every account, without that being treated as a misconfiguration. Rejecting
   CA-only would force operators to either skip CA verification entirely or fabricate a cert/key
   pair they don't have yet, both worse outcomes. If GEB/NUT's rollout plan changes such that a
   client cert becomes mandatory whenever a private CA is configured, that would be a design
   change requiring its own issue, not an assumption baked into this test design.

4. **Empty-string passphrase and empty-string key path are tested as real values, not "absent"
   (TC-27-24, TC-27-34).** Ruby's `if value` treats `""` as truthy, so a naive implementation might
   pass validation checks gated on simple truthiness and then fail confusingly deep inside
   `File.read` or `OpenSSL::PKey.read`. These cases force the implementation to check emptiness
   explicitly and fail with a clear, named-field message instead.

5. **Directory-instead-of-file is tested for all three path options (cert, key, CA — TC-27-14/35/36/37 area)**
   rather than just one, because the three options are validated through separate code paths
   (cert and key go through OpenSSL parsing, CA file is just handed to rest-client as a string) and
   each has an independent chance to leak a confusing low-level `Errno::EISDIR` instead of a
   clear, path-naming error.

6. **The retry-path tests assert on `object_id`, not just value equality (TC-27-40/41).** Value
   equality alone (`==`) would pass even if the implementation re-read and re-parsed the files on
   every retry attempt, which is both wasteful and reintroduces a window where an intermittent
   filesystem hiccup during a retry could turn a transient 502 into a hard failure. Checking
   identity is a stronger guarantee of "loaded once."

7. **`$DEBUG` safety checks use a unique PEM-body text needle, not just header markers
   (TC-27-45–48).** OpenSSL's default `#inspect` output for key objects is not guaranteed to dump
   raw key bytes on every OpenSSL/Ruby version, so asserting "no `#<OpenSSL::PKey::RSA` string
   appears" alone would not catch a version where `#inspect` is more verbose or less verbose than
   expected. A literal substring of the fixture's actual private key PEM is a version-independent
   tripwire.

8. **Public certificate content is explicitly *not* restricted under `$DEBUG` (decision in case
   TC-27-45).** The design says "never log or inspect key objects" — certificates are public by
   nature (they're sent to the server in the clear during the TLS handshake), so restricting debug
   output to omit cert subject/serial would be stricter than the design requires and would make
   debugging mTLS connection problems harder for no security benefit. Only the private key object
   and the passphrase are treated as sensitive.

9. **Chain files are defined to use the leaf block only, with no per-block parsing on our side
   (TC-27-7).** For `ssl_client_cert`: `OpenSSL::X509::Certificate.new` parses only the first PEM
   block it encounters in a multi-block file, so a concatenated leaf+intermediate cert file
   naturally yields the leaf — this is existing Ruby/OpenSSL behaviour, not new code, and the test
   pins it so nobody "fixes" it into unexpectedly building a chain array. For `ssl_ca_file`: this
   value is a bare path string handed to `RestClient`/`Net::HTTP`, which in turn hands it to
   OpenSSL's `SSL_CTX_load_verify_locations` — that call natively loads *every* PEM block in the
   file for the trust store, so a root+intermediate CA bundle in one file is the normal, correct
   way to supply a CA chain and requires zero special handling in this gem.

10. **An expired client cert is not rejected locally at construction (TC-27-8).** `check_private_key`
    only verifies that the public/private key pair match; it does not check `not_before`/`not_after`.
    Per the agreed design, construction-time validation is scoped to readability, parseability, and
    cert/key match — nothing in the design calls for a local expiry check, and the server is the
    correct authority on cert validity during the TLS handshake (consistent with TC-27-70/71/72,
    where the server, not the gem, is what accepts or refuses a presented cert). This case exists
    specifically to prevent an implementer from adding an unrequested, surprise
    `cert.not_after < Time.now` guard that would make an about-to-expire cert fail differently
    (and more confusingly, since it bypasses the server's own error) than letting the server decide.

11. **The `automated-strategies` seam is tested two ways, not one (section 9), because a single
    hand-built config hash cannot by itself satisfy "metadata actually populated by production
    code" (lesson 811).** TC-27-60 is a faithful, path-commented transcription of the actual
    `connect_cryptomnio` hash-building code (including its unusual two-phase `c.config = {...}`
    then `c.config[:contexts] = {...}` construction and the `exchange:` context label) rather than
    an idealized minimal hash, so it exercises the real shape the gem must accept. TC-27-61 is a
    live, read-only, **environment-conditional** regression-watch over the actual
    `automated-strategies` source text that keeps TC-27-60's transcription honest. It is not a
    hardcoded `skip` — it only skips (with an explicit reason) when the sibling checkout genuinely
    isn't available, such as in `ruby-cryptomnio`'s own GitHub CI, which has no reason to clone a
    separate private repo. When the checkout *is* available (e.g. in the shared SE workspace used
    for this run), it runs for real, and today it legitimately **fails**, because
    `automated-strategies` does not yet forward any `ssl_*` keys. That failure is reported
    explicitly rather than hidden behind a skip, and the test message points at
    **automated-strategies issue TBD** — fixing it is a follow-up in the `automated-strategies`
    repo once GEB/NUT mTLS is live, not a reason to weaken this test.

12. **No automated test exercises a live Cryptomnio host.** All of section 10 is marked
    manual/staging per the task brief, since it requires the real beta cert under `~/.secrets`
    (never touched here) and would otherwise make a real signed network call. These are documented
    as explicit manual steps for an operator rather than silently skipped or omitted, so Step 4
    (staging validation) has a ready-made script instead of having to invent one from scratch —
    the same failure mode SE#804/SE#633 hit when a test design existed only in prose.

13. **Excluded:** PKCS#12 (`.p12`/`.pfx`) cert bundles. The issue's open questions mention PKCS#12
    as a possible delivery format, but the final agreed-design comment settles on separate PEM
    cert and key files, which is what was actually delivered for GEB/NUT/beta. No PKCS#12 test
    case is included; if that format is later adopted, it needs its own design pass.

14. **Excluded:** testing `ssl_client_cert`/`ssl_client_key` via a *relative* path vs. absolute
    path distinction. The design doesn't call out relative-path handling as a requirement, and
    Ruby's `File.read`/`OpenSSL::X509::Certificate.new` handle both identically relative to the
    process's current working directory; adding cases here would test Ruby's own stdlib, not this
    feature.

---

## Totals

- **53 test cases** across 10 coverage areas (sections 1–10 above), matching the 53 `TC-27-*`
  table rows in this file exactly (every ID referenced in Decisions & Rationale has a
  corresponding row; no row is unreferenced-but-orphaned).
- **50 automated** (sections 1–9). Of these, 49 are expected to pass once implemented; TC-27-61 is
  environment-conditional — it `skip`s with an explicit reason when no sibling
  `automated-strategies` checkout is present (e.g. GitHub CI), and otherwise runs for real and is
  expected to **fail today** against the known `ssl_*`-forwarding gap in that repo (tracked as
  automated-strategies issue TBD).
- **3 manual/staging** (section 10), explicitly out of the automated `rake test` run.

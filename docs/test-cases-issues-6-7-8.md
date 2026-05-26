# Test Cases — Issues #6, #7, #8
## Branch: `fix/issues-5-6-7-8-code-cleanup`

**Designed by:** Gem (QA Lead)
**Date:** 2026-05-25
**Issues covered:** #6 (malformed query strings), #7 (missing `require 'openssl'`), #8 (missing gemspec dependency)
**Issue excluded:** #5 (`$balance` global — deferred pending trading bot review)

---

## Scope

These test cases validate three bug fixes in `lib/cryptomnio.rb` and `cryptomnio.gemspec`.
All tests are self-contained unit or structural tests; they do NOT require a live Cryptomnio API connection.

### Entry Criteria
- Branch `fix/issues-5-6-7-8-code-cleanup` checked out
- Ruby >= 3.3 available
- `gem install minitest rest-client` (or `bundle install` if Gemfile present)
- No live API credentials required

### Exit Criteria
- All test cases pass
- No test produces a URL containing `?&` or `=&` in query string output
- `lib/cryptomnio.rb` explicitly requires `openssl`
- `cryptomnio.gemspec` declares `rest-client` as a runtime dependency
- No S1/S2 defects open

---

## Issue #6 — Malformed Query Strings (Leading `&`)

**Bug summary:** Four methods initialize `uriparams = ""` then append each optional parameter with a leading `&` (e.g., `"&side=buy"`). When the first parameter is the only one present, this produces a malformed query string like `?&side=buy` instead of `?side=buy`.

**Affected methods:**
- `get_market_orderbook`
- `get_market_orderbook_depth_price`
- `get_market_orderbook_depth_volume`
- `get_market_trades`

**Fix approach:** Replace string-accumulation with array-join pattern:
```ruby
parts = []
parts << "key=val" % val if val
uriparams = parts.empty? ? nil : parts.join("&")
```

**Test approach:** Extract the query-string-building logic into a helper or test via method inspection.
Since `_rest_call` accepts `uriparameters` directly, tests stub out `_rest_call` and capture the `uriparameters` argument passed to it.

**Assertion helper (shared):** For any captured `uriparams` value:
- If not nil: must NOT start with `&`
- If not nil: must NOT contain `=&` or `&&`
- Must not produce a URI containing `?&`

---

### TC-6-OB: `get_market_orderbook` — Query String Construction

**Preconditions:** Client object instantiated with a stub config (no real API calls). `_rest_call` stubbed to capture `uriparameters` argument.

| ID | side | limit | Expected uriparams | Pass Criteria |
|---|---|---|---|---|
| TC-6-OB-1 | `nil` | `nil` | `nil` | uriparams is nil; no query string appended |
| TC-6-OB-2 | `"buy"` | `nil` | `"side=buy"` | No leading `&`; value is `"side=buy"` exactly |
| TC-6-OB-3 | `nil` | `10` | `"limit=10"` | No leading `&`; value is `"limit=10"` exactly |
| TC-6-OB-4 | `"buy"` | `10` | `"side=buy&limit=10"` | Both params joined by `&`; no leading `&` |
| TC-6-OB-5 | `"sell"` | `1` | `"side=sell&limit=1"` | BVA: limit=1 (minimum meaningful value) |
| TC-6-OB-6 | `"sell"` | `nil` | `"side=sell"` | Side-only for sell direction |

**Negative / regression guard:**

| ID | Description | Must NOT produce |
|---|---|---|
| TC-6-OB-NEG-1 | Single param (side only) | `"&side=buy"` (old bug) |
| TC-6-OB-NEG-2 | Single param (limit only) | `"&limit=10"` (old bug) |
| TC-6-OB-NEG-3 | No params | `""` empty string (should be nil, not empty string) |

---

### TC-6-OBP: `get_market_orderbook_depth_price` — Query String Construction

**Preconditions:** Same as TC-6-OB. Optional params: `side`, `volume`, `cumulative`.
Note: `cumulative` uses `!cumulative.nil?` guard — `false` is a valid value that must appear in output.

| ID | side | volume | cumulative | Expected uriparams |
|---|---|---|---|---|
| TC-6-OBP-1 | `nil` | `nil` | `nil` | `nil` |
| TC-6-OBP-2 | `"buy"` | `nil` | `nil` | `"side=buy"` |
| TC-6-OBP-3 | `nil` | `100.5` | `nil` | `"volume=100.500000"` |
| TC-6-OBP-4 | `nil` | `nil` | `true` | `"cumulative=true"` |
| TC-6-OBP-5 | `nil` | `nil` | `false` | `"cumulative=false"` (false is NOT nil; must be included) |
| TC-6-OBP-6 | `"buy"` | `100.5` | `nil` | `"side=buy&volume=100.500000"` |
| TC-6-OBP-7 | `"buy"` | `nil` | `true` | `"side=buy&cumulative=true"` |
| TC-6-OBP-8 | `nil` | `100.5` | `true` | `"volume=100.500000&cumulative=true"` |
| TC-6-OBP-9 | `"buy"` | `100.5` | `true` | `"side=buy&volume=100.500000&cumulative=true"` |
| TC-6-OBP-10 | `"sell"` | `0.0` | `false` | `"side=sell&volume=0.000000&cumulative=false"` (BVA: volume=0) |

**Edge case — cumulative=false:**
TC-6-OBP-5 is the critical edge case: `cumulative=false` must still appear in the query string because `false != nil`. The old code `uriparams << "&cumulative=false"` would produce a leading `&` bug AND the fix must preserve the `!nil?` semantics.

---

### TC-6-OBV: `get_market_orderbook_depth_volume` — Query String Construction

**Preconditions:** Same as TC-6-OB. Optional params: `side`, `price`, `cumulative`.

| ID | side | price | cumulative | Expected uriparams |
|---|---|---|---|---|
| TC-6-OBV-1 | `nil` | `nil` | `nil` | `nil` |
| TC-6-OBV-2 | `"buy"` | `nil` | `nil` | `"side=buy"` |
| TC-6-OBV-3 | `nil` | `50000.0` | `nil` | `"price=50000.000000"` |
| TC-6-OBV-4 | `nil` | `nil` | `true` | `"cumulative=true"` |
| TC-6-OBV-5 | `nil` | `nil` | `false` | `"cumulative=false"` |
| TC-6-OBV-6 | `"buy"` | `50000.0` | `nil` | `"side=buy&price=50000.000000"` |
| TC-6-OBV-7 | `"buy"` | `nil` | `true` | `"side=buy&cumulative=true"` |
| TC-6-OBV-8 | `nil` | `50000.0` | `true` | `"price=50000.000000&cumulative=true"` |
| TC-6-OBV-9 | `"buy"` | `50000.0` | `true` | `"side=buy&price=50000.000000&cumulative=true"` |
| TC-6-OBV-10 | `nil` | `0.01` | `false` | `"price=0.010000&cumulative=false"` (BVA: small price) |

---

### TC-6-TR: `get_market_trades` — Query String Construction

**Preconditions:** Same as TC-6-OB. Optional param: `limit`.
Note: Old code: `uriparams = "&limit=%s" % limit if limit` — always starts with `&`.

| ID | limit | Expected uriparams | Notes |
|---|---|---|---|
| TC-6-TR-1 | `nil` | `nil` | No limit → nil, no query string |
| TC-6-TR-2 | `10` | `"limit=10"` | No leading `&` |
| TC-6-TR-3 | `1` | `"limit=1"` | BVA: minimum meaningful limit |
| TC-6-TR-4 | `100` | `"limit=100"` | Typical larger value |
| TC-6-TR-5 | `0` | `"limit=0"` | BVA: limit=0 is truthy in Ruby; fix preserves existing behavior by passing it through. If the API rejects limit=0, that's a separate issue. |

**Note on TC-6-TR-5:** Ruby `0` is truthy, so `if limit` with `limit=0` includes it in the query string. The fix preserves this behavior — `limit=0` produces `"limit=0"`. If the API rejects `limit=0`, that's a separate issue to address independently.

**Negative regression guard:**

| ID | Description | Must NOT produce |
|---|---|---|
| TC-6-TR-NEG-1 | limit=10 provided | `"&limit=10"` (old bug) |
| TC-6-TR-NEG-2 | No limit | `""` empty string (must be nil) |

---

## Issue #7 — Missing `require 'openssl'`

**Bug summary:** `lib/cryptomnio.rb` calls `OpenSSL::HMAC.digest` in `auth_cryptomnio` but never explicitly requires `openssl`. The constant is only available because `rest-client` loads it transitively. This is an implicit dependency — fragile and incorrect.

**Fix:** Add `require "openssl"` at the top of `lib/cryptomnio.rb`, alongside existing requires.

---

### TC-7-STATIC: Static File Verification

| ID | Check | Method | Pass Criteria |
|---|---|---|---|
| TC-7-S-1 | File contains explicit openssl require | `grep -n 'require.*openssl' lib/cryptomnio.rb` | Exactly one match, not commented out |
| TC-7-S-2 | Require appears in the top-level requires block | Manual inspection of lines 1-10 | `require "openssl"` (or `require 'openssl'`) present before first class definition |
| TC-7-S-3 | No other file in lib/ depends on transitive openssl | `grep -rn 'OpenSSL' lib/` | All usages in files that also have explicit require |

---

### TC-7-FUNCTIONAL: OpenSSL::HMAC Accessibility (Isolated Load)

These tests verify that `OpenSSL::HMAC` is accessible from the gem's own explicit `require 'openssl'`, not through rest-client's transitive load.

**Why isolation matters:** `lib/cryptomnio.rb` has `require 'rest-client'` at the top, and rest-client transitively loads openssl. Without stubbing that out, loading cryptomnio always brings in openssl regardless of whether `require 'openssl'` is present — making the functional tests meaningless for issue #7.

**Test setup — subprocess with stubbed require:**
```ruby
# Spawn a subprocess that intercepts require 'rest-client' before loading cryptomnio,
# preventing the transitive openssl load. If OpenSSL::HMAC is still available,
# the explicit require 'openssl' in cryptomnio.rb is doing the work.
result = system(<<~CMD)
  ruby -e "
    # Stub out rest-client before loading the gem
    module Kernel
      alias_method :original_require, :require
      def require(path)
        return true if path == 'rest-client'
        original_require(path)
      end
    end
    require_relative 'lib/cryptomnio'
    # If we reach here without NameError, explicit require 'openssl' is present and working
    OpenSSL::HMAC.digest('sha512', 'key', 'data')
    puts 'PASS'
  "
CMD
assert result, 'subprocess exited non-zero — openssl not explicitly required'
```

| ID | Test | Expected Result | Failure Mode |
|---|---|---|---|
| TC-7-F-1 | Load cryptomnio in subprocess with `require 'rest-client'` stubbed out | Subprocess exits 0; no `NameError: uninitialized constant OpenSSL` | Raises NameError — explicit `require 'openssl'` missing |
| TC-7-F-2 | `OpenSSL::HMAC.digest('sha512', 'key', 'data')` callable after stubbed load | Returns a binary string of length 64 bytes | Raises NameError or NoMethodError |
| TC-7-F-3 | HMAC output is deterministic | Same inputs always produce same output | Flapping output |
| TC-7-F-4 | HMAC output for known inputs matches reference | `OpenSSL::HMAC.digest('sha512', 'secret', 'GET/venues')` == expected hex | Value mismatch indicates wrong algorithm |

**TC-7-F-4 reference value** (computed independently):
```
key = 'secret'
data = 'GET/venues'
algorithm = 'sha512'
# Expected HMAC-SHA512 (hex): verify with: echo -n 'GET/venues' | openssl dgst -sha512 -hmac 'secret'
```
Execute `echo -n 'GET/venues' | openssl dgst -sha512 -hmac 'secret'` in shell during test run to obtain the reference value, then assert Ruby output matches.

---

### TC-7-INTEGRATION: auth_cryptomnio Method

These verify the method using the explicit require works end-to-end without a live API.

**Preconditions:** Client instantiated with stub config containing valid `access_key` and `secret_key` strings.

| ID | Test | Expected |
|---|---|---|
| TC-7-I-1 | `auth_cryptomnio(:get, "/venues")` returns non-nil string | Returns Base64-encoded string |
| TC-7-I-2 | Return value contains no newlines (`.split.join` is effective) | `result.include?("\n") == false` |
| TC-7-I-3 | Return value is valid Base64 | `Base64.decode64(result)` succeeds without exception |
| TC-7-I-4 | Different method+path inputs produce different signatures | `auth_cryptomnio(:get, "/venues") != auth_cryptomnio(:post, "/venues")` |

---

## Issue #8 — Missing `rest-client` in Gemspec

**Bug summary:** `cryptomnio.gemspec` has all `add_runtime_dependency` and `add_development_dependency` lines commented out. Consumers who install the gem without prior knowledge of its dependencies will get a `LoadError` when `cryptomnio` tries to `require 'rest-client'`.

**Fix:** Uncomment (or add) `s.add_runtime_dependency "rest-client", "~> 2.1"`.

---

### TC-8-STATIC: Gemspec File Verification

| ID | Check | Method | Pass Criteria |
|---|---|---|---|
| TC-8-S-1 | `add_runtime_dependency` present and uncommented | `grep -n 'add_runtime_dependency' cryptomnio.gemspec` | At least one match with no leading `#` |
| TC-8-S-2 | Dependency name is `rest-client` | Content check | `"rest-client"` in the line |
| TC-8-S-3 | Version constraint present | Content check | `"~> 2.1"` in the line |
| TC-8-S-4 | No commented-out dependency lines remain for `rest-client` | `grep '# .*add_runtime_dependency.*rest-client' cryptomnio.gemspec` | Zero matches |

---

### TC-8-LOAD: Gemspec Loads Without Errors

| ID | Test | Expected |
|---|---|---|
| TC-8-L-1 | `ruby cryptomnio.gemspec` (or `Gem::Specification.load("cryptomnio.gemspec")`) | Exits 0, no exceptions |
| TC-8-L-2 | Loaded spec has `name == "cryptomnio"` | `spec.name` equals `"cryptomnio"` |
| TC-8-L-3 | `spec.runtime_dependencies` is not empty | Array has at least one entry |
| TC-8-L-4 | `rest-client` in runtime dependency names | `spec.runtime_dependencies.map(&:name).include?("rest-client")` |

---

### TC-8-VERSION: Dependency Version Constraint Verification

**Purpose:** Verify the `~> 2.1` pessimistic constraint admits correct versions and rejects incompatible ones.

| ID | Version | Constraint `"~> 2.1"` | Expected |
|---|---|---|---|
| TC-8-V-1 | `"2.1.0"` | `~> 2.1` | Satisfied (exact lower bound) |
| TC-8-V-2 | `"2.1.4"` | `~> 2.1` | Satisfied (patch within 2.x) |
| TC-8-V-3 | `"2.9.0"` | `~> 2.1` | Satisfied (higher minor, same major) |
| TC-8-V-4 | `"2.0.9"` | `~> 2.1` | NOT satisfied (below lower bound) |
| TC-8-V-5 | `"3.0.0"` | `~> 2.1` | NOT satisfied (major version bump) |
| TC-8-V-6 | `"1.9.9"` | `~> 2.1` | NOT satisfied (below major) |

**Ruby verification snippet:**
```ruby
require 'rubygems'
dep = Gem::Dependency.new("rest-client", "~> 2.1")
# Should be true:
dep.match?("rest-client", "2.1.0")   # TC-8-V-1
dep.match?("rest-client", "2.9.0")   # TC-8-V-3
# Should be false:
dep.match?("rest-client", "3.0.0")   # TC-8-V-5
```

---

## Cross-Cutting: URL Assembly Regression Suite

These tests verify that the full URI assembly in `_rest_call` does not produce malformed URLs, covering all four fixed methods end-to-end (with HTTP mocked).

| ID | Method Call | Expected URI fragment | Must NOT contain |
|---|---|---|---|
| TC-X-1 | `get_market_orderbook(market: "BTC-USD")` | No query string | `?&` |
| TC-X-2 | `get_market_orderbook(market: "BTC-USD", side: "buy")` | `?side=buy` | `?&` |
| TC-X-3 | `get_market_orderbook(market: "BTC-USD", limit: 5)` | `?limit=5` | `?&` |
| TC-X-4 | `get_market_orderbook(market: "BTC-USD", side: "buy", limit: 5)` | `?side=buy&limit=5` | `?&` |
| TC-X-5 | `get_market_orderbook_depth_price(market: "BTC-USD", side: "buy")` | `?side=buy` | `?&` |
| TC-X-6 | `get_market_orderbook_depth_price(market: "BTC-USD", cumulative: false)` | `?cumulative=false` | `?&` |
| TC-X-7 | `get_market_orderbook_depth_volume(market: "BTC-USD", price: 50000.0)` | `?price=50000.000000` | `?&` |
| TC-X-8 | `get_market_trades(market: "BTC-USD", limit: 20)` | `?limit=20` | `?&` |
| TC-X-9 | `get_market_trades(market: "BTC-USD")` | No query string | `?&` |

**Mock approach:** Intercept `RestClient::Request.execute` (or stub `_rest_call`) and capture the `url:` argument. Assert on the URL string.

---

## Implementation Notes for Coder

1. **Test file location:** `test/test_issues_6_7_8.rb` (Minitest preferred; matches existing test infrastructure hint from `.test_cryptomnio.rb.swp`)

2. **Stub config for `Cryptomnio::REST::Client`:**
```ruby
STUB_CONFIG = {
  api_host_core: "api.cryptomnio.com",
  api_host_cma:  "cma.cryptomnio.com",
  authtype:      "Cryptomnio",
  access_key:    "test_access_key",
  secret_key:    "test_secret_key",
  contexts: {
    test: {
      venue:      "test_venue",
      accountid:  "test_account",
      venuekeyid: "test_venuekeyid"
    }
  }
}
```

3. **Stub `_rest_call`** to avoid live HTTP calls and capture arguments:
```ruby
captured_params = nil
client.stub(:_rest_call, ->(method, api, path, params, *rest) {
  captured_params = params
  {}
}) do
  client.get_market_orderbook(market: "BTC-USD", side: "buy")
end
assert_equal "side=buy", captured_params
```

4. **For TC-7 isolation test:** Spawn a subprocess that stubs `require 'rest-client'` (preventing its transitive openssl load) before loading cryptomnio, then calls `OpenSSL::HMAC.digest`. Subprocess failure = test failure. See TC-7-F setup block for the stub pattern.

5. **For TC-8 gemspec tests:** Use `Gem::Specification.load(File.expand_path("../../cryptomnio.gemspec", __FILE__))` — do not use `eval` on gemspec content.

---

## Summary

| Issue | Test Group | Cases Designed |
|---|---|---|
| #6 `get_market_orderbook` | TC-6-OB | 6 positive + 3 negative |
| #6 `get_market_orderbook_depth_price` | TC-6-OBP | 10 cases + cumulative=false edge |
| #6 `get_market_orderbook_depth_volume` | TC-6-OBV | 10 cases |
| #6 `get_market_trades` | TC-6-TR | 5 cases + 2 negative |
| #6 Cross-cutting URL regression | TC-X | 9 integration-level |
| #7 Static file check | TC-7-S | 3 cases |
| #7 Functional OpenSSL access | TC-7-F | 4 cases |
| #7 auth_cryptomnio method | TC-7-I | 4 cases |
| #8 Static gemspec check | TC-8-S | 4 cases |
| #8 Gemspec load | TC-8-L | 4 cases |
| #8 Version constraint | TC-8-V | 6 cases |
| **Total** | | **70 test cases** |

**Quality gate:** All 70 cases must pass before PR approval.

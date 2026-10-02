# Test Case Design — Issues #5, #17, #18, #19 (release 0.2.2)

SE run #1067, Step 3 (QA). Designed by Gem (QA Lead). Implementation is **not** included here —
this document specifies test cases for Coder to implement in `test/test_issues_5_17_18_19.rb`
following the conventions in `test/test_issues_6_7_8.rb` (minitest, `build_client` helper, no live
HTTP, `rake test` / `ruby test/test_issues_5_17_18_19.rb`).

Batch scope: #5 ($balance global→local), #17 (case-insensitive currency match), #18
(single-sourced VERSION/DATE via `lib/cryptomnio/version.rb`, plus gemspec `s.homepage` change to
the GitHub repo URL), #19 (`geminfo` API-version line), plus the companion LICENSE file and
CHANGELOG 0.2.2 entry that ship with #18.

---

## 0. Shared Fixtures & Conventions

All fixtures model the **unwrapped** response shape returned by `get_account_balance`
(confirmed from source: `_rest_call` returns `JSON.parse(response)['body']` directly, and
`get_account_balance` returns that as-is — so `get_account_balance_symbol` /
`get_account_available_balance_symbol` index straight into `result["assets"]`, no extra `"body"`
wrapper). This matches the shape of both fixtures quoted in the batch spec.

Stub `get_account_balance` via `define_singleton_method` on the client built with the existing
`build_client` helper (no live HTTP), mirroring the `_rest_call` stubbing pattern already used in
`test_issues_6_7_8.rb`.

**FIXTURE_MIXED** (non-identity amount/available values, to catch a field mix-up; one nil-currency
and one missing-currency-key asset to cover the adversarial cases without a dedicated fixture per
case):

```ruby
FIXTURE_MIXED = {
  "assets" => [
    { "amount" => "1.5",      "available" => "1.1",     "currency" => "BTC", "unavailable" => "0.4" },
    { "amount" => "200.25",   "available" => "150.75",  "currency" => "USD", "unavailable" => "49.5" },
    { "amount" => "9.0",      "available" => "8.0" },                                       # missing "currency" key
    { "amount" => "3.0",      "available" => "2.0",     "currency" => nil },                 # nil "currency"
  ],
  "timestamp" => 1790981802706,
  "venue" => "kraken"
}
```

**FIXTURE_MIXED_CASE** (same as above but venue's currency is mixed-case, to test symbol-side vs.
venue-side casing independently):

```ruby
FIXTURE_MIXED_CASE = {
  "assets" => [
    { "amount" => "1.5", "available" => "1.1", "currency" => "Btc", "unavailable" => "0.4" },
    { "amount" => "200.25", "available" => "150.75", "currency" => "Usd", "unavailable" => "49.5" },
  ],
  "timestamp" => 1790981802706, "venue" => "kraken"
}
```

**FIXTURE_EMPTY**: `{ "assets" => [], "timestamp" => 1790981802706, "venue" => "kraken" }`

**FIXTURE_ALL_NIL_CURRENCY**: `{ "assets" => [{"amount"=>"1","available"=>"1","currency"=>nil}, {"amount"=>"2","available"=>"2"}], "timestamp" => 0, "venue" => "kraken" }`

**FIXTURE_ISSUE17_REPRO** (verbatim from issue #17's reported reproduction):
```json
{"assets":[{"amount":"175032.6811","available":"175032.6811","currency":"USD","unavailable":"0"},{"amount":"5.95177519","available":"5.95177519","currency":"BTC","unavailable":"0"}],"timestamp":1788450998716,"venue":"kraken"}
```

**FIXTURE_LIVE_2026_10_02** (verbatim from the batch spec's live Kraken fixture; amount ==
available on every asset, includes a zero-balance asset — regression guard that a truthy-but-zero
string balance is not treated as "not found"):
```json
{"assets":[{"amount":"0","available":"0","currency":"ETH","unavailable":"0"},{"amount":"0.00000296","available":"0.00000296","currency":"USDC","unavailable":"0"},{"amount":"0.57909963","available":"0.57909963","currency":"BTC","unavailable":"0"},{"amount":"167185.2346","available":"167185.2346","currency":"USD","unavailable":"0"}],"timestamp":1790981802706,"venue":"kraken"}
```

---

## 1. Issue #5 — `$balance` global → local (10 cases)

Setup for all: `client = build_client`. Stub `get_account_balance` to return `FIXTURE_MIXED`
(for success cases) via `client.define_singleton_method(:get_account_balance) { |*| FIXTURE_MIXED }`,
or `FIXTURE_EMPTY` (for failure cases), restoring/removing the stub in `ensure`.

| ID | Setup | Input / Action | Expected |
|---|---|---|---|
| TC-5-1 | Stub → FIXTURE_MIXED. Record `defined?($balance)` before call. | `client.get_account_balance_symbol(symbol: "btc")` | Call succeeds; `defined?($balance)` after call equals the pre-call value (global was never touched/created) |
| TC-5-2 | Same, available method | `client.get_account_available_balance_symbol(symbol: "btc")` | Same as TC-5-1 |
| TC-5-3 | `$balance = "SENTINEL-5-3"` before call; stub → FIXTURE_MIXED | `get_account_balance_symbol(symbol: "usd")` | Returns `200.25`; `$balance == "SENTINEL-5-3"` unchanged after |
| TC-5-4 | `$balance = "SENTINEL-5-4"`; stub → FIXTURE_MIXED | `get_account_available_balance_symbol(symbol: "usd")` | Returns `150.75`; `$balance == "SENTINEL-5-4"` unchanged |
| TC-5-5 | `$balance = "SENTINEL-5-5"`; stub → FIXTURE_EMPTY | `get_account_balance_symbol(symbol: "xrp")` | Raises `RuntimeError`; `$balance == "SENTINEL-5-5"` unchanged (no leak on the failure path) |
| TC-5-6 | `$balance = "SENTINEL-5-6"`; stub → FIXTURE_EMPTY | `get_account_available_balance_symbol(symbol: "xrp")` | Raises `RuntimeError`; `$balance` unchanged |
| TC-5-7 | Stub → FIXTURE_MIXED for 1st call, swap stub → FIXTURE_EMPTY for 2nd call on same `client` | Call `get_account_balance_symbol(symbol: "btc")` (succeeds, returns `1.5`), then `get_account_balance_symbol(symbol: "xrp")` (absent) | 2nd call raises `RuntimeError` — it must NOT silently return the stale `1.5` from the 1st call |
| TC-5-8 | Same pattern, available method | success(`"btc"`) then absent(`"xrp"`) | 2nd call raises; does not return stale `1.1` |
| TC-5-9 | Stub → FIXTURE_EMPTY for 1st call (raises), swap stub → FIXTURE_MIXED for 2nd call | Call `get_account_balance_symbol(symbol: "xrp")` (raises, rescue it), then `get_account_balance_symbol(symbol: "btc")` | 2nd call returns correct fresh `1.5` (not `nil`, not contaminated by the prior failed attempt) |
| TC-5-10 | Stub → FIXTURE_MIXED | Call `get_account_balance_symbol(symbol: "btc")` → `1.5`, then (different method, different symbol) `get_account_available_balance_symbol(symbol: "usd")` | 2nd call returns `150.75` — correct field for its own symbol, not leaked/mixed from the 1st call's value or field |

---

## 2. Issue #17 — case-insensitive currency match (28 cases)

Setup for all: `client = build_client`, stub `get_account_balance` to return the named fixture.

### 2a. `get_account_balance_symbol` happy path (amount field) — FIXTURE_MIXED unless noted

| ID | Input | Expected |
|---|---|---|
| TC-17-1 | `symbol: "btc"` (lowercase) vs. currency `"BTC"` | `1.5` (Float) |
| TC-17-2 | `symbol: "BTC"` (uppercase) vs. currency `"BTC"` | `1.5` (Float) |
| TC-17-3 | `symbol: "BtC"` (mixed-case) vs. currency `"BTC"` | `1.5` (Float) |
| TC-17-4 | Fixture: FIXTURE_MIXED_CASE. `symbol: "btc"` vs. currency `"Btc"` | `1.5` (Float) |
| TC-17-5 | Fixture: FIXTURE_MIXED_CASE. `symbol: "BTC"` vs. currency `"Btc"` | `1.5` (Float) |
| TC-17-6 | `symbol: "usd"` | Returns `200.25` (the **amount** field) — not `150.75` (available); `result.is_a?(Float)` |

### 2b. `get_account_available_balance_symbol` happy path (available field) — FIXTURE_MIXED unless noted

| ID | Input | Expected |
|---|---|---|
| TC-17-7 | `symbol: "btc"` vs. currency `"BTC"` | `1.1` (Float) |
| TC-17-8 | `symbol: "BTC"` vs. currency `"BTC"` | `1.1` (Float) |
| TC-17-9 | `symbol: "BtC"` vs. currency `"BTC"` | `1.1` (Float) |
| TC-17-10 | Fixture: FIXTURE_MIXED_CASE. `symbol: "btc"` vs. currency `"Btc"` | `1.1` (Float) |
| TC-17-11 | Fixture: FIXTURE_MIXED_CASE. `symbol: "BTC"` vs. currency `"Btc"` | `1.1` (Float) |
| TC-17-12 | `symbol: "usd"` | Returns `150.75` (the **available** field) — not `200.25`; `result.is_a?(Float)` |

### 2c. Absent currency / adversarial inputs

| ID | Method | Fixture | Input | Expected |
|---|---|---|---|---|
| TC-17-13 | balance | FIXTURE_MIXED | `symbol: "xrp"` | Raises `RuntimeError`, message `No balance returned for currency symbol "xrp"` |
| TC-17-14 | available | FIXTURE_MIXED | `symbol: "xrp"` | Raises `RuntimeError`, same message format |
| TC-17-15 | balance | FIXTURE_EMPTY | `symbol: "btc"` | Raises `RuntimeError` (no assets at all) |
| TC-17-16 | available | FIXTURE_EMPTY | `symbol: "btc"` | Raises `RuntimeError` |
| TC-17-17 | balance | FIXTURE_MIXED (contains a `nil`-currency and a missing-currency-key asset ahead of/around real data) | `symbol: "usd"` | Returns `200.25` without raising `NoMethodError` — nil/missing currency entries are skipped safely |
| TC-17-18 | available | FIXTURE_MIXED | `symbol: "usd"` | Returns `150.75`, no `NoMethodError` |
| TC-17-19 | balance | FIXTURE_MIXED | `symbol: "btc"` | Still matches `"BTC"` correctly even with adversarial siblings present in the array |
| TC-17-20 | available | FIXTURE_MIXED | `symbol: "btc"` | Still matches correctly |
| TC-17-21 | balance | FIXTURE_ALL_NIL_CURRENCY | `symbol: "usd"` | Raises `RuntimeError` (not `NoMethodError`) — genuinely absent after safely skipping all nil/missing-currency assets |
| TC-17-22 | available | FIXTURE_ALL_NIL_CURRENCY | `symbol: "usd"` | Raises `RuntimeError` (not `NoMethodError`) |

### 2d. Venue-code casing independence (orthogonality — venue casing must not affect currency matching)

| ID | Method | Input | Expected |
|---|---|---|---|
| TC-17-23 | balance | `venue: "KRAKEN"`, `symbol: "btc"`, fixture FIXTURE_MIXED | Matching behavior unaffected by venue casing — returns `1.5` |
| TC-17-24 | balance | `venue: "Kraken"`, `symbol: "BTC"`, fixture FIXTURE_MIXED | Returns `1.5` |
| TC-17-25 | available | `venue: "KRAKEN"`, `symbol: "btc"`, fixture FIXTURE_MIXED | Returns `1.1` |
| TC-17-26 | available | `venue: "Kraken"`, `symbol: "BTC"`, fixture FIXTURE_MIXED | Returns `1.1` |

### 2e. Direct regression against the reported bugs

| ID | Method | Fixture | Input | Expected |
|---|---|---|---|---|
| TC-17-27 | balance | FIXTURE_ISSUE17_REPRO | `symbol: "btc"` | Returns `5.95177519` (Float) — this is issue #17's exact reported reproduction; must no longer raise |
| TC-17-28 | balance | FIXTURE_LIVE_2026_10_02 | `symbol: "eth"` | Returns `0.0` (Float), does **not** raise — a truthy `"0"` string balance for a currency that IS present must not be mistaken for "not found" |

---

## 3. Issue #18 — single-sourced VERSION / DATE (22 cases)

| ID | Setup | Check | Expected |
|---|---|---|---|
| TC-18-1 | Grep `lib/**/*.rb` and `cryptomnio.gemspec` (explicitly **excluding** `CHANGELOG.md`, `test/`, `docs/`, and this design doc) for the literal string `0.2.2` | Count files containing the literal | Exactly one match: `lib/cryptomnio/version.rb` |
| TC-18-2 | `require 'cryptomnio/version'` (lib on `$LOAD_PATH`) | `Cryptomnio::VERSION` | `== "0.2.2"` |
| TC-18-3 | Same | `Cryptomnio::DATE` | Matches `/\A\d{4}-\d{2}-\d{2}\z/` and is **not** either stale value (`"2023-01-28"` or `"2024-11-22"`) |
| TC-18-4 | `Gem::Specification.load("cryptomnio.gemspec")` | `.version.to_s` | `== "0.2.2"` |
| TC-18-4b | `Gem::Specification.load("cryptomnio.gemspec")` | `.homepage` | `== "https://github.com/dtrammell/ruby-cryptomnio"` — scope addition (I)ruid, 2026-10-02 23:22Z), ships in the #18 commit, replaces `https://cryptomnio.com/dev/lib/ruby` |
| TC-18-5 | `build_client`-style load, `Cryptomnio.new.VERSION` | attr_reader value | `== "0.2.2"` |
| TC-18-6 | `Cryptomnio.new.geminfo` | first line | Contains `"0.2.2"` |
| TC-18-7 | Combine TC-18-2/4/5/6 in one assertion | `Cryptomnio::VERSION`, gemspec version, instance `.VERSION`, and geminfo's version line | All four equal `"0.2.2"` and equal each other |
| TC-18-8 | Subprocess (isolated, like `TestIssue7Functional` pattern): only `Gem::Specification.load` the gemspec, nothing else | `defined?(RestClient)` | `nil`/false — gemspec load must not pull in rest-client |
| TC-18-9 | Same subprocess | `defined?(OpenSSL::HMAC)` | `nil`/false — gemspec load must not pull in openssl via the library |
| TC-18-10 | `Gem::Specification.load(...).files` | array | Includes `"lib/cryptomnio/version.rb"` |
| TC-18-11 | Same | array | Includes `"LICENSE"` |
| TC-18-12 | Run `gem build cryptomnio.gemspec` in a scratch copy of the repo (tmp dir, so the artifact isn't left in the working tree) | exit status | `0`; produces `cryptomnio-0.2.2.gem` |
| TC-18-13 | `Gem::Package.new("cryptomnio-0.2.2.gem").spec.files` (or equivalent `tar tzf` on the extracted `data.tar.gz`) | file list of the **built artifact** | Includes `"lib/cryptomnio/version.rb"` |
| TC-18-14 | Same built-artifact inspection | file list | Includes `"LICENSE"` |
| TC-18-14b | Read `.homepage` from the **built/packaged artifact's own spec** — e.g. `Gem::Package.new("cryptomnio-0.2.2.gem").spec.homepage` — not a hard-coded string in the test, and not `Gem::Specification.load` on the source `.gemspec` (that's TC-18-4b's job) | value | `== "https://github.com/dtrammell/ruby-cryptomnio"` — confirms the new homepage actually made it into the packaged artifact, not just the working-tree gemspec |
| TC-18-15 | Install the built `.gem` with `gem install --install-dir <tmp_gem_home> --no-document cryptomnio-0.2.2.gem`, then in a subprocess with `GEM_HOME`/`GEM_PATH` set to `<tmp_gem_home>` and that dir's `gems/cryptomnio-0.2.2/lib` on `$LOAD_PATH` (or via `gem` + `require`) | `require 'cryptomnio'` | Succeeds with no `LoadError` (catches the exact #18 failure mode: `s.files` omitting `version.rb`) |
| TC-18-16 | Same installed-gem subprocess | `Cryptomnio.new.VERSION` (or geminfo) | Reports `"0.2.2"` — full round trip through the real packaged artifact, not the working tree |
| TC-18-16b | Three-way DATE agreement, mirroring TC-18-7's VERSION agreement (gap flagged in review, NOVA 2026-10-02). Reuse the built artifact from TC-18-12/13: `Gem::Package.new("cryptomnio-0.2.2.gem").spec.date` **if present** — note RubyGems stores `s.date` as a `Time`, so format with `.strftime("%Y-%m-%d")` before comparing to a string. Also parse the date substring out of `Cryptomnio.new.geminfo` line 2 (`@DATE + " - " + @AUTHOR`). | `Cryptomnio::DATE` == formatted built-artifact gemspec date == geminfo's line-2 date substring | All three agree. **If the gemspec omits `s.date` entirely** (RubyGems then defaults it to build time at the package layer — a legitimate choice per #18's "dropping `s.date` is also an option"), skip only the gemspec leg of this comparison with a code comment explaining why, but still assert `Cryptomnio::DATE` == geminfo's date substring. This is the DATE analog of TC-18-7/TC-18-3, closing the gap that let #18's date drift (`2023-01-28` vs `2024-11-22`) go unnoticed in the first place — read from the **built artifact**, not the working-tree gemspec, so that specific drift can't recur silently. |
| TC-18-17 | `File.read("CHANGELOG.md")` | content | Contains a `## 0.2.2` heading |
| TC-18-18 | Same | content | Does **not** contain a `## 0.2.1` heading (no backfill per spec) |
| TC-18-19 | Same | content | Existing `## 0.2.0` section text is byte-identical to the pre-change CHANGELOG (no accidental edit) |

---

## 4. Issue #19 — `geminfo` API-version line (6 cases)

| ID | Setup | Check | Expected |
|---|---|---|---|
| TC-19-1 | `Cryptomnio.new.geminfo` | Line starting `"Cryptomnio API Version: "` | Equals `"Cryptomnio API Version: " + API_VERSION + "\n"`, i.e. shows `"0.24.0"` |
| TC-19-2 | Same | First line (gem name/version line) | Contains VERSION value (`"0.2.2"`), and does **not** contain the API_VERSION value |
| TC-19-3 | `Cryptomnio.new` | `instance.VERSION != instance.API_VERSION` | `true` — sanity guard so the two lines are distinguishable; this is what makes TC-19-1/2 meaningful rather than coincidentally-passing |
| TC-19-4 | `Cryptomnio.new` | `instance.API_VERSION` (attr_reader, independent of geminfo string parsing) | `== "0.24.0"` |
| TC-19-5 | `Cryptomnio.new` | `instance.VERSION` | `== "0.2.2"` |
| TC-19-6 | `Cryptomnio.new` | `instance.API_VERSION` | Still `"0.24.0"` — regression guard that the #19 fix only touched the `geminfo` string, not the `@API_VERSION` constant itself |

---

## 5. LICENSE file (5 cases)

| ID | Check | Expected |
|---|---|---|
| TC-LIC-1 | `File.exist?("LICENSE")` at repo root | `true` |
| TC-LIC-2 | `File.read("LICENSE")` | Contains the canonical MIT opening phrase, e.g. `"Permission is hereby granted, free of charge"` |
| TC-LIC-3 | Same | Contains a `"Copyright"` line |
| TC-LIC-4 | Same | Copyright line includes `"Dustin D. Trammell"` |
| TC-LIC-5 | `Gem::Specification.load("cryptomnio.gemspec").files` | Includes `"LICENSE"` (cross-referenced with TC-18-11 for LICENSE-specific traceability) |

---

## 6. Full-suite / cross-cutting regression (5 cases)

| ID | Command / Check | Expected |
|---|---|---|
| TC-REG-1 | Run `test/test_issues_6_7_8.rb` unmodified | All existing assertions still pass — nothing in this batch touches query-string handling, openssl require, or the rest-client dependency |
| TC-REG-2 | `rake test` (full `test/` dir) | Exit code `0`, zero failures/errors |
| TC-REG-3 | `ruby -c lib/cryptomnio.rb` | Exit `0` ("Syntax OK") — CI parity |
| TC-REG-4 | `ruby -c lib/cryptomnio/version.rb` | Exit `0` ("Syntax OK") — new file, CI parity |
| TC-REG-5 | `gem build cryptomnio.gemspec` (scratch copy); capture combined stdout+stderr | Exit `0`; AND combined output contains no line matching `/does not exist|not found/i` naming a file listed in `s.files` (e.g. `/lib\/cryptomnio\/version\.rb.*(does not exist\|not found)/i` or `/LICENSE.*(does not exist\|not found)/i`). Narrowed from a blanket "no warnings" per review (NOVA, 2026-10-02): `gem build` legitimately emits unrelated warnings (e.g. metadata recommendations) on Ruby 3.3/3.4/4.0 that would otherwise flake CI — this case targets only the `s.files`-integrity failure mode #18 actually cares about. |

---

## Totals

| Issue | Test cases |
|---|---|
| #5 ($balance global→local) | 10 |
| #17 (case-insensitive match) | 28 |
| #18 (single-source VERSION/DATE) | 22 |
| #19 (geminfo API version line) | 6 |
| LICENSE | 5 |
| Cross-cutting regression | 5 |
| **Total** | **76** |

---

## Notes for implementers (Coder)

- Confirmed from source: `get_account_balance` returns the parsed body **unwrapped** (no extra
  `"body"` key) — `_rest_call` already does `JSON.parse(response)['body']` and returns that. The
  existing `@balances["assets"]` indexing in both symbol methods is correct as-is; only the
  `$balance`→local (#5) and case-folding (#17) defects need fixing. Fixtures above assume this
  confirmed shape.
- #17's adversarial nil/missing-`currency` handling is intentionally implementation-agnostic in
  this doc (e.g. `asset["currency"]&.downcase == symbol` vs. an explicit `next if
  asset["currency"].nil?` guard both satisfy TC-17-17 through TC-17-22) — tests assert behavior,
  not a specific code shape.
- TC-18-8/9/15/16 need subprocess isolation (same technique as `TestIssue7Functional` in
  `test_issues_6_7_8.rb`) to get a clean `$LOADED_FEATURES` state — don't rely on in-process
  `defined?` checks, since earlier tests in the same `rake test` run may have already loaded
  rest-client/openssl.
- TC-18-12/13/14/15/16 should build/install in a tmp directory, not the working tree, and clean up
  after themselves (temp `GEM_HOME`, temp `.gem` file) so `rake test` stays idempotent and doesn't
  leave build artifacts for git to pick up.
- TC-18-14b (homepage) must read the value off the **built `.gem`'s own spec** (e.g.
  `Gem::Package.new(path).spec.homepage`), not assert against a literal string duplicated in the
  test file — the point is to prove the new URL survived packaging, not to restate it. TC-18-4b is
  the separate, narrower check that the source gemspec itself declares the new URL.
- TC-18-16b (DATE agreement) follows the same built-artifact-not-working-tree principle as
  TC-18-14b/TC-18-13. `Gem::Specification#date` is typed `Time`, not `String` — compare via
  `.strftime("%Y-%m-%d")`, not `==` against a raw string, or the assertion will always fail
  regardless of correctness. If Coder drops `s.date` from the gemspec (explicitly permitted by
  #18), the test must detect that condition (e.g. `spec.date.nil?` won't apply since RubyGems
  back-fills a default — instead check whether the gemspec source literally sets `s.date`, or
  simply treat the gemspec leg as best-effort/skippable and keep the geminfo-vs-DATE leg as the
  hard assertion) rather than silently passing on a build-time default that was never meant to be
  meaningful.
- TC-REG-5's regex is intentionally narrow (per review) — do not widen it back to "zero warnings"
  or it will flake on unrelated `gem build` metadata warnings across the CI matrix (3.3/3.4/4.0).
  If a future `gem build` warning format changes, adjust the pattern, not the intent (catch
  `s.files` entries that don't exist on disk at build time).

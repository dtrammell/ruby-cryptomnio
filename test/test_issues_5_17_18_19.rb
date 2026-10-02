#!/usr/bin/env ruby
# frozen_string_literal: true

# Test suite for Issues #5, #17, #18, #19 (release 0.2.2)
# Run with: rake test  (or: ruby test/test_issues_5_17_18_19.rb)
# Requires: gem install minitest rest-client

require 'minitest/autorun'
require 'rubygems'
require 'shellwords'
require 'tempfile'
require 'fileutils'

# ---------------------------------------------------------------------------
# Stub config — no live API calls required
# ---------------------------------------------------------------------------
STUB_CONFIG = {
  api_host_core: "api.cryptomnio.com",
  api_host_cma:  "cma.cryptomnio.com",
  authtype:      "Cryptomnio",
  access_key:    "test_access_key",
  secret_key:    "test_secret_key",
  contexts: {
    test: {
      venue:      "kraken",
      accountid:  "test_account",
      venuekeyid: "test_venuekeyid"
    }
  }
}.freeze

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
FIXTURE_MIXED = {
  "assets" => [
    { "amount" => "1.5",      "available" => "1.1",     "currency" => "BTC", "unavailable" => "0.4" },
    { "amount" => "200.25",   "available" => "150.75",  "currency" => "USD", "unavailable" => "49.5" },
    { "amount" => "9.0",      "available" => "8.0" },                                       # missing "currency" key
    { "amount" => "3.0",      "available" => "2.0",     "currency" => nil },                 # nil "currency"
  ],
  "timestamp" => 1790981802706,
  "venue" => "kraken"
}.freeze

FIXTURE_MIXED_CASE = {
  "assets" => [
    { "amount" => "1.5", "available" => "1.1", "currency" => "Btc", "unavailable" => "0.4" },
    { "amount" => "200.25", "available" => "150.75", "currency" => "Usd", "unavailable" => "49.5" },
  ],
  "timestamp" => 1790981802706, "venue" => "kraken"
}.freeze

FIXTURE_EMPTY = { "assets" => [], "timestamp" => 1790981802706, "venue" => "kraken" }.freeze

FIXTURE_ALL_NIL_CURRENCY = {
  "assets" => [
    {"amount" => "1", "available" => "1", "currency" => nil},
    {"amount" => "2", "available" => "2"}
  ],
  "timestamp" => 0,
  "venue" => "kraken"
}.freeze

FIXTURE_ISSUE17_REPRO = {
  "assets" => [
    {"amount" => "175032.6811", "available" => "175032.6811", "currency" => "USD", "unavailable" => "0"},
    {"amount" => "5.95177519", "available" => "5.95177519", "currency" => "BTC", "unavailable" => "0"}
  ],
  "timestamp" => 1788450998716,
  "venue" => "kraken"
}.freeze

FIXTURE_LIVE_2026_10_02 = {
  "assets" => [
    {"amount" => "0", "available" => "0", "currency" => "ETH", "unavailable" => "0"},
    {"amount" => "0.00000296", "available" => "0.00000296", "currency" => "USDC", "unavailable" => "0"},
    {"amount" => "0.57909963", "available" => "0.57909963", "currency" => "BTC", "unavailable" => "0"},
    {"amount" => "167185.2346", "available" => "167185.2346", "currency" => "USD", "unavailable" => "0"}
  ],
  "timestamp" => 1790981802706,
  "venue" => "kraken"
}.freeze

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Build a Cryptomnio::REST::Client from stub config without any real HTTP calls.
def build_client
  $LOAD_PATH.unshift(File.expand_path('../../lib', __FILE__)) unless
    $LOAD_PATH.include?(File.expand_path('../../lib', __FILE__))
  require 'cryptomnio'

  client = Cryptomnio::REST::Client.allocate
  client.config = STUB_CONFIG.dup
  client.instance_variable_set(:@context,      STUB_CONFIG[:contexts][:test])
  client.instance_variable_set(:@URI_VERSION,  "")
  client
end

# ============================================================================
# Issue #5 — $balance global → local variable
# ============================================================================
class TestIssue5BalanceLocal < Minitest::Test
  def setup
    @client = build_client
  end

  def teardown
    # Remove the singleton stub if present
    @client.singleton_class.remove_method(:get_account_balance) rescue nil
  end

  def stub_balance(fixture)
    @client.define_singleton_method(:get_account_balance) { |*| fixture }
  end

  # TC-5-1: get_account_balance_symbol must not touch/create $balance global
  def test_5_1_balance_symbol_does_not_create_global
    before = defined?($balance)
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_balance_symbol(symbol: "btc")
    assert_equal 1.5, result
    assert_equal before, defined?($balance), "$balance global state changed after call"
  end

  # TC-5-2: get_account_available_balance_symbol must not touch/create $balance global
  def test_5_2_available_balance_symbol_does_not_create_global
    before = defined?($balance)
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_available_balance_symbol(symbol: "btc")
    assert_equal 1.1, result
    assert_equal before, defined?($balance), "$balance global state changed after call"
  end

  # TC-5-3: existing $balance sentinel is preserved on balance success
  def test_5_3_existing_global_unchanged_on_balance_success
    $balance = "SENTINEL-5-3"
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_balance_symbol(symbol: "usd")
    assert_equal 200.25, result
    assert_equal "SENTINEL-5-3", $balance
  ensure
    $balance = nil if defined?($balance)
  end

  # TC-5-4: existing $balance sentinel is preserved on available success
  def test_5_4_existing_global_unchanged_on_available_success
    $balance = "SENTINEL-5-4"
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_available_balance_symbol(symbol: "usd")
    assert_equal 150.75, result
    assert_equal "SENTINEL-5-4", $balance
  ensure
    $balance = nil if defined?($balance)
  end

  # TC-5-5: existing $balance sentinel is preserved on balance failure
  def test_5_5_existing_global_unchanged_on_balance_failure
    $balance = "SENTINEL-5-5"
    stub_balance(FIXTURE_EMPTY)
    error = assert_raises(RuntimeError) { @client.get_account_balance_symbol(symbol: "xrp") }
    assert_match(/No balance returned for currency symbol "xrp"/, error.message)
    assert_equal "SENTINEL-5-5", $balance
  ensure
    $balance = nil if defined?($balance)
  end

  # TC-5-6: existing $balance sentinel is preserved on available failure
  def test_5_6_existing_global_unchanged_on_available_failure
    $balance = "SENTINEL-5-6"
    stub_balance(FIXTURE_EMPTY)
    error = assert_raises(RuntimeError) { @client.get_account_available_balance_symbol(symbol: "xrp") }
    assert_match(/No balance returned for currency symbol "xrp"/, error.message)
    assert_equal "SENTINEL-5-6", $balance
  ensure
    $balance = nil if defined?($balance)
  end

  # TC-5-7: absent symbol after success must raise, not return stale balance
  def test_5_7_absent_symbol_raises_not_stale_balance
    stub_balance(FIXTURE_MIXED)
    assert_equal 1.5, @client.get_account_balance_symbol(symbol: "btc")

    @client.singleton_class.remove_method(:get_account_balance) rescue nil
    stub_balance(FIXTURE_EMPTY)
    assert_raises(RuntimeError) { @client.get_account_balance_symbol(symbol: "xrp") }
  end

  # TC-5-8: absent symbol after success must raise, not return stale available
  def test_5_8_absent_symbol_raises_not_stale_available
    stub_balance(FIXTURE_MIXED)
    assert_equal 1.1, @client.get_account_available_balance_symbol(symbol: "btc")

    @client.singleton_class.remove_method(:get_account_balance) rescue nil
    stub_balance(FIXTURE_EMPTY)
    assert_raises(RuntimeError) { @client.get_account_available_balance_symbol(symbol: "xrp") }
  end

  # TC-5-9: success after failure returns correct fresh value
  def test_5_9_success_after_failure_returns_fresh_value
    stub_balance(FIXTURE_EMPTY)
    assert_raises(RuntimeError) { @client.get_account_balance_symbol(symbol: "xrp") }

    @client.singleton_class.remove_method(:get_account_balance) rescue nil
    stub_balance(FIXTURE_MIXED)
    assert_equal 1.5, @client.get_account_balance_symbol(symbol: "btc")
  end

  # TC-5-10: different method/symbol does not leak/mix values
  def test_5_10_different_methods_do_not_mix_values
    stub_balance(FIXTURE_MIXED)
    assert_equal 1.5, @client.get_account_balance_symbol(symbol: "btc")
    assert_equal 150.75, @client.get_account_available_balance_symbol(symbol: "usd")
  end
end

# ============================================================================
# Issue #17 — case-insensitive currency symbol match
# ============================================================================
class TestIssue17CaseInsensitiveMatch < Minitest::Test
  def setup
    @client = build_client
  end

  def teardown
    @client.singleton_class.remove_method(:get_account_balance) rescue nil
  end

  def stub_balance(fixture)
    @client.define_singleton_method(:get_account_balance) { |*| fixture }
  end

  # --- 2a. get_account_balance_symbol happy path ---

  # TC-17-1: lowercase symbol matches uppercase currency
  def test_17_1_balance_lowercase_symbol_uppercase_currency
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_balance_symbol(symbol: "btc")
    assert_equal 1.5, result
    assert_instance_of Float, result
  end

  # TC-17-2: uppercase symbol matches uppercase currency
  def test_17_2_balance_uppercase_symbol_uppercase_currency
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_balance_symbol(symbol: "BTC")
    assert_equal 1.5, result
    assert_instance_of Float, result
  end

  # TC-17-3: mixed-case symbol matches uppercase currency
  def test_17_3_balance_mixed_case_symbol_uppercase_currency
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_balance_symbol(symbol: "BtC")
    assert_equal 1.5, result
    assert_instance_of Float, result
  end

  # TC-17-4: lowercase symbol matches mixed-case currency
  def test_17_4_balance_lowercase_symbol_mixed_case_currency
    stub_balance(FIXTURE_MIXED_CASE)
    result = @client.get_account_balance_symbol(symbol: "btc")
    assert_equal 1.5, result
    assert_instance_of Float, result
  end

  # TC-17-5: uppercase symbol matches mixed-case currency
  def test_17_5_balance_uppercase_symbol_mixed_case_currency
    stub_balance(FIXTURE_MIXED_CASE)
    result = @client.get_account_balance_symbol(symbol: "BTC")
    assert_equal 1.5, result
    assert_instance_of Float, result
  end

  # TC-17-6: returns amount field, not available
  def test_17_6_balance_returns_amount_not_available
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_balance_symbol(symbol: "usd")
    assert_equal 200.25, result  # amount from fixture, not 150.75 (available)
    assert_instance_of Float, result
  end

  # --- 2b. get_account_available_balance_symbol happy path ---

  # TC-17-7: lowercase symbol matches uppercase currency
  def test_17_7_available_lowercase_symbol_uppercase_currency
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_available_balance_symbol(symbol: "btc")
    assert_equal 1.1, result
    assert_instance_of Float, result
  end

  # TC-17-8: uppercase symbol matches uppercase currency
  def test_17_8_available_uppercase_symbol_uppercase_currency
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_available_balance_symbol(symbol: "BTC")
    assert_equal 1.1, result
    assert_instance_of Float, result
  end

  # TC-17-9: mixed-case symbol matches uppercase currency
  def test_17_9_available_mixed_case_symbol_uppercase_currency
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_available_balance_symbol(symbol: "BtC")
    assert_equal 1.1, result
    assert_instance_of Float, result
  end

  # TC-17-10: lowercase symbol matches mixed-case currency
  def test_17_10_available_lowercase_symbol_mixed_case_currency
    stub_balance(FIXTURE_MIXED_CASE)
    result = @client.get_account_available_balance_symbol(symbol: "btc")
    assert_equal 1.1, result
    assert_instance_of Float, result
  end

  # TC-17-11: uppercase symbol matches mixed-case currency
  def test_17_11_available_uppercase_symbol_mixed_case_currency
    stub_balance(FIXTURE_MIXED_CASE)
    result = @client.get_account_available_balance_symbol(symbol: "BTC")
    assert_equal 1.1, result
    assert_instance_of Float, result
  end

  # TC-17-12: returns available field, not amount
  def test_17_12_available_returns_available_not_amount
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_available_balance_symbol(symbol: "usd")
    assert_equal 150.75, result  # available from fixture, not 200.25 (amount)
    assert_instance_of Float, result
  end

  # --- 2c. Absent currency / adversarial inputs ---

  # TC-17-13: absent currency raises RuntimeError on balance
  def test_17_13_absent_currency_raises_on_balance
    stub_balance(FIXTURE_MIXED)
    error = assert_raises(RuntimeError) { @client.get_account_balance_symbol(symbol: "xrp") }
    assert_match(/No balance returned for currency symbol "xrp"/, error.message)
  end

  # TC-17-14: absent currency raises RuntimeError on available
  def test_17_14_absent_currency_raises_on_available
    stub_balance(FIXTURE_MIXED)
    error = assert_raises(RuntimeError) { @client.get_account_available_balance_symbol(symbol: "xrp") }
    assert_match(/No balance returned for currency symbol "xrp"/, error.message)
  end

  # TC-17-15: empty assets raises RuntimeError on balance
  def test_17_15_empty_assets_raises_on_balance
    stub_balance(FIXTURE_EMPTY)
    assert_raises(RuntimeError) { @client.get_account_balance_symbol(symbol: "btc") }
  end

  # TC-17-16: empty assets raises RuntimeError on available
  def test_17_16_empty_assets_raises_on_available
    stub_balance(FIXTURE_EMPTY)
    assert_raises(RuntimeError) { @client.get_account_available_balance_symbol(symbol: "btc") }
  end

  # TC-17-17: nil/missing currency entries are skipped safely on balance
  def test_17_17_nil_missing_currency_skipped_on_balance
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_balance_symbol(symbol: "usd")
    assert_equal 200.25, result  # second asset, after nil/missing-currency siblings
  end

  # TC-17-18: nil/missing currency entries are skipped safely on available
  def test_17_18_nil_missing_currency_skipped_on_available
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_available_balance_symbol(symbol: "usd")
    assert_equal 150.75, result
  end

  # TC-17-19: still matches BTC correctly with adversarial siblings
  def test_17_19_matches_btc_with_adversarial_siblings
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_balance_symbol(symbol: "btc")
    assert_equal 1.5, result
  end

  # TC-17-20: still matches BTC available correctly with adversarial siblings
  def test_17_20_matches_btc_available_with_adversarial_siblings
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_available_balance_symbol(symbol: "btc")
    assert_equal 1.1, result
  end

  # TC-17-21: all nil/missing currency raises RuntimeError on balance
  def test_17_21_all_nil_currency_raises_on_balance
    stub_balance(FIXTURE_ALL_NIL_CURRENCY)
    assert_raises(RuntimeError) { @client.get_account_balance_symbol(symbol: "usd") }
  end

  # TC-17-22: all nil/missing currency raises RuntimeError on available
  def test_17_22_all_nil_currency_raises_on_available
    stub_balance(FIXTURE_ALL_NIL_CURRENCY)
    assert_raises(RuntimeError) { @client.get_account_available_balance_symbol(symbol: "usd") }
  end

  # --- 2d. Venue-code casing independence ---

  # TC-17-23: venue casing does not affect balance matching
  def test_17_23_venue_uppercase_balance
    context = STUB_CONFIG[:contexts][:test].dup
    context[:venue] = "KRAKEN"
    @client.instance_variable_set(:@context, context)
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_balance_symbol(symbol: "btc")
    assert_equal 1.5, result
  end

  # TC-17-24: mixed-case venue does not affect balance matching
  def test_17_24_venue_mixed_case_balance
    context = STUB_CONFIG[:contexts][:test].dup
    context[:venue] = "Kraken"
    @client.instance_variable_set(:@context, context)
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_balance_symbol(symbol: "BTC")
    assert_equal 1.5, result
  end

  # TC-17-25: venue casing does not affect available matching
  def test_17_25_venue_uppercase_available
    context = STUB_CONFIG[:contexts][:test].dup
    context[:venue] = "KRAKEN"
    @client.instance_variable_set(:@context, context)
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_available_balance_symbol(symbol: "btc")
    assert_equal 1.1, result
  end

  # TC-17-26: mixed-case venue does not affect available matching
  def test_17_26_venue_mixed_case_available
    context = STUB_CONFIG[:contexts][:test].dup
    context[:venue] = "Kraken"
    @client.instance_variable_set(:@context, context)
    stub_balance(FIXTURE_MIXED)
    result = @client.get_account_available_balance_symbol(symbol: "BTC")
    assert_equal 1.1, result
  end

  # --- 2e. Direct regression against reported bugs ---

  # TC-17-27: issue #17 exact reproduction no longer raises
  def test_17_27_issue_17_exact_repro
    stub_balance(FIXTURE_ISSUE17_REPRO)
    result = @client.get_account_balance_symbol(symbol: "btc")
    assert_equal 5.95177519, result  # amount from BTC asset in issue #17 repro fixture
    assert_instance_of Float, result
  end

  # TC-17-28: zero string balance for present currency returns 0.0
  def test_17_28_zero_string_balance_present_currency
    stub_balance(FIXTURE_LIVE_2026_10_02)
    result = @client.get_account_balance_symbol(symbol: "eth")
    assert_equal 0.0, result  # "0".to_f == 0.0, but currency is present so must not raise
    assert_instance_of Float, result
  end
end

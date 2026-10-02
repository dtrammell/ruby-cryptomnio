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

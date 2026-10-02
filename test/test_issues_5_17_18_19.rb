#!/usr/bin/env ruby
# frozen_string_literal: true

# Test suite for Issues #5, #17, #18, #19 (release 0.2.2)
# Run with: rake test  (or: ruby test/test_issues_5_17_18_19.rb)
# Requires: gem install minitest rest-client

require 'minitest/autorun'
require 'rubygems'
require 'rubygems/package'
require 'shellwords'
require 'tempfile'
require 'fileutils'

$LOAD_PATH.unshift(File.expand_path('../lib', __FILE__)) unless
  $LOAD_PATH.include?(File.expand_path('../lib', __FILE__))
require 'cryptomnio'

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

# ============================================================================
# Issue #19 — geminfo prints API_VERSION on API version line
# ============================================================================
class TestIssue19GeminfoApiVersion < Minitest::Test
  def setup
    @instance = Cryptomnio.new
  end

  # TC-19-1: API version line shows @API_VERSION (0.24.0)
  def test_19_1_api_version_line
    lines = @instance.geminfo.lines
    assert_equal "Cryptomnio API Version: 0.24.0\n", lines[2]
  end

  # TC-19-2: first line contains VERSION, not API_VERSION
  def test_19_2_first_line_contains_version_not_api_version
    first_line = @instance.geminfo.lines[0]
    assert_includes first_line, @instance.VERSION
    refute_includes first_line, @instance.API_VERSION
  end

  # TC-19-3: VERSION and API_VERSION are distinguishable
  def test_19_3_version_and_api_version_differ
    refute_equal @instance.VERSION, @instance.API_VERSION
  end

  # TC-19-4: API_VERSION attr_reader returns 0.24.0
  def test_19_4_api_version_value
    assert_equal "0.24.0", @instance.API_VERSION
  end

  # TC-19-5: VERSION attr_reader returns current gem version
  def test_19_5_version_value
    assert_equal "0.2.2", @instance.VERSION  # release version per #18 design
  end

  # TC-19-6: API_VERSION constant itself is unchanged
  def test_19_6_api_version_constant_unchanged
    assert_equal "0.24.0", @instance.API_VERSION
  end
end

# ============================================================================
# Issue #18 — single-sourced VERSION / DATE
# ============================================================================
class TestIssue18SingleSourceVersion < Minitest::Test
  REPO_ROOT = File.expand_path('../..', __FILE__).freeze
  LIB_DIR   = File.expand_path('../../lib', __FILE__).freeze
  RUBY_BIN  = RbConfig.ruby

  # TC-18-1: only version.rb contains the literal "0.2.2" in lib/ and gemspec
  def test_18_1_only_version_rb_has_release_literal
    matches = []
    Dir.glob(File.join(REPO_ROOT, 'lib', '**', '*.rb')).each do |rb_file|
      matches << rb_file if File.read(rb_file).include?('0.2.2')
    end
    gemspec_path = File.join(REPO_ROOT, 'cryptomnio.gemspec')
    matches << gemspec_path if File.read(gemspec_path).include?('0.2.2')

    assert_equal 1, matches.length,
      "Expected exactly one file in lib/ + gemspec to contain '0.2.2', got: #{matches.inspect}"
    assert_equal File.join(REPO_ROOT, 'lib', 'cryptomnio', 'version.rb'), matches.first
  end

  # TC-18-2: Cryptomnio::VERSION == "0.2.2"
  def test_18_2_version_constant
    assert_equal "0.2.2", Cryptomnio::VERSION
  end

  # TC-18-3: Cryptomnio::DATE is a valid ISO date and not stale
  def test_18_3_date_constant
    assert_match(/\A\d{4}-\d{2}-\d{2}\z/, Cryptomnio::DATE)
    refute_equal "2023-01-28", Cryptomnio::DATE
    refute_equal "2024-11-22", Cryptomnio::DATE
  end

  # TC-18-4: gemspec version == "0.2.2"
  def test_18_4_gemspec_version
    spec = Gem::Specification.load(File.join(REPO_ROOT, 'cryptomnio.gemspec'))
    assert_equal "0.2.2", spec.version.to_s
  end

  # TC-18-4b: gemspec homepage points to GitHub
  def test_18_4b_gemspec_homepage
    spec = Gem::Specification.load(File.join(REPO_ROOT, 'cryptomnio.gemspec'))
    assert_equal "https://github.com/dtrammell/ruby-cryptomnio", spec.homepage
  end

  # TC-18-5: instance VERSION attr_reader == "0.2.2"
  def test_18_5_instance_version
    assert_equal "0.2.2", Cryptomnio.new.VERSION
  end

  # TC-18-6: geminfo first line contains VERSION
  def test_18_6_geminfo_version_line
    first_line = Cryptomnio.new.geminfo.lines[0]
    assert_includes first_line, "0.2.2"
  end

  # TC-18-7: all four version sources agree
  def test_18_7_all_version_sources_agree
    spec = Gem::Specification.load(File.join(REPO_ROOT, 'cryptomnio.gemspec'))
    instance = Cryptomnio.new
    geminfo_version_line = instance.geminfo.lines[0]

    assert_equal "0.2.2", Cryptomnio::VERSION
    assert_equal "0.2.2", spec.version.to_s
    assert_equal "0.2.2", instance.VERSION
    assert_includes geminfo_version_line, "0.2.2"
  end

  # TC-18-8: loading gemspec does not pull in rest-client
  def test_18_8_gemspec_does_not_require_rest_client
    script = <<~'RUBY'
      $LOAD_PATH.unshift(ARGV[0])
      Gem::Specification.load(ARGV[1])
      if defined?(RestClient)
        puts "FAIL: RestClient defined"
        exit 1
      else
        puts "PASS"
      end
    RUBY

    tf = Tempfile.new(['tc18_8_', '.rb'])
    begin
      tf.write(script)
      tf.flush
      output = `#{RUBY_BIN.shellescape} #{tf.path.shellescape} #{LIB_DIR.shellescape} #{File.join(REPO_ROOT, 'cryptomnio.gemspec').shellescape} 2>&1`
      assert $?.success?, "subprocess failed. Output: #{output}"
      assert_match(/PASS/, output, "RestClient was defined when loading gemspec. Output: #{output}")
    ensure
      tf.close
      tf.unlink
    end
  end

  # TC-18-9: loading gemspec does not pull in openssl via the library
  def test_18_9_gemspec_does_not_require_openssl
    script = <<~'RUBY'
      $LOAD_PATH.unshift(ARGV[0])
      Gem::Specification.load(ARGV[1])
      if defined?(OpenSSL::HMAC)
        puts "FAIL: OpenSSL::HMAC defined"
        exit 1
      else
        puts "PASS"
      end
    RUBY

    tf = Tempfile.new(['tc18_9_', '.rb'])
    begin
      tf.write(script)
      tf.flush
      output = `#{RUBY_BIN.shellescape} #{tf.path.shellescape} #{LIB_DIR.shellescape} #{File.join(REPO_ROOT, 'cryptomnio.gemspec').shellescape} 2>&1`
      assert $?.success?, "subprocess failed. Output: #{output}"
      assert_match(/PASS/, output, "OpenSSL::HMAC was defined when loading gemspec. Output: #{output}")
    ensure
      tf.close
      tf.unlink
    end
  end

  # TC-18-10: source gemspec files include version.rb
  def test_18_10_gemspec_files_include_version_rb
    spec = Gem::Specification.load(File.join(REPO_ROOT, 'cryptomnio.gemspec'))
    assert_includes spec.files, "lib/cryptomnio/version.rb"
  end

  # TC-18-11: source gemspec files include LICENSE
  def test_18_11_gemspec_files_include_license
    spec = Gem::Specification.load(File.join(REPO_ROOT, 'cryptomnio.gemspec'))
    assert_includes spec.files, "LICENSE"
  end

  # TC-18-12/13/14/14b/15/16/16b helpers: build gem in scratch copy
  def build_gem_in_scratch
    scratch = Dir.mktmpdir('cryptomnio_build')
    FileUtils.cp_r(File.join(REPO_ROOT, '.'), scratch)
    gem_path = File.join(scratch, 'cryptomnio-0.2.2.gem')

    Dir.chdir(scratch) do
      output = `gem build cryptomnio.gemspec 2>&1`
      assert $?.success?, "gem build failed. Output: #{output}"
      assert File.exist?(gem_path), "Expected gem artifact not found at #{gem_path}"
    end

    [scratch, gem_path]
  end

  # TC-18-12: gem build succeeds and produces artifact
  def test_18_12_gem_build_succeeds
    scratch, _gem_path = build_gem_in_scratch
  ensure
    FileUtils.rm_rf(scratch) if scratch
  end

  # TC-18-13: built artifact includes version.rb
  def test_18_13_built_artifact_includes_version_rb
    scratch, gem_path = build_gem_in_scratch
    spec = Gem::Package.new(gem_path).spec
    assert_includes spec.files, "lib/cryptomnio/version.rb"
  ensure
    FileUtils.rm_rf(scratch) if scratch
  end

  # TC-18-14: built artifact includes LICENSE
  def test_18_14_built_artifact_includes_license
    scratch, gem_path = build_gem_in_scratch
    spec = Gem::Package.new(gem_path).spec
    assert_includes spec.files, "LICENSE"
  ensure
    FileUtils.rm_rf(scratch) if scratch
  end

  # TC-18-14b: built artifact homepage is GitHub URL
  def test_18_14b_built_artifact_homepage
    scratch, gem_path = build_gem_in_scratch
    spec = Gem::Package.new(gem_path).spec
    assert_equal "https://github.com/dtrammell/ruby-cryptomnio", spec.homepage
  ensure
    FileUtils.rm_rf(scratch) if scratch
  end

  # TC-18-15/16: install built gem to tmp gem home and verify load + version
  def test_18_15_16_install_and_load_built_gem
    scratch, gem_path = build_gem_in_scratch
    gem_home = Dir.mktmpdir('cryptomnio_gem_home')

    install_output = `gem install --install-dir #{gem_home.shellescape} --no-document #{gem_path.shellescape} 2>&1`
    assert $?.success?, "gem install failed. Output: #{install_output}"

    script = <<~'RUBY'
      gem_home = ARGV[0]
      gem_lib = File.join(gem_home, 'gems', 'cryptomnio-0.2.2', 'lib')
      $LOAD_PATH.unshift(gem_lib)
      ENV['GEM_HOME'] = gem_home
      ENV['GEM_PATH'] = gem_home
      require 'cryptomnio'
      puts "VERSION=#{Cryptomnio.new.VERSION}"
      puts "PASS"
    RUBY

    tf = Tempfile.new(['tc18_15_16_', '.rb'])
    begin
      tf.write(script)
      tf.flush
      output = `#{RUBY_BIN.shellescape} #{tf.path.shellescape} #{gem_home.shellescape} 2>&1`
      assert $?.success?, "subprocess failed. Output: #{output}"
      assert_match(/PASS/, output, "require 'cryptomnio' failed in installed gem. Output: #{output}")
      assert_match(/VERSION=0\.2\.2/, output, "Installed gem version mismatch. Output: #{output}")
    ensure
      tf.close
      tf.unlink
      FileUtils.rm_rf(gem_home)
      FileUtils.rm_rf(scratch)
    end
  end

  # TC-18-16b: three-way DATE agreement from built artifact
  def test_18_16b_date_agreement
    scratch, gem_path = build_gem_in_scratch
    begin
      packaged_spec = Gem::Package.new(gem_path).spec
      instance = Cryptomnio.new
      geminfo_date = instance.geminfo.lines[1].split(' - ').first

      assert_equal Cryptomnio::DATE, geminfo_date

      if packaged_spec.date
        assert_equal Cryptomnio::DATE, packaged_spec.date.strftime("%Y-%m-%d")
      end
    ensure
      FileUtils.rm_rf(scratch)
    end
  end

  # TC-18-17: CHANGELOG contains 0.2.2 heading
  def test_18_17_changelog_has_0_2_2
    content = File.read(File.join(REPO_ROOT, 'CHANGELOG.md'))
    assert_match(/##\s+0\.2\.2/, content)
  end

  # TC-18-18: CHANGELOG does not contain 0.2.1 heading
  def test_18_18_changelog_no_0_2_1
    content = File.read(File.join(REPO_ROOT, 'CHANGELOG.md'))
    refute_match(/##\s+0\.2\.1/, content)
  end

  # TC-18-19: 0.2.0 section is byte-identical to pre-change
  def test_18_19_changelog_0_2_0_unchanged
    current = File.read(File.join(REPO_ROOT, 'CHANGELOG.md'))
    original = `git -C #{REPO_ROOT.shellescape} show ac29adf:CHANGELOG.md 2>&1`
    skip "git baseline unavailable: #{original}" unless $?.success?

    current_section = current[current.index("## 0.2.0")..-1]
    original_section = original[original.index("## 0.2.0")..-1]
    assert_equal original_section, current_section,
      "0.2.0 CHANGELOG section must remain byte-identical to ac29adf"
  end
end

# ============================================================================
# LICENSE file tests
# ============================================================================
class TestLicense < Minitest::Test
  REPO_ROOT = File.expand_path('../..', __FILE__).freeze

  # TC-LIC-1: LICENSE exists at repo root
  def test_lic_1_exists
    assert File.exist?(File.join(REPO_ROOT, 'LICENSE'))
  end

  # TC-LIC-2: LICENSE contains MIT opening phrase
  def test_lic_2_mit_opening
    content = File.read(File.join(REPO_ROOT, 'LICENSE'))
    assert_includes content, "Permission is hereby granted, free of charge"
  end

  # TC-LIC-3: LICENSE contains a Copyright line
  def test_lic_3_copyright_line
    content = File.read(File.join(REPO_ROOT, 'LICENSE'))
    assert_match(/Copyright/i, content)
  end

  # TC-LIC-4: Copyright includes Dustin D. Trammell
  def test_lic_4_copyright_holder
    content = File.read(File.join(REPO_ROOT, 'LICENSE'))
    assert_includes content, "Dustin D. Trammell"
  end

  # TC-LIC-5: gemspec files include LICENSE
  def test_lic_5_gemspec_files_include_license
    spec = Gem::Specification.load(File.join(REPO_ROOT, 'cryptomnio.gemspec'))
    assert_includes spec.files, "LICENSE"
  end
end

# ============================================================================
# Cross-cutting regression tests
# ============================================================================
class TestRegression < Minitest::Test
  REPO_ROOT = File.expand_path('../..', __FILE__).freeze
  RUBY_BIN  = RbConfig.ruby

  # TC-REG-1: existing test_issues_6_7_8.rb still passes unmodified
  def test_reg_1_existing_suite_still_passes
    output = `#{RUBY_BIN.shellescape} #{File.join(REPO_ROOT, 'test', 'test_issues_6_7_8.rb').shellescape} 2>&1`
    assert $?.success?, "test_issues_6_7_8.rb failed. Output: #{output}"
    assert_match(/0 failures, 0 errors/, output, "Existing suite had failures/errors. Output: #{output}")
  end

  # TC-REG-2: full rake test passes
  # Guarded against recursive invocation because this test itself runs inside rake test.
  def test_reg_2_full_rake_test
    if ENV['CRYPTOMNIO_REG2_RUNNING']
      skip "Already inside the recursive rake test run"
    end
    output = `cd #{REPO_ROOT.shellescape} && CRYPTOMNIO_REG2_RUNNING=1 rake test 2>&1`
    assert $?.success?, "rake test failed. Output: #{output}"
    assert_match(/0 failures, 0 errors/, output, "rake test had failures/errors. Output: #{output}")
  end

  # TC-REG-3: ruby -c lib/cryptomnio.rb
  def test_reg_3_syntax_check_main
    output = `#{RUBY_BIN.shellescape} -c #{File.join(REPO_ROOT, 'lib', 'cryptomnio.rb').shellescape} 2>&1`
    assert $?.success?, "lib/cryptomnio.rb syntax check failed. Output: #{output}"
    assert_match(/Syntax OK/, output)
  end

  # TC-REG-4: ruby -c lib/cryptomnio/version.rb
  def test_reg_4_syntax_check_version
    output = `#{RUBY_BIN.shellescape} -c #{File.join(REPO_ROOT, 'lib', 'cryptomnio', 'version.rb').shellescape} 2>&1`
    assert $?.success?, "lib/cryptomnio/version.rb syntax check failed. Output: #{output}"
    assert_match(/Syntax OK/, output)
  end

  # TC-REG-5: gem build in scratch copy has no missing-file warnings for s.files
  def test_reg_5_gem_build_no_missing_files
    scratch = Dir.mktmpdir('cryptomnio_build')
    FileUtils.cp_r(File.join(REPO_ROOT, '.'), scratch)

    Dir.chdir(scratch) do
      output = `gem build cryptomnio.gemspec 2>&1`
      assert $?.success?, "gem build failed. Output: #{output}"

      refute_match(/lib\/cryptomnio\/version\.rb.*(does not exist|not found)/i, output)
      refute_match(/LICENSE.*(does not exist|not found)/i, output)
      refute_match(/lib\/cryptomnio\.rb.*(does not exist|not found)/i, output)
    end
  ensure
    FileUtils.rm_rf(scratch) if scratch
  end
end

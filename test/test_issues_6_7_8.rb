#!/usr/bin/env ruby
# frozen_string_literal: true

# Test suite for Issues #6, #7, #8
# Issue #6: Malformed query strings (leading &)
# Issue #7: Missing explicit require 'openssl'
# Issue #8: Missing rest-client runtime dependency in gemspec
#
# Run with: rake test  (or: ruby test/test_issues_6_7_8.rb)
# Requires: gem install minitest rest-client

require 'minitest/autorun'
require 'rubygems'
require 'shellwords'
require 'tempfile'

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
      venue:      "test_venue",
      accountid:  "test_account",
      venuekeyid: "test_venuekeyid"
    }
  }
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
# Shared assertion helper
# ============================================================================
module QueryStringAssertions
  def assert_valid_uriparams(uriparams, msg = "")
    if uriparams.nil?
      pass
    else
      refute uriparams.start_with?("&"),
        "#{msg}: uriparams must not start with '&', got: #{uriparams.inspect}"
      refute uriparams.include?("=&"),
        "#{msg}: uriparams must not contain '=&', got: #{uriparams.inspect}"
      refute uriparams.include?("&&"),
        "#{msg}: uriparams must not contain '&&', got: #{uriparams.inspect}"
      refute uriparams.empty?,
        "#{msg}: uriparams must be nil (not empty string) when no params"
    end
  end
end

# ============================================================================
# Issue #7 — Static checks
# ============================================================================
class TestIssue7Static < Minitest::Test
  LIB_FILE = File.expand_path('../../lib/cryptomnio.rb', __FILE__)

  # TC-7-S-1: File contains explicit openssl require (not commented out)
  def test_s1_explicit_openssl_require_present
    content = File.read(LIB_FILE)
    matches = content.lines.select { |l| l =~ /require.*openssl/i && l !~ /^\s*#/ }
    refute_empty matches, "lib/cryptomnio.rb must have an uncommented require for openssl"
  end

  # TC-7-S-2: require 'openssl' appears before first class definition
  def test_s2_openssl_require_before_first_class
    lines = File.readlines(LIB_FILE)
    openssl_line = lines.index { |l| l =~ /require.*openssl/i && l !~ /^\s*#/ }
    first_class   = lines.index { |l| l =~ /^\s*class\s/ }
    refute_nil openssl_line, "require 'openssl' must be present"
    refute_nil first_class,  "There must be at least one class definition"
    assert openssl_line < first_class,
      "require 'openssl' (line #{openssl_line + 1}) must appear before first class (line #{first_class + 1})"
  end

  # TC-7-S-3: All files in lib/ that use OpenSSL also have explicit require
  def test_s3_all_openssl_usages_have_explicit_require
    lib_dir = File.expand_path('../../lib', __FILE__)
    Dir.glob("#{lib_dir}/**/*.rb").each do |rb_file|
      content = File.read(rb_file)
      next unless content =~ /OpenSSL/
      has_require = content.lines.any? { |l| l =~ /require.*openssl/i && l !~ /^\s*#/ }
      assert has_require,
        "#{rb_file} uses OpenSSL but has no explicit require 'openssl'"
    end
  end
end

# ============================================================================
# Issue #7 — Functional: OpenSSL accessible via explicit require (isolated)
# ============================================================================
class TestIssue7Functional < Minitest::Test
  LIB_DIR  = File.expand_path('../../lib', __FILE__)
  RUBY_BIN = RbConfig.ruby

  # TC-7-F-1 and TC-7-F-2: Load cryptomnio with rest-client stubbed out;
  # OpenSSL::HMAC must still be available via the explicit require 'openssl'.
  # Uses a single-quoted heredoc so no interpolation happens in the outer process.
  def test_f1_f2_openssl_available_without_restclient_transitive_load
    script = <<~'RUBY'
      module Kernel
        alias_method :original_require, :require
        def require(path)
          return true if path == 'rest-client'
          original_require(path)
        end
      end
      $LOAD_PATH.unshift(ARGV[0])
      require 'cryptomnio'
      digest = OpenSSL::HMAC.digest('sha512', 'key', 'data')
      raise "Expected 64 bytes, got #{digest.bytesize}" unless digest.bytesize == 64
      puts 'PASS'
    RUBY

    tf = Tempfile.new(['tc7_f1_', '.rb'])
    begin
      tf.write(script)
      tf.flush
      output = `#{RUBY_BIN.shellescape} #{tf.path.shellescape} #{LIB_DIR.shellescape} 2>&1`
      assert $?.success?,
        "subprocess failed — openssl not explicitly required.\nOutput: #{output}"
      assert_match(/PASS/, output,
        "subprocess did not print PASS.\nOutput: #{output}")
    ensure
      tf.close
      tf.unlink
    end
  end

  # TC-7-F-3 and TC-7-F-4: HMAC is deterministic and matches reference value
  def test_f3_f4_hmac_deterministic_and_matches_reference
    require 'openssl'
    ref_raw = `echo -n 'GET/venues' | openssl dgst -sha512 -hmac 'secret' 2>/dev/null`.strip
    ref_hex = ref_raw.include?('=') ? ref_raw.split('=').last.strip : ref_raw

    ruby_result  = OpenSSL::HMAC.digest('sha512', 'secret', 'GET/venues')
    ruby_hex     = ruby_result.unpack1('H*')

    refute_empty ref_hex, "Could not compute shell reference HMAC"
    assert_equal ref_hex, ruby_hex,
      "Ruby HMAC-SHA512 output must match openssl dgst reference"

    ruby_result2 = OpenSSL::HMAC.digest('sha512', 'secret', 'GET/venues')
    assert_equal ruby_result, ruby_result2, "HMAC must be deterministic"
  end
end

# ============================================================================
# Issue #7 — Integration: auth_cryptomnio method
# ============================================================================
class TestIssue7Integration < Minitest::Test
  def setup
    @client = build_client
  end

  # TC-7-I-1: auth_cryptomnio returns non-nil string
  def test_i1_returns_non_nil_string
    result = @client.auth_cryptomnio(:get, "/venues")
    refute_nil result
    assert_instance_of String, result
    refute_empty result
  end

  # TC-7-I-2: Return value contains no newlines
  def test_i2_no_newlines_in_result
    result = @client.auth_cryptomnio(:get, "/venues")
    refute result.include?("\n"), "auth_cryptomnio result must not contain newlines"
  end

  # TC-7-I-3: Return value is valid Base64
  def test_i3_result_is_valid_base64
    require 'base64'
    result = @client.auth_cryptomnio(:get, "/venues")
    decoded = Base64.decode64(result)   # raises if invalid
    refute_nil decoded, "Base64.decode64 must not return nil"
  end

  # TC-7-I-4: Different method+path inputs produce different signatures
  def test_i4_different_inputs_produce_different_signatures
    sig1 = @client.auth_cryptomnio(:get,  "/venues")
    sig2 = @client.auth_cryptomnio(:post, "/venues")
    refute_equal sig1, sig2,
      "Different method+path must produce different HMAC signatures"
  end
end

# ============================================================================
# Issue #8 — Static gemspec verification
# ============================================================================
class TestIssue8Static < Minitest::Test
  GEMSPEC_PATH = File.expand_path('../../cryptomnio.gemspec', __FILE__)

  # TC-8-S-1: add_runtime_dependency present and uncommented
  def test_s1_runtime_dependency_uncommented
    content = File.read(GEMSPEC_PATH)
    matches = content.lines.select { |l| l =~ /add_runtime_dependency/ && l !~ /^\s*#/ }
    refute_empty matches,
      "cryptomnio.gemspec must have an uncommented add_runtime_dependency"
  end

  # TC-8-S-2: Dependency name is rest-client
  def test_s2_dependency_name_is_rest_client
    content = File.read(GEMSPEC_PATH)
    matches = content.lines.select { |l| l =~ /add_runtime_dependency/ && l !~ /^\s*#/ }
    assert matches.any? { |l| l.include?("rest-client") },
      "add_runtime_dependency must specify 'rest-client'"
  end

  # TC-8-S-3: Version constraint present (~> 2.1)
  def test_s3_version_constraint_present
    content = File.read(GEMSPEC_PATH)
    matches = content.lines.select do |l|
      l =~ /add_runtime_dependency.*rest-client/ && l !~ /^\s*#/
    end
    assert matches.any? { |l| l.include?("~> 2.1") },
      "add_runtime_dependency for rest-client must include '~> 2.1' constraint"
  end

  # TC-8-S-4: No commented-out rest-client runtime dependency lines remain
  def test_s4_no_commented_rest_client_dependency
    content = File.read(GEMSPEC_PATH)
    commented = content.lines.select do |l|
      l =~ /^\s*#.*add_runtime_dependency.*rest-client/
    end
    assert_empty commented,
      "No commented-out add_runtime_dependency lines for rest-client should remain"
  end
end

# ============================================================================
# Issue #8 — Gemspec loads without errors
# ============================================================================
class TestIssue8Load < Minitest::Test
  GEMSPEC_PATH = File.expand_path('../../cryptomnio.gemspec', __FILE__)

  def spec
    @spec ||= Gem::Specification.load(GEMSPEC_PATH)
  end

  # TC-8-L-1: Gemspec loads without exceptions
  def test_l1_gemspec_loads_cleanly
    loaded_spec = spec
    refute_nil loaded_spec, "Gem::Specification.load must return a non-nil spec"
  end

  # TC-8-L-2: Spec name is cryptomnio
  def test_l2_spec_name
    assert_equal "cryptomnio", spec.name
  end

  # TC-8-L-3: runtime_dependencies is not empty
  def test_l3_runtime_dependencies_not_empty
    refute_empty spec.runtime_dependencies,
      "gemspec must declare at least one runtime dependency"
  end

  # TC-8-L-4: rest-client in runtime dependency names
  def test_l4_rest_client_in_runtime_deps
    names = spec.runtime_dependencies.map(&:name)
    assert_includes names, "rest-client",
      "rest-client must be declared as a runtime dependency"
  end
end

# ============================================================================
# Issue #8 — Version constraint verification
# ============================================================================
class TestIssue8Version < Minitest::Test
  def dep
    @dep ||= Gem::Dependency.new("rest-client", "~> 2.1")
  end

  def test_v1_version_2_1_0_satisfied
    assert dep.match?("rest-client", "2.1.0"), "~> 2.1 must admit 2.1.0"
  end

  def test_v2_version_2_1_4_satisfied
    assert dep.match?("rest-client", "2.1.4"), "~> 2.1 must admit 2.1.4"
  end

  def test_v3_version_2_9_0_satisfied
    assert dep.match?("rest-client", "2.9.0"), "~> 2.1 must admit 2.9.0"
  end

  def test_v4_version_2_0_9_not_satisfied
    refute dep.match?("rest-client", "2.0.9"), "~> 2.1 must NOT admit 2.0.9"
  end

  def test_v5_version_3_0_0_not_satisfied
    refute dep.match?("rest-client", "3.0.0"), "~> 2.1 must NOT admit 3.0.0"
  end

  def test_v6_version_1_9_9_not_satisfied
    refute dep.match?("rest-client", "1.9.9"), "~> 2.1 must NOT admit 1.9.9"
  end
end

# ============================================================================
# Issue #6 — get_market_orderbook
# ============================================================================
class TestIssue6Orderbook < Minitest::Test
  include QueryStringAssertions

  def setup
    @client = build_client
  end

  # Stub _rest_call on the singleton and capture the uriparameters argument.
  # The stub is always cleaned up in ensure.
  def capture_params(market: "BTC-USD", side: nil, limit: nil)
    captured = nil
    @client.define_singleton_method(:_rest_call) do |*args|
      captured = args[3]
      {}
    end
    @client.get_market_orderbook(market: market, side: side, limit: limit)
    captured
  ensure
    @client.singleton_class.remove_method(:_rest_call) rescue nil
  end

  # TC-6-OB-1: nil, nil → nil
  def test_ob1_no_params_nil
    params = capture_params(side: nil, limit: nil)
    assert_nil params, "No params should produce nil uriparams, got: #{params.inspect}"
  end

  # TC-6-OB-2: side="buy" → "side=buy"
  def test_ob2_side_only
    params = capture_params(side: "buy", limit: nil)
    assert_valid_uriparams(params, "TC-6-OB-2")
    assert_equal "side=buy", params
  end

  # TC-6-OB-3: limit=10 → "limit=10"
  def test_ob3_limit_only
    params = capture_params(side: nil, limit: 10)
    assert_valid_uriparams(params, "TC-6-OB-3")
    assert_equal "limit=10", params
  end

  # TC-6-OB-4: side="buy", limit=10 → "side=buy&limit=10"
  def test_ob4_both_params
    params = capture_params(side: "buy", limit: 10)
    assert_valid_uriparams(params, "TC-6-OB-4")
    assert_equal "side=buy&limit=10", params
  end

  # TC-6-OB-5: BVA side="sell", limit=1
  def test_ob5_sell_limit1
    params = capture_params(side: "sell", limit: 1)
    assert_valid_uriparams(params, "TC-6-OB-5")
    assert_equal "side=sell&limit=1", params
  end

  # TC-6-OB-6: side="sell", limit=nil
  def test_ob6_sell_no_limit
    params = capture_params(side: "sell", limit: nil)
    assert_valid_uriparams(params, "TC-6-OB-6")
    assert_equal "side=sell", params
  end

  # TC-6-OB-NEG-1: side only must not produce "&side=buy"
  def test_ob_neg1_no_leading_ampersand_side
    params = capture_params(side: "buy", limit: nil)
    refute_equal "&side=buy", params, "Old bug: leading & on side=buy"
    refute params&.start_with?("&"), "uriparams must not start with &"
  end

  # TC-6-OB-NEG-2: limit only must not produce "&limit=10"
  def test_ob_neg2_no_leading_ampersand_limit
    params = capture_params(side: nil, limit: 10)
    refute_equal "&limit=10", params, "Old bug: leading & on limit=10"
    refute params&.start_with?("&"), "uriparams must not start with &"
  end

  # TC-6-OB-NEG-3: no params → nil, not empty string
  def test_ob_neg3_no_params_not_empty_string
    params = capture_params(side: nil, limit: nil)
    refute_equal "", params, "No params should produce nil, not empty string"
  end
end

# ============================================================================
# Issue #6 — get_market_orderbook_depth_price
# ============================================================================
class TestIssue6OrderbookDepthPrice < Minitest::Test
  include QueryStringAssertions

  def setup
    @client = build_client
  end

  def capture_params(market: "BTC-USD", side: nil, volume: nil, cumulative: nil)
    captured = nil
    @client.define_singleton_method(:_rest_call) do |*args|
      captured = args[3]
      {}
    end
    @client.get_market_orderbook_depth_price(
      market: market, side: side, volume: volume, cumulative: cumulative
    )
    captured
  ensure
    @client.singleton_class.remove_method(:_rest_call) rescue nil
  end

  # TC-6-OBP-1: all nil → nil
  def test_obp1_all_nil
    assert_nil capture_params
  end

  # TC-6-OBP-2: side="buy" → "side=buy"
  def test_obp2_side_only
    params = capture_params(side: "buy")
    assert_valid_uriparams(params, "TC-6-OBP-2")
    assert_equal "side=buy", params
  end

  # TC-6-OBP-3: volume=100.5 → "volume=100.500000"
  def test_obp3_volume_only
    params = capture_params(volume: 100.5)
    assert_valid_uriparams(params, "TC-6-OBP-3")
    assert_equal "volume=100.500000", params
  end

  # TC-6-OBP-4: cumulative=true → "cumulative=true"
  def test_obp4_cumulative_true
    params = capture_params(cumulative: true)
    assert_valid_uriparams(params, "TC-6-OBP-4")
    assert_equal "cumulative=true", params
  end

  # TC-6-OBP-5: cumulative=false → "cumulative=false" (critical edge case: false != nil)
  def test_obp5_cumulative_false_critical_edge_case
    params = capture_params(cumulative: false)
    assert_valid_uriparams(params, "TC-6-OBP-5")
    assert_equal "cumulative=false", params,
      "cumulative=false is NOT nil — must appear in query string"
  end

  # TC-6-OBP-6: side="buy", volume=100.5 → "side=buy&volume=100.500000"
  def test_obp6_side_and_volume
    params = capture_params(side: "buy", volume: 100.5)
    assert_valid_uriparams(params, "TC-6-OBP-6")
    assert_equal "side=buy&volume=100.500000", params
  end

  # TC-6-OBP-7: side="buy", cumulative=true → "side=buy&cumulative=true"
  def test_obp7_side_and_cumulative_true
    params = capture_params(side: "buy", cumulative: true)
    assert_valid_uriparams(params, "TC-6-OBP-7")
    assert_equal "side=buy&cumulative=true", params
  end

  # TC-6-OBP-8: volume=100.5, cumulative=true → "volume=100.500000&cumulative=true"
  def test_obp8_volume_and_cumulative_true
    params = capture_params(volume: 100.5, cumulative: true)
    assert_valid_uriparams(params, "TC-6-OBP-8")
    assert_equal "volume=100.500000&cumulative=true", params
  end

  # TC-6-OBP-9: all three → "side=buy&volume=100.500000&cumulative=true"
  def test_obp9_all_three
    params = capture_params(side: "buy", volume: 100.5, cumulative: true)
    assert_valid_uriparams(params, "TC-6-OBP-9")
    assert_equal "side=buy&volume=100.500000&cumulative=true", params
  end

  # TC-6-OBP-10: BVA volume=0.0, cumulative=false
  def test_obp10_bva_zero_volume_cumulative_false
    params = capture_params(side: "sell", volume: 0.0, cumulative: false)
    assert_valid_uriparams(params, "TC-6-OBP-10")
    assert_equal "side=sell&volume=0.000000&cumulative=false", params
  end
end

# ============================================================================
# Issue #6 — get_market_orderbook_depth_volume
# ============================================================================
class TestIssue6OrderbookDepthVolume < Minitest::Test
  include QueryStringAssertions

  def setup
    @client = build_client
  end

  def capture_params(market: "BTC-USD", side: nil, price: nil, cumulative: nil)
    captured = nil
    @client.define_singleton_method(:_rest_call) do |*args|
      captured = args[3]
      {}
    end
    @client.get_market_orderbook_depth_volume(
      market: market, side: side, price: price, cumulative: cumulative
    )
    captured
  ensure
    @client.singleton_class.remove_method(:_rest_call) rescue nil
  end

  # TC-6-OBV-1: all nil → nil
  def test_obv1_all_nil
    assert_nil capture_params
  end

  # TC-6-OBV-2: side="buy" → "side=buy"
  def test_obv2_side_only
    params = capture_params(side: "buy")
    assert_valid_uriparams(params, "TC-6-OBV-2")
    assert_equal "side=buy", params
  end

  # TC-6-OBV-3: price=50000.0 → "price=50000.000000"
  def test_obv3_price_only
    params = capture_params(price: 50000.0)
    assert_valid_uriparams(params, "TC-6-OBV-3")
    assert_equal "price=50000.000000", params
  end

  # TC-6-OBV-4: cumulative=true → "cumulative=true"
  def test_obv4_cumulative_true
    params = capture_params(cumulative: true)
    assert_valid_uriparams(params, "TC-6-OBV-4")
    assert_equal "cumulative=true", params
  end

  # TC-6-OBV-5: cumulative=false → "cumulative=false"
  def test_obv5_cumulative_false
    params = capture_params(cumulative: false)
    assert_valid_uriparams(params, "TC-6-OBV-5")
    assert_equal "cumulative=false", params
  end

  # TC-6-OBV-6: side="buy", price=50000.0 → "side=buy&price=50000.000000"
  def test_obv6_side_and_price
    params = capture_params(side: "buy", price: 50000.0)
    assert_valid_uriparams(params, "TC-6-OBV-6")
    assert_equal "side=buy&price=50000.000000", params
  end

  # TC-6-OBV-7: side="buy", cumulative=true → "side=buy&cumulative=true"
  def test_obv7_side_and_cumulative_true
    params = capture_params(side: "buy", cumulative: true)
    assert_valid_uriparams(params, "TC-6-OBV-7")
    assert_equal "side=buy&cumulative=true", params
  end

  # TC-6-OBV-8: price=50000.0, cumulative=true → "price=50000.000000&cumulative=true"
  def test_obv8_price_and_cumulative_true
    params = capture_params(price: 50000.0, cumulative: true)
    assert_valid_uriparams(params, "TC-6-OBV-8")
    assert_equal "price=50000.000000&cumulative=true", params
  end

  # TC-6-OBV-9: all three → "side=buy&price=50000.000000&cumulative=true"
  def test_obv9_all_three
    params = capture_params(side: "buy", price: 50000.0, cumulative: true)
    assert_valid_uriparams(params, "TC-6-OBV-9")
    assert_equal "side=buy&price=50000.000000&cumulative=true", params
  end

  # TC-6-OBV-10: BVA price=0.01, cumulative=false
  def test_obv10_bva_small_price_cumulative_false
    params = capture_params(price: 0.01, cumulative: false)
    assert_valid_uriparams(params, "TC-6-OBV-10")
    assert_equal "price=0.010000&cumulative=false", params
  end
end

# ============================================================================
# Issue #6 — get_market_trades
# ============================================================================
class TestIssue6Trades < Minitest::Test
  include QueryStringAssertions

  def setup
    @client = build_client
  end

  def capture_params(market: "BTC-USD", limit: nil)
    captured = nil
    # get_market_trades has a retry loop; stub returns a non-empty array to avoid retry
    @client.define_singleton_method(:_rest_call) do |*args|
      captured = args[3]
      [{ "price" => "100", "qty" => "1" }]
    end
    @client.get_market_trades(market: market, limit: limit)
    captured
  ensure
    @client.singleton_class.remove_method(:_rest_call) rescue nil
  end

  # TC-6-TR-1: nil → nil
  def test_tr1_no_limit_nil
    params = capture_params(limit: nil)
    assert_nil params, "No limit should produce nil uriparams, got: #{params.inspect}"
  end

  # TC-6-TR-2: limit=10 → "limit=10"
  def test_tr2_limit_10
    params = capture_params(limit: 10)
    assert_valid_uriparams(params, "TC-6-TR-2")
    assert_equal "limit=10", params
  end

  # TC-6-TR-3: BVA limit=1 → "limit=1"
  def test_tr3_limit_1_bva
    params = capture_params(limit: 1)
    assert_valid_uriparams(params, "TC-6-TR-3")
    assert_equal "limit=1", params
  end

  # TC-6-TR-4: limit=100 → "limit=100"
  def test_tr4_limit_100
    params = capture_params(limit: 100)
    assert_valid_uriparams(params, "TC-6-TR-4")
    assert_equal "limit=100", params
  end

  # TC-6-TR-5: BVA limit=0 — Ruby 0 is truthy; fix preserves this behavior
  def test_tr5_bva_limit_0_truthy
    params = capture_params(limit: 0)
    assert_valid_uriparams(params, "TC-6-TR-5")
    assert_equal "limit=0", params,
      "limit=0 is truthy in Ruby — must produce 'limit=0', not nil"
  end

  # TC-6-TR-NEG-1: limit=10 must not produce "&limit=10"
  def test_tr_neg1_no_leading_ampersand
    params = capture_params(limit: 10)
    refute_equal "&limit=10", params, "Old bug: leading & on limit=10"
    refute params&.start_with?("&"), "uriparams must not start with &"
  end

  # TC-6-TR-NEG-2: no limit → nil, not empty string
  def test_tr_neg2_no_limit_not_empty_string
    params = capture_params(limit: nil)
    refute_equal "", params, "No limit should produce nil, not empty string"
  end
end

# ============================================================================
# Cross-cutting: URI assembly regression (TC-X)
# ============================================================================
class TestCrossCuttingURIRegression < Minitest::Test
  def setup
    @client = build_client
  end

  # Stub _rest_call for the duration of the block, capture uriparameters
  def capture_params_for
    captured = nil
    @client.define_singleton_method(:_rest_call) do |*args|
      captured = args[3]
      [{ "price" => "1", "qty" => "1" }]
    end
    yield
    captured
  ensure
    @client.singleton_class.remove_method(:_rest_call) rescue nil
  end

  def assert_no_leading_ampersand(params, case_id)
    return if params.nil?
    refute params.start_with?("&"),
      "#{case_id}: URI params must not start with '&', got: #{params.inspect}"
  end

  def assert_uri_fragment(params, expected_fragment, case_id)
    if expected_fragment.nil?
      assert_nil params,
        "#{case_id}: Expected no query string, got: #{params.inspect}"
    else
      assert_equal expected_fragment, params,
        "#{case_id}: Expected '#{expected_fragment}', got: #{params.inspect}"
    end
  end

  # TC-X-1: get_market_orderbook no side/limit → no query string
  def test_x1_orderbook_no_params
    params = capture_params_for { @client.get_market_orderbook(market: "BTC-USD") }
    assert_uri_fragment(params, nil, "TC-X-1")
    assert_no_leading_ampersand(params, "TC-X-1")
  end

  # TC-X-2: get_market_orderbook with side="buy" → "side=buy"
  def test_x2_orderbook_side_buy
    params = capture_params_for { @client.get_market_orderbook(market: "BTC-USD", side: "buy") }
    assert_uri_fragment(params, "side=buy", "TC-X-2")
    assert_no_leading_ampersand(params, "TC-X-2")
  end

  # TC-X-3: get_market_orderbook with limit=5 → "limit=5"
  def test_x3_orderbook_limit_5
    params = capture_params_for { @client.get_market_orderbook(market: "BTC-USD", limit: 5) }
    assert_uri_fragment(params, "limit=5", "TC-X-3")
    assert_no_leading_ampersand(params, "TC-X-3")
  end

  # TC-X-4: get_market_orderbook side="buy", limit=5 → "side=buy&limit=5"
  def test_x4_orderbook_side_and_limit
    params = capture_params_for { @client.get_market_orderbook(market: "BTC-USD", side: "buy", limit: 5) }
    assert_uri_fragment(params, "side=buy&limit=5", "TC-X-4")
    assert_no_leading_ampersand(params, "TC-X-4")
  end

  # TC-X-5: get_market_orderbook_depth_price side="buy" → "side=buy"
  def test_x5_depth_price_side_buy
    params = capture_params_for { @client.get_market_orderbook_depth_price(market: "BTC-USD", side: "buy") }
    assert_uri_fragment(params, "side=buy", "TC-X-5")
    assert_no_leading_ampersand(params, "TC-X-5")
  end

  # TC-X-6: get_market_orderbook_depth_price cumulative=false → "cumulative=false"
  def test_x6_depth_price_cumulative_false
    params = capture_params_for { @client.get_market_orderbook_depth_price(market: "BTC-USD", cumulative: false) }
    assert_uri_fragment(params, "cumulative=false", "TC-X-6")
    assert_no_leading_ampersand(params, "TC-X-6")
  end

  # TC-X-7: get_market_orderbook_depth_volume price=50000.0 → "price=50000.000000"
  def test_x7_depth_volume_price
    params = capture_params_for { @client.get_market_orderbook_depth_volume(market: "BTC-USD", price: 50000.0) }
    assert_uri_fragment(params, "price=50000.000000", "TC-X-7")
    assert_no_leading_ampersand(params, "TC-X-7")
  end

  # TC-X-8: get_market_trades limit=20 → "limit=20"
  def test_x8_trades_limit_20
    params = capture_params_for { @client.get_market_trades(market: "BTC-USD", limit: 20) }
    assert_uri_fragment(params, "limit=20", "TC-X-8")
    assert_no_leading_ampersand(params, "TC-X-8")
  end

  # TC-X-9: get_market_trades no limit → nil
  def test_x9_trades_no_limit
    params = capture_params_for { @client.get_market_trades(market: "BTC-USD") }
    assert_uri_fragment(params, nil, "TC-X-9")
    assert_no_leading_ampersand(params, "TC-X-9")
  end
end

#!/usr/bin/env ruby
# frozen_string_literal: true

# Test suite for Issue #27 — TLS client-certificate (mTLS) authentication.
#
# Run with: rake test  (or: ruby test/test_issue_27.rb)
# Requires: gem install minitest rest-client

require 'minitest/autorun'
require 'rubygems'
require 'openssl'
require 'tmpdir'
require 'fileutils'
require 'stringio'

$LOAD_PATH.unshift(File.expand_path('../../lib', __FILE__)) unless
  $LOAD_PATH.include?(File.expand_path('../../lib', __FILE__))
require 'cryptomnio'

# ----------------------------------------------------------------------------
# Shared fixtures generated at test time
# ----------------------------------------------------------------------------
module Issue27
  # In-memory PKI fixture produced at runtime.
  Pki = Struct.new(:dir, :ca_cert_path, :cert_path, :key_path, :key_object,
                   :cert_object, :encrypted_key_path, :passphrase,
                   :mismatched_key_path, keyword_init: true)

  module MtlsFixtures
    @dirs = []

    def self.dirs
      @dirs
    end

    # Build a throwaway self-signed CA and one leaf cert/key signed by it.
    def self.build(label:, passphrase: "test-pass-#{label}")
      dir = Dir.mktmpdir("mtls-fixture-#{label}-")
      @dirs << dir

      ca_key  = OpenSSL::PKey::RSA.new(2048)
      ca_name = OpenSSL::X509::Name.parse("/CN=Cryptomnio #{label.capitalize} CA")
      ca_cert = OpenSSL::X509::Certificate.new.tap do |c|
        c.version = 2; c.serial = 1; c.subject = ca_name; c.issuer = ca_name
        c.public_key = ca_key.public_key
        c.not_before = Time.now - 3600
        c.not_after  = Time.now + 3600 * 24 * 365
        c.sign(ca_key, OpenSSL::Digest.new('SHA256'))
      end

      leaf_key  = OpenSSL::PKey::RSA.new(2048)
      leaf_name = OpenSSL::X509::Name.parse("/CN=test-client-#{label}@example.invalid")
      leaf_cert = OpenSSL::X509::Certificate.new.tap do |c|
        c.version = 2; c.serial = 2; c.subject = leaf_name; c.issuer = ca_cert.subject
        c.public_key = leaf_key.public_key
        c.not_before = Time.now - 3600
        c.not_after  = Time.now + 3600 * 24 * 365
        c.sign(ca_key, OpenSSL::Digest.new('SHA256'))
      end

      other_key = OpenSSL::PKey::RSA.new(2048)

      ca_path   = File.join(dir, "ca.pem");   File.write(ca_path, ca_cert.to_pem)
      cert_path = File.join(dir, "cert.pem"); File.write(cert_path, leaf_cert.to_pem)
      key_path  = File.join(dir, "key.pem");  File.write(key_path, leaf_key.to_pem)
      enc_path  = File.join(dir, "key.enc.pem")
      File.write(enc_path, leaf_key.to_pem(OpenSSL::Cipher.new("AES-256-CBC"), passphrase))
      mismatched_path = File.join(dir, "other_key.pem")
      File.write(mismatched_path, other_key.to_pem)

      Pki.new(dir: dir, ca_cert_path: ca_path, cert_path: cert_path,
              key_path: key_path, key_object: leaf_key, cert_object: leaf_cert,
              encrypted_key_path: enc_path, passphrase: passphrase,
              mismatched_key_path: mismatched_path)
    end

    def self.garbage_file(dir)
      tap_write(dir, "garbage.pem", "this is not PEM data at all\n")
    end

    def self.empty_file(dir)
      tap_write(dir, "empty.pem", "")
    end

    def self.tap_write(dir, name, content)
      path = File.join(dir, name)
      File.write(path, content)
      path
    end

    # A second self-signed cert used only as an extra PEM block in chain files.
    def self.extra_cert(label:)
      key  = OpenSSL::PKey::RSA.new(2048)
      name = OpenSSL::X509::Name.parse("/CN=Cryptomnio #{label.capitalize} Intermediate (fixture)")
      OpenSSL::X509::Certificate.new.tap do |c|
        c.version = 2; c.serial = 9; c.subject = name; c.issuer = name
        c.public_key = key.public_key
        c.not_before = Time.now - 3600
        c.not_after  = Time.now + 3600 * 24 * 365
        c.sign(key, OpenSSL::Digest.new('SHA256'))
      end
    end

    def self.chain_cert_path(pki, extra)
      path = File.join(pki.dir, "chain_cert.pem")
      File.write(path, pki.cert_object.to_pem + extra.to_pem)
      path
    end

    def self.chain_ca_path(pki, extra)
      path = File.join(pki.dir, "chain_ca.pem")
      File.write(path, File.read(pki.ca_cert_path) + extra.to_pem)
      path
    end

    def self.build_expired(label:)
      dir = Dir.mktmpdir("mtls-fixture-#{label}-expired-")
      @dirs << dir
      ca_key  = OpenSSL::PKey::RSA.new(2048)
      ca_name = OpenSSL::X509::Name.parse("/CN=Cryptomnio #{label.capitalize} CA (expired-fixture)")
      ca_cert = OpenSSL::X509::Certificate.new.tap do |c|
        c.version = 2; c.serial = 1; c.subject = ca_name; c.issuer = ca_name
        c.public_key = ca_key.public_key
        c.not_before = Time.now - 3600 * 24 * 1000
        c.not_after  = Time.now + 3600 * 24 * 365
        c.sign(ca_key, OpenSSL::Digest.new('SHA256'))
      end
      leaf_key = OpenSSL::PKey::RSA.new(2048)
      leaf_cert = OpenSSL::X509::Certificate.new.tap do |c|
        c.version = 2; c.serial = 2
        c.subject = OpenSSL::X509::Name.parse("/CN=test-client-#{label}-expired@example.invalid")
        c.issuer = ca_cert.subject
        c.public_key = leaf_key.public_key
        c.not_before = Time.now - 3600 * 24 * 730
        c.not_after  = Time.now - 3600 * 24 * 365
        c.sign(ca_key, OpenSSL::Digest.new('SHA256'))
      end
      cert_path = File.join(dir, "expired_cert.pem"); File.write(cert_path, leaf_cert.to_pem)
      key_path  = File.join(dir, "expired_key.pem");  File.write(key_path, leaf_key.to_pem)
      [cert_path, key_path]
    end
  end

  GEB = MtlsFixtures.build(label: "geb")
  NUT = MtlsFixtures.build(label: "nut")
  GEB_CHAIN_CERT_PATH = MtlsFixtures.chain_cert_path(GEB, MtlsFixtures.extra_cert(label: "geb"))
  GEB_CHAIN_CA_PATH   = MtlsFixtures.chain_ca_path(GEB, MtlsFixtures.extra_cert(label: "geb-root2"))
  EXPIRED_CERT_PATH, EXPIRED_KEY_PATH = MtlsFixtures.build_expired(label: "geb")

  Minitest.after_run do
    MtlsFixtures.dirs.each do |d|
      FileUtils.remove_entry(d) rescue nil
    end
  end

  # A fragment of the fixture private key used as a canary for log leakage.
  # It is taken from the middle of the PEM body so it is not a header line.
  KEY_NEEDLE = GEB.key_object.to_pem.lines[3].strip[0, 40]

  # Stub config for construction-time tests; matches the shape used by the
  # existing test suite but keeps credentials deterministic.
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

  # Fake RestClient response object yielded to the request block.
  # It defines #to_str so JSON.parse accepts it as a string source.
  FakeResponse = Struct.new(:code, :body) do
    def to_s
      body
    end

    def to_str
      body
    end
  end

  # Fake RestClient request object so the $DEBUG block in _rest_call can log
  # method/URI/headers without touching real request state.
  FakeRequest = Struct.new(:method, :uri, :headers)

  # Records every call made to RestClient::Request.execute and drives the
  # response sequence so retry paths can be tested without network I/O.
  class ExecuteSpy
    attr_reader :calls

    def initialize(responses)
      @responses = responses.dup
      @calls = []
    end

    # RestClient::Request.execute receives a positional options hash, so the
    # spy must accept that shape rather than keyword arguments.
    def call(args = {}, &block)
      @calls << args
      response = @responses.shift || FakeResponse.new(200, '{"body":{}}')
      request = FakeRequest.new(args[:method], args[:url], args[:headers])
      block.call(response, request, nil)
    end
  end

  module Helpers
    # Build a real client from STUB_CONFIG plus optional mTLS options.
    def build_client(ssl: {})
      config = STUB_CONFIG.merge(ssl)
      config[:contexts] = { test: STUB_CONFIG[:contexts][:test].dup }
      Cryptomnio::REST::Client.new do |c|
        c.config = config
      end
    end

    # Stub RestClient::Request.execute for the duration of the block.
    def with_execute_stub(responses)
      spy = ExecuteSpy.new(responses)
      RestClient::Request.define_singleton_method(:execute, &spy.method(:call))
      begin
        yield spy
      ensure
        RestClient::Request.singleton_class.remove_method(:execute) rescue nil
      end
    end

    # Count reads of specific paths while still forwarding to File.read.
    def with_file_read_counter(paths)
      counts = Hash.new(0)
      original = File.method(:read)
      File.define_singleton_method(:read) do |*args|
        counts[args[0]] += 1 if paths.include?(args[0])
        original.call(*args)
      end
      begin
        yield counts
      ensure
        File.singleton_class.remove_method(:read) rescue nil
      end
    end

    # Capture $stdout in a StringIO and return the accumulated text.
    def capture_stdout
      old_stdout = $stdout
      $stdout = StringIO.new
      begin
        yield
        $stdout.string
      ensure
        $stdout = old_stdout
      end
    end

    # Asserts that the captured text contains no private key material.
    def refute_key_material_leak(output, msg)
      refute_includes output, "BEGIN PRIVATE KEY", "#{msg}: leaked PRIVATE KEY header"
      refute_includes output, "BEGIN RSA PRIVATE KEY", "#{msg}: leaked RSA PRIVATE KEY header"
      refute_includes output, "BEGIN ENCRYPTED PRIVATE KEY", "#{msg}: leaked ENCRYPTED PRIVATE KEY header"
      refute_includes output, KEY_NEEDLE, "#{msg}: leaked raw private-key body"
      refute_includes output, "#<OpenSSL::PKey::RSA", "#{msg}: inspected key object"
    end
  end

  # ----------------------------------------------------------------------------
  # Section 1 — Happy path & backward compatibility
  # ----------------------------------------------------------------------------
  class TestIssue27HappyPath < Minitest::Test
    include Helpers

    # TC-27-1: cert + key + CA are forwarded as OpenSSL objects / path string.
    def test_tc_27_1_cert_key_ca_forwarded
      client = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path,
        ssl_ca_file:     GEB.ca_cert_path
      })

      with_execute_stub([FakeResponse.new(200, '{"body":{"venues":[]}}')]) do |spy|
        result = client.get_venues
        assert_equal({"venues" => []}, result)

        assert_equal 1, spy.calls.length
        call = spy.calls.first
        assert_instance_of OpenSSL::X509::Certificate, call[:ssl_client_cert]
        assert_equal GEB.cert_object.to_der, call[:ssl_client_cert].to_der
        assert_instance_of OpenSSL::PKey::RSA, call[:ssl_client_key]
        assert_equal GEB.key_object.to_der, call[:ssl_client_key].to_der
        assert_equal GEB.ca_cert_path, call[:ssl_ca_file]
      end
    end

    # TC-27-2: cert + key without CA omits ssl_ca_file entirely.
    def test_tc_27_2_cert_key_no_ca
      client = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path
      })

      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        client.get_venues
        call = spy.calls.first
        assert call.key?(:ssl_client_cert)
        assert call.key?(:ssl_client_key)
        refute call.key?(:ssl_ca_file)
      end
    end

    # TC-27-3: no mTLS config leaves RestClient kwargs byte-identical.
    def test_tc_27_3_no_ssl_kwargs_unchanged
      client = build_client

      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        client.get_venues
        call = spy.calls.first

        # The Sign header is deterministic; build the expected kwargs from the
        # captured headers so the comparison does not hardcode a signature.
        expected = {
          method:  :get,
          url:     "https://api.cryptomnio.com/venues",
          headers: call[:headers],
          payload: nil
        }
        assert_equal expected, call
        assert_equal ["Access-Key", "Sign"], call[:headers].keys.sort
      end
    end

    # TC-27-4: construction succeeds with no new required parameters.
    def test_tc_27_4_construction_without_ssl
      client = build_client
      refute_nil client
    end

    # TC-27-5: CA-only config forwards ssl_ca_file and no client cert.
    def test_tc_27_5_ca_only_forwards_ca
      client = build_client(ssl: { ssl_ca_file: GEB.ca_cert_path })

      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        client.get_venues
        call = spy.calls.first
        assert_equal GEB.ca_cert_path, call[:ssl_ca_file]
        refute call.key?(:ssl_client_cert)
        refute call.key?(:ssl_client_key)
      end
    end

    # TC-27-6: CA-only config does not trigger the cert/key pairing error.
    def test_tc_27_6_ca_only_no_pairing_error
      client = build_client(ssl: { ssl_ca_file: GEB.ca_cert_path })
      refute_nil client
    end

    # TC-27-7: chain files keep the leaf PEM block as the client cert.
    def test_tc_27_7_chain_file_uses_leaf
      client = build_client(ssl: {
        ssl_client_cert: GEB_CHAIN_CERT_PATH,
        ssl_client_key:  GEB.key_path,
        ssl_ca_file:     GEB_CHAIN_CA_PATH
      })

      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        client.get_venues
        call = spy.calls.first
        assert_equal GEB.cert_object.to_der, call[:ssl_client_cert].to_der
        assert call[:ssl_client_cert].check_private_key(call[:ssl_client_key])
        assert_equal GEB_CHAIN_CA_PATH, call[:ssl_ca_file]
      end
    end

    # TC-27-8: expired cert is not rejected locally.
    def test_tc_27_8_expired_cert_not_rejected
      client = build_client(ssl: {
        ssl_client_cert: EXPIRED_CERT_PATH,
        ssl_client_key:  EXPIRED_KEY_PATH
      })

      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        client.get_venues
        call = spy.calls.first
        assert_instance_of OpenSSL::X509::Certificate, call[:ssl_client_cert]
      end
    end
  end

  # ----------------------------------------------------------------------------
  # Section 2 — Fail-early validation
  # ----------------------------------------------------------------------------
  class TestIssue27Validation < Minitest::Test
    include Helpers

    # TC-27-10: only cert configured raises.
    def test_tc_27_10_cert_only_raises
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_cert: GEB.cert_path })
      end
      assert_match(/ssl_client_cert/, err.message)
      assert_match(/ssl_client_key/, err.message)
    end

    # TC-27-11: only key configured raises.
    def test_tc_27_11_key_only_raises
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_key: GEB.key_path })
      end
      assert_match(/ssl_client_cert/, err.message)
      assert_match(/ssl_client_key/, err.message)
    end

    # TC-27-12: missing cert file names the path.
    def test_tc_27_12_missing_cert_file
      missing = File.join(GEB.dir, "does-not-exist.pem")
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_cert: missing, ssl_client_key: GEB.key_path })
      end
      assert_match(/ssl_client_cert/, err.message)
      assert_match(/does-not-exist\.pem/, err.message)
    end

    # TC-27-13: missing key file names the path.
    def test_tc_27_13_missing_key_file
      missing = File.join(GEB.dir, "does-not-exist.pem")
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_cert: GEB.cert_path, ssl_client_key: missing })
      end
      assert_match(/ssl_client_key/, err.message)
      assert_match(/does-not-exist\.pem/, err.message)
    end

    # TC-27-14: missing CA file is validated at construction.
    def test_tc_27_14_missing_ca_file
      missing = File.join(GEB.dir, "does-not-exist.pem")
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert: GEB.cert_path,
          ssl_client_key:  GEB.key_path,
          ssl_ca_file:     missing
        })
      end
      assert_match(/ssl_ca_file/, err.message)
      assert_match(/does-not-exist\.pem/, err.message)
    end

    # TC-27-15: garbage cert file raises without leaking contents.
    def test_tc_27_15_garbage_cert
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert: MtlsFixtures.garbage_file(GEB.dir),
          ssl_client_key:  GEB.key_path
        })
      end
      assert_match(/ssl_client_cert/, err.message)
      refute_match(/not PEM data/, err.message)
    end

    # TC-27-16: garbage key file raises without leaking contents.
    def test_tc_27_16_garbage_key
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert: GEB.cert_path,
          ssl_client_key:  MtlsFixtures.garbage_file(GEB.dir)
        })
      end
      assert_match(/ssl_client_key/, err.message)
      refute_match(/not PEM data/, err.message)
    end

    # TC-27-17: mismatched cert/key pair raises a distinct error.
    def test_tc_27_17_mismatched_key
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert: GEB.cert_path,
          ssl_client_key:  GEB.mismatched_key_path
        })
      end
      assert_match(/does not match/, err.message)
      refute_match(/BEGIN/, err.message)
    end

    # TC-27-18: cert file supplied as key path raises a key parse error.
    def test_tc_27_18_cert_as_key
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert: GEB.cert_path,
          ssl_client_key:  GEB.cert_path
        })
      end
      assert_match(/ssl_client_key/, err.message)
    end

    # TC-27-19: empty key file is rejected, not treated as absent.
    def test_tc_27_19_empty_key_file
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert: GEB.cert_path,
          ssl_client_key:  MtlsFixtures.empty_file(GEB.dir)
        })
      end
      assert_match(/ssl_client_key/, err.message)
    end
  end

  # ----------------------------------------------------------------------------
  # Section 3 — Passphrase handling
  # ----------------------------------------------------------------------------
  class TestIssue27Passphrase < Minitest::Test
    include Helpers

    # TC-27-20: encrypted key loads with the correct passphrase.
    def test_tc_27_20_encrypted_key_with_passphrase
      client = build_client(ssl: {
        ssl_client_cert:          GEB.cert_path,
        ssl_client_key:           GEB.encrypted_key_path,
        ssl_client_key_passphrase: GEB.passphrase
      })

      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        client.get_venues
        assert_equal GEB.key_object.to_der, spy.calls.first[:ssl_client_key].to_der
      end
    end

    # TC-27-21: encrypted key without passphrase raises a specific message.
    def test_tc_27_21_encrypted_key_missing_passphrase
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert: GEB.cert_path,
          ssl_client_key:  GEB.encrypted_key_path
        })
      end
      assert_match(/encrypted/, err.message)
      assert_match(/passphrase required/, err.message)
    end

    # TC-27-22: wrong passphrase does not leak the attempt.
    def test_tc_27_22_wrong_passphrase_no_leak
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert:          GEB.cert_path,
          ssl_client_key:           GEB.encrypted_key_path,
          ssl_client_key_passphrase: "definitely-wrong"
        })
      end
      refute_match(/definitely-wrong/, err.message)
      refute_match(/BEGIN/, err.message)
    end

    # TC-27-23: passphrase supplied with an unencrypted key is harmless.
    def test_tc_27_23_unencrypted_key_with_passphrase
      client = build_client(ssl: {
        ssl_client_cert:          GEB.cert_path,
        ssl_client_key:           GEB.key_path,
        ssl_client_key_passphrase: "harmless"
      })
      refute_nil client
    end

    # TC-27-24: empty-string passphrase is treated as absent.
    def test_tc_27_24_empty_passphrase_treated_missing
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert:          GEB.cert_path,
          ssl_client_key:           GEB.encrypted_key_path,
          ssl_client_key_passphrase: ""
        })
      end
      assert_match(/encrypted/, err.message)
      assert_match(/passphrase required/, err.message)
    end
  end

  # ----------------------------------------------------------------------------
  # Section 4 — Wrong-type / malformed config values
  # ----------------------------------------------------------------------------
  class TestIssue27TypeErrors < Minitest::Test
    include Helpers

    # TC-27-30: integer cert path raises a type error naming the field.
    def test_tc_27_30_cert_path_integer
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_cert: 42, ssl_client_key: GEB.key_path })
      end
      assert_match(/ssl_client_cert/, err.message)
      assert_match(/non-empty String path/, err.message)
    end

    # TC-27-31: explicit nil cert with key present is "key only".
    def test_tc_27_31_cert_path_nil_with_key
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_cert: nil, ssl_client_key: GEB.key_path })
      end
      assert_match(/ssl_client_cert.*ssl_client_key/, err.message)
    end

    # TC-27-32: symbol key path raises a type error naming the field.
    def test_tc_27_32_key_path_symbol
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_cert: GEB.cert_path, ssl_client_key: :a_symbol })
      end
      assert_match(/ssl_client_key/, err.message)
      assert_match(/non-empty String path/, err.message)
    end

    # TC-27-33: pre-loaded OpenSSL object is rejected, not accepted.
    def test_tc_27_33_cert_object_rejected
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert: GEB.cert_object,
          ssl_client_key:  GEB.key_path
        })
      end
      assert_match(/ssl_client_cert/, err.message)
      assert_match(/non-empty String path/, err.message)
    end

    # TC-27-34: empty string key path is rejected.
    def test_tc_27_34_key_path_empty_string
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_cert: GEB.cert_path, ssl_client_key: "" })
      end
      assert_match(/ssl_client_key/, err.message)
      assert_match(/non-empty String path/, err.message)
    end

    # TC-27-35: CA path that is a directory raises a clear error.
    def test_tc_27_35_ca_path_directory
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert: GEB.cert_path,
          ssl_client_key:  GEB.key_path,
          ssl_ca_file:     GEB.dir
        })
      end
      assert_match(/ssl_ca_file/, err.message)
      assert_match(/not a file/, err.message)
    end

    # TC-27-36: cert path that is a directory raises a clear error.
    def test_tc_27_36_cert_path_directory
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_cert: GEB.dir, ssl_client_key: GEB.key_path })
      end
      assert_match(/ssl_client_cert/, err.message)
      assert_match(/not a file/, err.message)
    end

    # TC-27-37: key path that is a directory raises a clear error.
    def test_tc_27_37_key_path_directory
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_cert: GEB.cert_path, ssl_client_key: GEB.dir })
      end
      assert_match(/ssl_client_key/, err.message)
      assert_match(/not a file/, err.message)
    end

    # TC-27-38: non-String passphrase is rejected.
    def test_tc_27_38_passphrase_integer
      err = assert_raises(ArgumentError) do
        build_client(ssl: {
          ssl_client_cert:          GEB.cert_path,
          ssl_client_key:           GEB.encrypted_key_path,
          ssl_client_key_passphrase: 12_345
        })
      end
      assert_match(/ssl_client_key_passphrase/, err.message)
      assert_match(/String/, err.message)
    end

    # TC-27-39: boolean cert path raises a type error.
    def test_tc_27_39_cert_path_boolean
      err = assert_raises(ArgumentError) do
        build_client(ssl: { ssl_client_cert: true, ssl_client_key: GEB.key_path })
      end
      assert_match(/ssl_client_cert/, err.message)
      assert_match(/non-empty String path/, err.message)
    end
  end

  # ----------------------------------------------------------------------------
  # Section 5 — Retry path
  # ----------------------------------------------------------------------------
  class TestIssue27Retry < Minitest::Test
    include Helpers

    # TC-27-40: retries reuse the same loaded cert/key objects.
    def test_tc_27_40_retry_reuses_objects
      client = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path
      })
      def client.sleep(_seconds); end

      responses = [
        FakeResponse.new(502, '{"body":null}'),
        FakeResponse.new(502, '{"body":null}'),
        FakeResponse.new(200, '{"body":{"ok":true}}')
      ]
      with_execute_stub(responses) do |spy|
        result = client.get_venues
        assert_equal({"ok" => true}, result)
        assert_equal 3, spy.calls.length

        cert_ids = spy.calls.map { |c| c[:ssl_client_cert].object_id }
        key_ids  = spy.calls.map { |c| c[:ssl_client_key].object_id }
        assert_equal 1, cert_ids.uniq.length
        assert_equal 1, key_ids.uniq.length
      end
    end

    # TC-27-41: files are read exactly once across construction and retries.
    def test_tc_27_41_retry_does_not_reread_files
      paths = [GEB.cert_path, GEB.key_path]
      client = nil
      with_file_read_counter(paths) do |counts|
        client = build_client(ssl: {
          ssl_client_cert: GEB.cert_path,
          ssl_client_key:  GEB.key_path
        })
        def client.sleep(_seconds); end

        responses = [
          FakeResponse.new(502, '{"body":null}'),
          FakeResponse.new(502, '{"body":null}'),
          FakeResponse.new(200, '{"body":{}}')
        ]
        with_execute_stub(responses) do
          client.get_venues
        end

        assert_equal 1, counts[GEB.cert_path]
        assert_equal 1, counts[GEB.key_path]
      end
    end

    # TC-27-42: pre-existing retry behaviour is unaffected when no ssl is set.
    def test_tc_27_42_retry_without_ssl_unchanged
      client = build_client
      def client.sleep(_seconds); end

      responses = [
        FakeResponse.new(502, '{"body":null}'),
        FakeResponse.new(200, '{"body":{}}')
      ]
      with_execute_stub(responses) do |spy|
        client.get_venues
        assert_equal 2, spy.calls.length
        refute spy.calls.first.key?(:ssl_client_cert)
      end
    end

    # TC-27-43: the final successful response is parsed normally.
    def test_tc_27_43_retry_success_parsed
      client = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path
      })
      def client.sleep(_seconds); end

      responses = [
        FakeResponse.new(502, '{"body":null}'),
        FakeResponse.new(200, '{"body":{"venues":["A"]}}')
      ]
      with_execute_stub(responses) do
        assert_equal({"venues" => ["A"]}, client.get_venues)
      end
    end
  end

  # ----------------------------------------------------------------------------
  # Section 6 — $DEBUG / logging safety
  # ----------------------------------------------------------------------------
  class TestIssue27DebugSafety < Minitest::Test
    include Helpers

    # TC-27-45: $DEBUG output on success does not leak key material.
    def test_tc_27_45_debug_success_no_leak
      old_debug = $DEBUG
      $DEBUG = true
      client = build_client(ssl: {
        ssl_client_cert:          GEB.cert_path,
        ssl_client_key:           GEB.key_path,
        ssl_client_key_passphrase: "harmless",
        ssl_ca_file:              GEB.ca_cert_path
      })
      def client.sleep(_seconds); end

      begin
        output = capture_stdout do
          with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do
            client.get_venues
          end
        end
        refute_key_material_leak(output, "TC-27-45")
        refute_includes output, "harmless"
      ensure
        $DEBUG = old_debug
      end
    end

    # TC-27-46: $DEBUG output on mismatch failure does not leak key material.
    def test_tc_27_46_debug_failure_no_leak
      old_debug = $DEBUG
      $DEBUG = true

      begin
        output = capture_stdout do
          assert_raises(ArgumentError) do
            build_client(ssl: {
              ssl_client_cert: GEB.cert_path,
              ssl_client_key:  GEB.mismatched_key_path
            })
          end
        end
        refute_key_material_leak(output, "TC-27-46")
        refute_includes output, "BEGIN"
      ensure
        $DEBUG = old_debug
      end
    end

    # TC-27-47: HMAC debug lines still print and no key material leaks.
    def test_tc_27_47_debug_hmac_lines_unchanged
      old_debug = $DEBUG
      old_verbose = $VERBOSE
      $DEBUG   = true
      $VERBOSE = true

      client = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path
      })
      def client.sleep(_seconds); end

      begin
        output = capture_stdout do
          with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do
            client.get_venues
          end
        end
        assert_includes output, "Access-Key:"
        assert_includes output, "Signature:"
        refute_key_material_leak(output, "TC-27-47")
      ensure
        $DEBUG   = old_debug
        $VERBOSE = old_verbose
      end
    end

    # TC-27-48: no accidental inspect/p/pp of the loaded key object.
    def test_tc_27_48_debug_no_key_object_inspect
      old_debug = $DEBUG
      $DEBUG = true
      client = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path
      })
      def client.sleep(_seconds); end

      begin
        output = capture_stdout do
          with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do
            client.get_venues
          end
        end
        refute_key_material_leak(output, "TC-27-48")
      ensure
        $DEBUG = old_debug
      end
    end
  end

  # ----------------------------------------------------------------------------
  # Section 7 — HMAC headers unchanged alongside cert
  # ----------------------------------------------------------------------------
  class TestIssue27HmacUnchanged < Minitest::Test
    include Helpers

    # TC-27-50: capture baseline HMAC headers without mTLS.
    def test_tc_27_50_hmac_baseline
      client = build_client
      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        client.get_venues
        headers = spy.calls.first[:headers]
        assert_equal "test_access_key", headers["Access-Key"]
        refute_nil headers["Sign"]
      end
    end

    # TC-27-51: mTLS config leaves HMAC headers byte-identical to baseline.
    def test_tc_27_51_hmac_same_with_ssl
      baseline = nil
      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        build_client.get_venues
        baseline = spy.calls.first[:headers]
      end

      client = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path,
        ssl_ca_file:     GEB.ca_cert_path
      })
      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        client.get_venues
        assert_equal baseline, spy.calls.first[:headers]
      end
    end

    # TC-27-52: no ssl_* key ever leaks into the HTTP headers hash.
    def test_tc_27_52_headers_no_ssl_keys
      client = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path,
        ssl_ca_file:     GEB.ca_cert_path
      })
      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        client.get_venues
        keys = spy.calls.first[:headers].keys
        refute keys.any? { |k| k.to_s.start_with?("ssl_") },
               "ssl_* key leaked into headers: #{keys.inspect}"
      end
    end
  end

  # ----------------------------------------------------------------------------
  # Section 8 — Instance isolation
  # ----------------------------------------------------------------------------
  class TestIssue27Isolation < Minitest::Test
    include Helpers

    # TC-27-55: GEB and NUT clients construct independently.
    def test_tc_27_55_geb_nut_construction
      geb = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path,
        ssl_ca_file:     GEB.ca_cert_path
      })
      nut = build_client(ssl: {
        ssl_client_cert: NUT.cert_path,
        ssl_client_key:  NUT.key_path,
        ssl_ca_file:     NUT.ca_cert_path
      })
      refute_nil geb
      refute_nil nut
    end

    # TC-27-56: GEB and NUT carry distinct cert/key objects.
    def test_tc_27_56_geb_nut_objects_differ
      geb = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path
      })
      nut = build_client(ssl: {
        ssl_client_cert: NUT.cert_path,
        ssl_client_key:  NUT.key_path
      })

      with_execute_stub([
        FakeResponse.new(200, '{"body":{}}'),
        FakeResponse.new(200, '{"body":{}}')
      ]) do |spy|
        geb.get_venues
        nut.get_venues
        geb_call = spy.calls[0]
        nut_call = spy.calls[1]

        refute_equal geb_call[:ssl_client_cert].object_id,
                     nut_call[:ssl_client_cert].object_id
        refute_equal geb_call[:ssl_client_key].object_id,
                     nut_call[:ssl_client_key].object_id

        assert_equal GEB.cert_object.to_der, geb_call[:ssl_client_cert].to_der
        assert_equal NUT.cert_object.to_der, nut_call[:ssl_client_cert].to_der
      end
    end

    # TC-27-57: a second GEB call is unaffected by an intervening NUT call.
    def test_tc_27_57_geb_stable_after_nut_call
      geb = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path
      })
      nut = build_client(ssl: {
        ssl_client_cert: NUT.cert_path,
        ssl_client_key:  NUT.key_path
      })

      with_execute_stub([
        FakeResponse.new(200, '{"body":{}}'),
        FakeResponse.new(200, '{"body":{}}'),
        FakeResponse.new(200, '{"body":{}}')
      ]) do |spy|
        geb.get_venues
        nut.get_venues
        geb.get_venues

        assert_equal spy.calls[0][:ssl_client_cert].object_id,
                     spy.calls[2][:ssl_client_cert].object_id
        refute_equal spy.calls[0][:ssl_client_cert].object_id,
                     spy.calls[1][:ssl_client_cert].object_id
      end
    end

    # TC-27-58: a plain client created after an mTLS client has no ssl state.
    def test_tc_27_58_plain_after_ssl_no_leak
      _ssl_client = build_client(ssl: {
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path
      })
      plain = build_client

      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        plain.get_venues
        call = spy.calls.first
        refute call.key?(:ssl_client_cert)
        refute call.key?(:ssl_client_key)
        refute call.key?(:ssl_ca_file)
      end
    end
  end

  # ----------------------------------------------------------------------------
  # Section 9 — Config→runtime seam with automated-strategies
  # ----------------------------------------------------------------------------
  class TestIssue27AutomatedStrategiesSeam < Minitest::Test
    include Helpers

    # TC-27-60: the exact hash shape used by automated-strategies works.
    def test_tc_27_60_automated_strategies_hash_shape
      config_phase1 = {
        api_host_core: "api.cryptomnio.com",
        api_host_cma:  "cma.cryptomnio.com",
        authtype:      "Cryptomnio",
        access_key:    "test_access_key",
        secret_key:    "test_secret_key",
        contexts:      [],
        ssl_client_cert: GEB.cert_path,
        ssl_client_key:  GEB.key_path,
        ssl_ca_file:     GEB.ca_cert_path
      }

      client = Cryptomnio::REST::Client.new do |c|
        c.config = config_phase1
        c.config[:contexts] = {
          exchange: {
            venue:      "test_venue",
            accountid:  "test_account",
            venuekeyid: "test_venuekeyid"
          }
        }
      end

      with_execute_stub([FakeResponse.new(200, '{"body":{}}')]) do |spy|
        client.get_venues
        assert_equal GEB.ca_cert_path, spy.calls.first[:ssl_ca_file]
      end
    end

    # TC-27-61: regression-watch over live automated-strategies source text.
    def test_tc_27_61_automated_strategies_forwarding_watch
      path = ENV.fetch("AUTOMATED_STRATEGIES_PATH",
                       "/home/nova/.openclaw/workspace/automated-strategies")
      file = File.join(path, "class_automated_strategy.rb")

      unless File.exist?(file)
        skip "automated-strategies checkout not found at #{path}; " \
             "this regression watch only runs where that sibling repo is checked out. " \
             "See automated-strategies #132 (GitLab bhco/co/automated-strategies) " \
             "for the ssl_* forwarding gap this test watches for."
      end

      source = File.read(file)
      method_body = source[/def connect_cryptomnio\b.*?^\tend/m] ||
                    source[/def connect_cryptomnio\b.*?^  end/m] ||
                    ""
      keys = method_body.scan(/@config\[:cryptomnio\]\[:([^\]]+)\]/).flatten.map(&:to_sym)

      expected = %i[
        api_host_core api_host_cma authtype access_key secret_key
        exchange accountid venuekeyid
        ssl_client_cert ssl_client_key ssl_client_key_passphrase ssl_ca_file
      ].to_set
      missing = expected - keys.to_set

      assert_empty missing,
        "automated-strategies connect_cryptomnio is missing ssl_* forwarding. " \
        "Missing keys: #{missing.to_a.inspect}. " \
        "See automated-strategies #132 (GitLab bhco/co/automated-strategies). " \
        "Fix belongs in the automated-strategies repo, not this gem."
    end
  end
end

require 'openssl'
require "test/unit"

class TestCertificate < Test::Unit::TestCase
  def setup
    cert_file = File.expand_path('fixture/selfcert.pem', File.dirname(__FILE__))
    key_file = File.expand_path('fixture/keypair.pem', File.dirname(__FILE__))
    @cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    @key = OpenSSL::PKey::RSA.new(File.read(key_file))
  end

  def test_sign_for_pem_initialized_certificate
    pem = @cert.to_pem
    exts = @cert.extensions
    assert_nothing_raised do
      @cert.sign(@key, OpenSSL::Digest::SHA1.new)
    end
    # TODO: for now, jruby-openssl cannot keep order of extensions after sign.
    # assert_equal(pem, @cert.to_pem)
    assert_equal(exts.size, @cert.extensions.size)
    exts.each do |ext|
      found = @cert.extensions.find { |e| e.oid == ext.oid }
      assert_not_nil(found)
      assert_equal(ext.value, found.value)
    end
  end

  def test_set_public_key
    pkey = @cert.public_key
    newkey = OpenSSL::PKey::RSA.new(1024)
    @cert.public_key = newkey
    assert_equal(newkey.public_key.to_pem, @cert.public_key.to_pem)
  end
end

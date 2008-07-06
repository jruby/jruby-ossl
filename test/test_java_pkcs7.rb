require "test/unit"

if defined?(JRUBY_VERSION)
  require "java"
  $CLASSPATH << 'pkg/classes'
  
  class TestJavaPKCS7 < Test::Unit::TestCase
    PKCS7 = org.jruby.ext.openssl.impl.PKCS7 unless defined?(PKCS7)
    Digest = org.jruby.ext.openssl.impl.Digest unless defined?(Digest)
    EncContent = org.jruby.ext.openssl.impl.EncContent unless defined?(EncContent)
    Encrypt = org.jruby.ext.openssl.impl.Encrypt unless defined?(Encrypt)
    Envelope = org.jruby.ext.openssl.impl.Envelope unless defined?(Envelope)
    IssuerAndSerial = org.jruby.ext.openssl.impl.IssuerAndSerial unless defined?(IssuerAndSerial)
    RecipInfo = org.jruby.ext.openssl.impl.RecipInfo unless defined?(RecipInfo)
    SignEnvelope = org.jruby.ext.openssl.impl.SignEnvelope unless defined?(SignEnvelope)
    Signed = org.jruby.ext.openssl.impl.Signed unless defined?(Signed)
    SignerInfo = org.jruby.ext.openssl.impl.SignerInfo unless defined?(SignerInfo)

    def test_truth
      assert true
    end
  end
end

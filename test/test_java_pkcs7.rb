require "test/unit"

if defined?(JRUBY_VERSION)
  require "java"
  $CLASSPATH << 'pkg/classes'
  $CLASSPATH << 'lib/bcprov-jdk14-139.jar'
  
  class TestJavaPKCS7 < Test::Unit::TestCase
    module ASN1
      OctetString = org.bouncycastle.asn1.DEROctetString
    end
    
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
    
    def test_is_signed
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signed
      assert p7.signed?
      assert !p7.encrypted?
      assert !p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert !p7.data?
      assert !p7.digest?
    end

    def test_is_encrypted
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_encrypted
      assert !p7.signed?
      assert p7.encrypted?
      assert !p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert !p7.data?
      assert !p7.digest?
    end

    def test_is_enveloped
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_enveloped
      assert !p7.signed?
      assert !p7.encrypted?
      assert p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert !p7.data?
      assert !p7.digest?
    end

    def test_is_signed_and_enveloped
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
      assert !p7.signed?
      assert !p7.encrypted?
      assert !p7.enveloped?
      assert p7.signed_and_enveloped?
      assert !p7.data?
      assert !p7.digest?
    end

    def test_is_data
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_data
      assert !p7.signed?
      assert !p7.encrypted?
      assert !p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert p7.data?
      assert !p7.digest?
    end

    def test_is_digest
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_digest
      assert !p7.signed?
      assert !p7.encrypted?
      assert !p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert !p7.data?
      assert p7.digest?
    end

    def test_set_detached
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signed

      sign = Signed.new
      p7.sign = sign
      
      test_p7 = PKCS7.new
      test_p7.type = PKCS7::NID_pkcs7_data 
      test_p7.data = ASN1::OctetString.new("foo".to_java_bytes)
      sign.contents = test_p7
      
      p7.detached = 2
      assert_equal 1, p7.get_detached
      assert_equal nil, test_p7.data
    end

    def test_set_not_detached
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signed

      sign = Signed.new
      p7.sign = sign
      
      test_p7 = PKCS7.new
      test_p7.type = PKCS7::NID_pkcs7_data 
      data = ASN1::OctetString.new("foo".to_java_bytes)
      test_p7.data = data
      sign.contents = test_p7
      
      p7.detached = 0
      assert_equal 0, p7.get_detached
      assert_equal data, test_p7.data
    end

    def test_is_detached
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signed

      sign = Signed.new
      p7.sign = sign
      
      test_p7 = PKCS7.new
      test_p7.type = PKCS7::NID_pkcs7_data 
      data = ASN1::OctetString.new("foo".to_java_bytes)
      test_p7.data = data
      sign.contents = test_p7
      
      p7.detached = 1
      assert p7.detached?
    end

    def test_is_detached_with_wrong_type
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_data
      
      p7.detached = 1
      assert !p7.detached?
    end
    
    def test_encrypt_generates_enveloped_PKCS7_object
      p7 = PKCS7.encrypt([], "".to_java_bytes, nil, 0)
      assert !p7.signed?
      assert !p7.encrypted?
      assert p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert !p7.data?
      assert !p7.digest?
    end
    
    def test_set_type_throws_exception_on_wrong_argument
      assert_raises NativeException do 
        # 42 is a value that is not one of the valid NID's for type
        PKCS7.new.type = 42
      end
    end
    
    def test_set_type_signed
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signed

      assert p7.signed?
      assert_equal 1, p7.get_sign.version

      assert_nil p7.get_data
      assert_nil p7.get_enveloped
      assert_nil p7.get_signed_and_enveloped
      assert_nil p7.get_digest
      assert_nil p7.get_encrypted
      assert_nil p7.get_other
    end

    def test_set_type_data
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_data

      assert p7.data?
      assert_equal ASN1::OctetString.new("".to_java_bytes), p7.data

      assert_nil p7.get_sign
      assert_nil p7.get_enveloped
      assert_nil p7.get_signed_and_enveloped
      assert_nil p7.get_digest
      assert_nil p7.get_encrypted
      assert_nil p7.get_other
    end

    def test_set_type_signed_and_enveloped
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signedAndEnveloped

      assert p7.signed_and_enveloped?
      assert_equal 1, p7.get_signed_and_enveloped.version
      assert_equal PKCS7::NID_pkcs7_data, p7.get_signed_and_enveloped.enc_data.content_type

      assert_nil p7.get_sign
      assert_nil p7.get_enveloped
      assert_nil p7.get_data
      assert_nil p7.get_digest
      assert_nil p7.get_encrypted
      assert_nil p7.get_other
    end

    def test_set_type_enveloped
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_enveloped

      assert p7.enveloped?
      assert_equal 0, p7.get_enveloped.version
      assert_equal PKCS7::NID_pkcs7_data, p7.get_enveloped.enc_data.content_type

      assert_nil p7.get_sign
      assert_nil p7.get_signed_and_enveloped
      assert_nil p7.get_data
      assert_nil p7.get_digest
      assert_nil p7.get_encrypted
      assert_nil p7.get_other
    end

    def test_set_type_encrypted
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_encrypted

      assert p7.encrypted?
      assert_equal 0, p7.get_encrypted.version
      assert_equal PKCS7::NID_pkcs7_data, p7.get_encrypted.enc_data.content_type

      assert_nil p7.get_sign
      assert_nil p7.get_signed_and_enveloped
      assert_nil p7.get_data
      assert_nil p7.get_digest
      assert_nil p7.get_enveloped
      assert_nil p7.get_other
    end

    def test_set_type_digest
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_digest

      assert p7.digest?
      assert_equal 0, p7.get_digest.version

      assert_nil p7.get_sign
      assert_nil p7.get_signed_and_enveloped
      assert_nil p7.get_data
      assert_nil p7.get_encrypted
      assert_nil p7.get_enveloped
      assert_nil p7.get_other
    end
    
    def test_set_cipher_on_non_enveloped_object
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_digest
      
      assert_raises NativeException do 
        p7.cipher = nil
      end
      
      p7.type = PKCS7::NID_pkcs7_encrypted

      assert_raises NativeException do 
        p7.cipher = nil
      end

      p7.type = PKCS7::NID_pkcs7_data

      assert_raises NativeException do 
        p7.cipher = nil
      end

      p7.type = PKCS7::NID_pkcs7_signed

      assert_raises NativeException do 
        p7.cipher = nil
      end
    end
    
    def test_set_cipher_on_enveloped_object
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_enveloped

      cipher = javax.crypto.Cipher.getInstance("RSA")
      
      p7.cipher = cipher
      
      assert_equal cipher, p7.get_enveloped.enc_data.cipher
    end

      
    def test_set_cipher_on_signedAndEnveloped_object
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signedAndEnveloped

      cipher = javax.crypto.Cipher.getInstance("RSA")
      
      p7.cipher = cipher
      
      assert_equal cipher, p7.get_signed_and_enveloped.enc_data.cipher
    end
  end
end

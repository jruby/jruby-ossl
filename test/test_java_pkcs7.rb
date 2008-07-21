$:.unshift File.join(File.dirname(__FILE__), '..', 'mocha', 'lib')

require "test/unit"
require 'mocha'

if defined?(JRUBY_VERSION)
  require "java"
  $CLASSPATH << 'pkg/classes'
  $CLASSPATH << 'lib/bcprov-jdk14-139.jar'

  module PKCS7Test
    module ASN1
      OctetString = org.bouncycastle.asn1.DEROctetString
    end
    
    PKCS7 = org.jruby.ext.openssl.impl.PKCS7 unless defined?(PKCS7)
    Attribute = org.jruby.ext.openssl.impl.Attribute unless defined?(Attribute)
    Digest = org.jruby.ext.openssl.impl.Digest unless defined?(Digest)
    EncContent = org.jruby.ext.openssl.impl.EncContent unless defined?(EncContent)
    Encrypt = org.jruby.ext.openssl.impl.Encrypt unless defined?(Encrypt)
    Envelope = org.jruby.ext.openssl.impl.Envelope unless defined?(Envelope)
    IssuerAndSerial = org.jruby.ext.openssl.impl.IssuerAndSerial unless defined?(IssuerAndSerial)
    RecipInfo = org.jruby.ext.openssl.impl.RecipInfo unless defined?(RecipInfo)
    SignEnvelope = org.jruby.ext.openssl.impl.SignEnvelope unless defined?(SignEnvelope)
    Signed = org.jruby.ext.openssl.impl.Signed unless defined?(Signed)
    SignerInfo = org.jruby.ext.openssl.impl.SignerInfo unless defined?(SignerInfo)
    SMIME = org.jruby.ext.openssl.impl.SMIME unless defined?(SMIME)
    Mime = org.jruby.ext.openssl.impl.Mime unless defined?(Mime)
    MimeHeader = org.jruby.ext.openssl.impl.MimeHeader unless defined?(MimeHeader)
    BIO = org.jruby.ext.openssl.impl.BIO unless defined?(BIO)
    PKCS7Exception = org.jruby.ext.openssl.impl.PKCS7Exception unless defined?(PKCS7Exception)
    
    ArrayList = java.util.ArrayList unless defined?(ArrayList)
    CertificateFactory = java.security.cert.CertificateFactory unless defined?(CertificateFactory)
    BCP = org.bouncycastle.jce.provider.BouncyCastleProvider unless defined?(BCP)
    ByteArrayInputStream = java.io.ByteArrayInputStream unless defined?(ByteArrayInputStream)
    
    X509CertString = <<CERT
-----BEGIN CERTIFICATE-----
MIICijCCAXKgAwIBAgIBAjANBgkqhkiG9w0BAQUFADA9MRMwEQYKCZImiZPyLGQB
GRYDb3JnMRkwFwYKCZImiZPyLGQBGRYJcnVieS1sYW5nMQswCQYDVQQDDAJDQTAe
Fw0wODA3MDgxOTE1NDZaFw0wODA3MDgxOTQ1NDZaMEQxEzARBgoJkiaJk/IsZAEZ
FgNvcmcxGTAXBgoJkiaJk/IsZAEZFglydWJ5LWxhbmcxEjAQBgNVBAMMCWxvY2Fs
aG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAy8LEsNRApz7U/j5DoB4X
BgO9Z8Atv5y/OVQRp0ag8Tqo1YewsWijxEWB7JOATwpBN267U4T1nPZIxxEEO7n/
WNa2ws9JWsjah8ssEBFSxZqdXKSLf0N4Hi7/GQ/aYoaMCiQ8jA4jegK2FJmXM71u
Pe+jFN/peeBOpRfyXxRFOYcCAwEAAaMSMBAwDgYDVR0PAQH/BAQDAgWgMA0GCSqG
SIb3DQEBBQUAA4IBAQCU879BALJIM9avHiuZ3WTjDy0UYP3ZG5wtuSqBSnD1k8pr
hXfRaga7mDj6EQaGUovImb+KrRi6mZc+zsx4rTxwBNJT9U8yiW2eYxmgcT9/qKrD
/1nz+e8NeUCCDY5UTUHGszZw5zLEDgDX2n3E/CDIZsoRSyq5vXq1jpfih/tSWanj
Y9uP/o8Dc7ZcRJOAX7NPu1bbZcbxEbZ8sMe5wZ5HNiAR6gnOrjz2Yyazb//PSskE
4flt/2h4pzGA0/ZHcnDjcoLdiLtInsqPOlVDLgqd/XqRYWtj84N4gw1iS9cHyrIZ
dqbS54IKvzElD+R0QVS2z6TIGJSpuSBnZ4yfuNuq
-----END CERTIFICATE-----
CERT

    X509CRLString = <<CRL
----BEGIN X509 CRL-----
MIIBlTB/AgEBMA0GCSqGSIb3DQEBBQUAMD0xEzARBgoJkiaJk/IsZAEZFgNvcmcx
GTAXBgoJkiaJk/IsZAEZFglydWJ5LWxhbmcxCzAJBgNVBAMMAkNBFw0wODA3MTgx
NzQxMjhaFw0wODA3MTgxODA4MDhaoA4wDDAKBgNVHRQEAwIBATANBgkqhkiG9w0B
AQUFAAOCAQEASJaj1keN+tMmsF3QmjH2RhbW/9rZAl4gjv+uQQqrcS2ByfkXLU1d
l/8rCHeT/XMoeU6xhQNHPP3uZBwfuuETcp65BMBcZFOUhUR0U5AaGhvSDS/+6EsP
zFdQgAagmThFdN5ei9guTLqWwN0ZyqiaHyevFJuk+L9qbKavaSeKqfJbU7Sj/Z3J
WLKoixvyj3N6W7evygH80lTvjZugmxJ1/AjICVSYr1hpHHd6EWq0b0YFrGFmg27R
WmsAXd0QV5UChfAJ2+Cz5U1bPszvIJGrzfAIoLxHv5rI5rseQzqZdPaFSe4Oehln
9qEYmsK3PS6bYoQol0cgj97Ep4olS8CulA==
-----END X509 CRL-----
CRL
    
    X509Cert = CertificateFactory.getInstance("X.509",BCP.new).generateCertificate(ByteArrayInputStream.new(X509CertString.to_java_bytes))
    X509CRL = CertificateFactory.getInstance("X.509",BCP.new).generateCRL(ByteArrayInputStream.new(X509CRLString.to_java_bytes))

    class TestJavaSMIME < Test::Unit::TestCase
      def test_read_pkcs7_should_raise_error_when_parsing_headers_fails
        bio = BIO.new
        mime = Mime.new
        mime.stubs(:parseHeaders).returns(nil)

        begin
          SMIME.new(mime).readPKCS7(bio, nil)
          assert false
        rescue PKCS7Exception => e
          assert_equal PKCS7::F_SMIME_READ_PKCS7, e.cause.get_method
          assert_equal PKCS7::R_MIME_PARSE_ERROR, e.cause.get_reason
        end
      end

      def test_read_pkcs7_should_raise_error_when_content_type_is_not_there
        bio = BIO.new
        mime = Mime.new

        headers = ArrayList.new
        mime.expects(:parseHeaders).with(bio).returns(headers)
        mime.expects(:findHeader).with(headers, "content-type").returns(nil)

        begin
          SMIME.new(mime).readPKCS7(bio, nil)
          assert false
        rescue PKCS7Exception => e
          assert_equal PKCS7::F_SMIME_READ_PKCS7, e.cause.get_method
          assert_equal PKCS7::R_NO_CONTENT_TYPE, e.cause.get_reason
        end


        
        
        mime = Mime.new
        mime.expects(:parseHeaders).with(bio).returns(headers)
        mime.expects(:findHeader).with(headers, "content-type").returns(MimeHeader.new("content-type", nil))

        begin
          SMIME.new(mime).readPKCS7(bio, nil)
          assert false
        rescue PKCS7Exception => e
          assert_equal PKCS7::F_SMIME_READ_PKCS7, e.cause.get_method
          assert_equal PKCS7::R_NO_CONTENT_TYPE, e.cause.get_reason
        end
      end
      
      def test_read_pkcs7_should_set_the_second_arguments_contents_to_null_if_its_there
        mime = Mime.new
        mime.stubs(:parseHeaders).raises("getOutOfJailForFree")

        bio2 = BIO.new
        arr = [bio2].to_java BIO
        
        begin
          SMIME.new(mime).readPKCS7(nil, arr)
        rescue
        end

        assert_nil arr[0]


        arr = [bio2, bio2].to_java BIO
        begin
          SMIME.new(mime).readPKCS7(nil, arr)
        rescue
        end

        assert_nil arr[0]
        assert_equal bio2, arr[1]
      end
      
      def test_read_pkcs7_should_call_methods_on_mime
        bio = BIO.new
        mime = Mime.new

        headers = ArrayList.new
        mime.expects(:parseHeaders).with(bio).returns(headers)
        mime.expects(:findHeader).with(headers, "content-type").returns(MimeHeader.new("content-type", "foo"))

        SMIME.new(mime).readPKCS7(bio, nil)
      end
    end
    
    class TestJavaSignerInfo < Test::Unit::TestCase
      def test_get_attribute_with_nonexisting_nid
        assert_nil SignerInfo.new.get_attribute(321)
        val = ASN1::OctetString.new("foo".to_java_bytes)

        si = SignerInfo.new
        si.add_attribute(123, 444, val)
        assert_nil si.get_attribute(321)
      end

      def test_get_attribute_with_existing_nid
        val = ASN1::OctetString.new("foo".to_java_bytes)
        val2 = ASN1::OctetString.new("bar".to_java_bytes)

        si = SignerInfo.new
        si.add_attribute(123, 444, val)
        assert_equal val, si.get_attribute(123)

        si.add_attribute(124, 444, val2)
        assert_equal val, si.get_attribute(123)
        assert_equal val2, si.get_attribute(124)
      end

      def test_get_signed_attribute_with_nonexisting_nid
        assert_nil SignerInfo.new.get_signed_attribute(321)
        val = ASN1::OctetString.new("foo".to_java_bytes)
        attr1 = Attribute.create(123, 444, val)

        si = SignerInfo.new
        si.add_signed_attribute(123, 444, val)
        assert_nil si.get_signed_attribute(321)
      end

      def test_get_signed_attribute_with_existing_nid
        val = ASN1::OctetString.new("foo".to_java_bytes)
        val2 = ASN1::OctetString.new("bar".to_java_bytes)

        si = SignerInfo.new
        si.add_signed_attribute(123, 444, val)
        assert_equal val, si.get_signed_attribute(123)

        si.add_signed_attribute(124, 444, val2)
        assert_equal val, si.get_signed_attribute(123)
        assert_equal val2, si.get_signed_attribute(124)
      end
      
      def test_add_signed_attribute
        val = ASN1::OctetString.new("foo".to_java_bytes)
        val2 = ASN1::OctetString.new("bar".to_java_bytes)
        attr1 = Attribute.create(123, 444, val)
        attr2 = Attribute.create(124, 444, val2)
        attr3 = Attribute.create(123, 444, val2)

        si = SignerInfo.new
        assert si.auth_attr.empty?
        si.add_signed_attribute(123, 444, val)
        assert_equal 1, si.auth_attr.size
        assert_equal attr1, si.auth_attr.get(0)

        si.add_signed_attribute(123, 444, val2)
        assert_equal 1, si.auth_attr.size
        assert_equal attr3, si.auth_attr.get(0)
      
        si.add_signed_attribute(124, 444, val2)
        assert_equal 2, si.auth_attr.size
        assert_equal attr2, si.auth_attr.get(1)
      end
      
      def test_add_attribute
        val = ASN1::OctetString.new("foo".to_java_bytes)
        val2 = ASN1::OctetString.new("bar".to_java_bytes)
        attr1 = Attribute.create(123, 444, val)
        attr2 = Attribute.create(124, 444, val2)
        attr3 = Attribute.create(123, 444, val2)

        si = SignerInfo.new
        assert si.unauth_attr.empty?
        si.add_attribute(123, 444, val)
        assert_equal 1, si.unauth_attr.size
        assert_equal attr1, si.unauth_attr.get(0)

        si.add_attribute(123, 444, val2)
        assert_equal 1, si.unauth_attr.size
        assert_equal attr3, si.unauth_attr.get(0)
      
        si.add_attribute(124, 444, val2)
        assert_equal 2, si.unauth_attr.size
        assert_equal attr2, si.unauth_attr.get(1)
      end
    end
    
    class TestJavaAttribute < Test::Unit::TestCase
      def test_attributes
        val = ASN1::OctetString.new("foo".to_java_bytes)
        val2 = ASN1::OctetString.new("bar".to_java_bytes)
        attr = Attribute.create(123, 444, val)
        assert_raises NoMethodError do 
          attr.type = 12
        end
        assert_raises NoMethodError do 
          attr.value = val2
        end

        assert_equal 123, attr.type
        assert_equal val, attr.set.get(0)

        attr2 = Attribute.create(123, 444, val)
        
        assert_equal attr, attr2
        
        assert_not_equal Attribute.create(124, 444, val), attr
        assert_not_equal Attribute.create(123, 444, val2), attr
      end
    end

    class TestJavaPKCS7 < Test::Unit::TestCase
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
      
      def test_add_recipient_info_to_something_that_cant_have_recipients
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signed
        assert_raises NativeException do 
          p7.add_recipient(X509Cert)
        end

        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_data
        assert_raises NativeException do 
          p7.add_recipient(X509Cert)
        end
        
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_encrypted
        assert_raises NativeException do 
          p7.add_recipient(X509Cert)
        end
        
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_digest
        assert_raises NativeException do 
          p7.add_recipient(X509Cert)
        end
      end

      def test_add_recipient_info_to_enveloped_should_add_that_to_stack
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_enveloped
        
        ri = p7.add_recipient(X509Cert)
        
        assert_equal 1, p7.get_enveloped.recipient_info.size
        assert_equal ri, p7.get_enveloped.recipient_info.get(0)
      end


      def test_add_recipient_info_to_signedAndEnveloped_should_add_that_to_stack
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
        
        ri = p7.add_recipient(X509Cert)
        
        assert_equal 1, p7.get_signed_and_enveloped.recipient_info.size
        assert_equal ri, p7.get_signed_and_enveloped.recipient_info.get(0)
      end
      
      def test_add_signer_to_something_that_cant_have_signers
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_enveloped
        assert_raises NativeException do 
          p7.add_signer(SignerInfo.new)
        end

        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_data
        assert_raises NativeException do 
          p7.add_signer(SignerInfo.new)
        end
        
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_encrypted
        assert_raises NativeException do 
          p7.add_signer(SignerInfo.new)
        end
        
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_digest
        assert_raises NativeException do 
          p7.add_signer(SignerInfo.new)
        end
      end

      def test_add_signer_to_signed_should_add_that_to_stack
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signed
        
        si = SignerInfo.new
        p7.add_signer(si)
        
        assert_equal 1, p7.get_sign.signer_info.size
        assert_equal si, p7.get_sign.signer_info.get(0)
      end


      def test_add_signer_to_signedAndEnveloped_should_add_that_to_stack
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
        
        si = SignerInfo.new
        p7.add_signer(si)
        
        assert_equal 1, p7.get_signed_and_enveloped.signer_info.size
        assert_equal si, p7.get_signed_and_enveloped.signer_info.get(0)
      end

      
      def test_add_signer_to_signed_with_new_algo_should_add_that_algo_to_the_algo_list
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signed
        
        si = SignerInfo.new
        si.digest_algorithm = "MD5"
        p7.add_signer(si)

        assert_equal "MD5", p7.get_sign.md_algs.iterator.next
        assert_equal 1, p7.get_sign.md_algs.size

        si = SignerInfo.new
        si.digest_algorithm = "MD5"
        p7.add_signer(si)

        assert_equal "MD5", p7.get_sign.md_algs.iterator.next
        assert_equal 1, p7.get_sign.md_algs.size

        si = SignerInfo.new
        si.digest_algorithm = "MD4"
        p7.add_signer(si)

        assert_equal 2, p7.get_sign.md_algs.size
        assert p7.get_sign.md_algs.contains("MD4")
        assert p7.get_sign.md_algs.contains("MD5")
      end


      def test_add_signer_to_signedAndEnveloped_with_new_algo_should_add_that_algo_to_the_algo_list
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
        
        si = SignerInfo.new
        si.digest_algorithm = "MD5"
        p7.add_signer(si)

        assert_equal "MD5", p7.get_signed_and_enveloped.md_algs.iterator.next
        assert_equal 1, p7.get_signed_and_enveloped.md_algs.size

        si = SignerInfo.new
        si.digest_algorithm = "MD5"
        p7.add_signer(si)

        assert_equal "MD5", p7.get_signed_and_enveloped.md_algs.iterator.next
        assert_equal 1, p7.get_signed_and_enveloped.md_algs.size

        si = SignerInfo.new
        si.digest_algorithm = "MD4"
        p7.add_signer(si)

        assert_equal 2, p7.get_signed_and_enveloped.md_algs.size
        assert p7.get_signed_and_enveloped.md_algs.contains("MD4")
        assert p7.get_signed_and_enveloped.md_algs.contains("MD5")
      end
      
      def test_set_content_on_data_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_data
        assert_raises NativeException do 
          p7.setContent(PKCS7.new)
        end
      end

      def test_set_content_on_enveloped_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_enveloped
        assert_raises NativeException do 
          p7.setContent(PKCS7.new)
        end
      end

      def test_set_content_on_signedAndEnveloped_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
        assert_raises NativeException do 
          p7.setContent(PKCS7.new)
        end
      end

      def test_set_content_on_encrypted_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_encrypted
        assert_raises NativeException do 
          p7.setContent(PKCS7.new)
        end
      end

      def test_set_content_on_signed_sets_the_content
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signed
        p7new = PKCS7.new
        p7.setContent(p7new)
        
        assert_equal p7new, p7.get_sign.contents
      end

      def test_set_content_on_digest_sets_the_content
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_digest
        p7new = PKCS7.new
        p7.setContent(p7new)
        
        assert_equal p7new, p7.get_digest.contents
      end
      
      def test_get_signer_info_on_digest_returns_null
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_digest
        assert_nil p7.signer_info
      end

      def test_get_signer_info_on_data_returns_null
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_data
        assert_nil p7.signer_info
      end

      def test_get_signer_info_on_encrypted_returns_null
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_encrypted
        assert_nil p7.signer_info
      end

      def test_get_signer_info_on_enveloped_returns_null
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_enveloped
        assert_nil p7.signer_info
      end

      def test_get_signer_info_on_signed_returns_signer_info
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signed
        assert_equal p7.get_sign.signer_info.object_id, p7.signer_info.object_id
      end

      def test_get_signer_info_on_signedAndEnveloped_returns_signer_info
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
        assert_equal p7.get_signed_and_enveloped.signer_info.object_id, p7.signer_info.object_id
      end
      
      def test_content_new_on_data_raises_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_data
        assert_raises NativeException do 
          p7.content_new(PKCS7::NID_pkcs7_data)
        end
      end

      def test_content_new_on_encrypted_raises_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_encrypted
        assert_raises NativeException do 
          p7.content_new(PKCS7::NID_pkcs7_data)
        end
      end

      def test_content_new_on_enveloped_raises_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_enveloped
        assert_raises NativeException do 
          p7.content_new(PKCS7::NID_pkcs7_data)
        end
      end

      def test_content_new_on_signedAndEnveloped_raises_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
        assert_raises NativeException do 
          p7.content_new(PKCS7::NID_pkcs7_data)
        end
      end
      
      def test_content_new_on_digest_creates_new_content
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_digest
        p7.content_new(PKCS7::NID_pkcs7_signedAndEnveloped)
        assert p7.get_digest.contents.signed_and_enveloped?
        
        p7.content_new(PKCS7::NID_pkcs7_encrypted)
        assert p7.get_digest.contents.encrypted?
      end

      def test_content_new_on_signed_creates_new_content
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signed
        p7.content_new(PKCS7::NID_pkcs7_signedAndEnveloped)
        assert p7.get_sign.contents.signed_and_enveloped?
        
        p7.content_new(PKCS7::NID_pkcs7_encrypted)
        assert p7.get_sign.contents.encrypted?
      end

    
      def test_add_certificate_on_data_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_data
        assert_raises NativeException do 
          p7.add_certificate(X509Cert)
        end
      end

      def test_add_certificate_on_enveloped_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_enveloped
        assert_raises NativeException do 
          p7.add_certificate(X509Cert)
        end
      end

      def test_add_certificate_on_encrypted_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_encrypted
        assert_raises NativeException do 
          p7.add_certificate(X509Cert)
        end
      end

      def test_add_certificate_on_digest_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_digest
        assert_raises NativeException do 
          p7.add_certificate(X509Cert)
        end
      end

      def test_add_certificate_on_signed_adds_the_certificate
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signed
        p7.add_certificate(X509Cert)
        assert_equal 1, p7.get_sign.cert.size
        assert_equal X509Cert, p7.get_sign.cert.get(0)
      end

      def test_add_certificate_on_signedAndEnveloped_adds_the_certificate
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
        p7.add_certificate(X509Cert)
        assert_equal 1, p7.get_signed_and_enveloped.cert.size
        assert_equal X509Cert, p7.get_signed_and_enveloped.cert.get(0)
      end

      def test_add_crl_on_data_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_data
        assert_raises NativeException do 
          p7.add_crl(X509CRL)
        end
      end

      def test_add_crl_on_enveloped_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_enveloped
        assert_raises NativeException do 
          p7.add_crl(X509CRL)
        end
      end

      def test_add_crl_on_encrypted_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_encrypted
        assert_raises NativeException do 
          p7.add_crl(X509CRL)
        end
      end

      def test_add_crl_on_digest_throws_exception
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_digest
        assert_raises NativeException do 
          p7.add_crl(X509CRL)
        end
      end

      def test_add_crl_on_signed_adds_the_crl
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signed
        p7.add_crl(X509CRL)
        assert_equal 1, p7.get_sign.crl.size
        assert_equal X509CRL, p7.get_sign.crl.get(0)
      end

      def test_add_crl_on_signedAndEnveloped_adds_the_crl
        p7 = PKCS7.new
        p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
        p7.add_crl(X509CRL)
        assert_equal 1, p7.get_signed_and_enveloped.crl.size
        assert_equal X509CRL, p7.get_signed_and_enveloped.crl.get(0)
      end
    end
  end
end

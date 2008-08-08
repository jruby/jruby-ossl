module PKCS7Test
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
    
    def _test_encrypt_generates_enveloped_PKCS7_object
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
      assert_equal ri, p7.get_enveloped.recipient_info.iterator.next
    end


    def test_add_recipient_info_to_signedAndEnveloped_should_add_that_to_stack
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
      
      ri = p7.add_recipient(X509Cert)
      
      assert_equal 1, p7.get_signed_and_enveloped.recipient_info.size
      assert_equal ri, p7.get_signed_and_enveloped.recipient_info.iterator.next
    end
    
    def test_add_signer_to_something_that_cant_have_signers
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_enveloped
      assert_raises NativeException do 
        p7.add_signer(SignerInfo.new(nil, nil, nil, nil, nil, nil, nil))
      end

      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_data
      assert_raises NativeException do 
        p7.add_signer(SignerInfo.new(nil, nil, nil, nil, nil, nil, nil))
      end
      
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_encrypted
      assert_raises NativeException do 
        p7.add_signer(SignerInfo.new(nil, nil, nil, nil, nil, nil, nil))
      end
      
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_digest
      assert_raises NativeException do 
        p7.add_signer(SignerInfo.new(nil, nil, nil, nil, nil, nil, nil))
      end
    end

    def test_add_signer_to_signed_should_add_that_to_stack
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signed
      
      si = SignerInfo.new(nil, nil, nil, nil, nil, nil, nil)
      p7.add_signer(si)
      
      assert_equal 1, p7.get_sign.signer_info.size
      assert_equal si, p7.get_sign.signer_info.iterator.next
    end


    def test_add_signer_to_signedAndEnveloped_should_add_that_to_stack
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
      
      si = SignerInfo.new(nil, nil, nil, nil, nil, nil, nil)
      p7.add_signer(si)
      
      assert_equal 1, p7.get_signed_and_enveloped.signer_info.size
      assert_equal si, p7.get_signed_and_enveloped.signer_info.iterator.next
    end

    def create_signer_info_with_algo(algo)
      md5 = AlgorithmIdentifier.new(ASN1Registry.nid2obj(4))
      SignerInfo.new(DERInteger.new(BigInteger::ONE), 
                     IssuerAndSerialNumber.new(X509Name.new("C=SE"), DERInteger.new(BigInteger::ONE)), 
                     algo, 
                     DERSet.new, 
                     md5, 
                     DEROctetString.new([].to_java(:byte)), 
                     DERSet.new)
    end
    
    def test_add_signer_to_signed_with_new_algo_should_add_that_algo_to_the_algo_list
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signed

      # YES, these numbers are correct. Don't change them. They are OpenSSL internal NIDs
      md5 = AlgorithmIdentifier.new(ASN1Registry.nid2obj(4))
      md4 = AlgorithmIdentifier.new(ASN1Registry.nid2obj(5))
      
      si = create_signer_info_with_algo(md5)
      p7.add_signer(si)

      assert_equal md5, p7.get_sign.md_algs.iterator.next
      assert_equal 1, p7.get_sign.md_algs.size

      si = create_signer_info_with_algo(md5)
      p7.add_signer(si)

      assert_equal md5, p7.get_sign.md_algs.iterator.next
      assert_equal 1, p7.get_sign.md_algs.size

      si = create_signer_info_with_algo(md4)
      p7.add_signer(si)

      assert_equal 2, p7.get_sign.md_algs.size
      assert p7.get_sign.md_algs.contains(md4)
      assert p7.get_sign.md_algs.contains(md5)
    end


    def test_add_signer_to_signedAndEnveloped_with_new_algo_should_add_that_algo_to_the_algo_list
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
      
      # YES, these numbers are correct. Don't change them. They are OpenSSL internal NIDs
      md5 = AlgorithmIdentifier.new(ASN1Registry.nid2obj(4))
      md4 = AlgorithmIdentifier.new(ASN1Registry.nid2obj(5))

      si = create_signer_info_with_algo(md5)
      p7.add_signer(si)

      assert_equal md5, p7.get_signed_and_enveloped.md_algs.iterator.next
      assert_equal 1, p7.get_signed_and_enveloped.md_algs.size

      si = create_signer_info_with_algo(md5)
      p7.add_signer(si)

      assert_equal md5, p7.get_signed_and_enveloped.md_algs.iterator.next
      assert_equal 1, p7.get_signed_and_enveloped.md_algs.size

      si = create_signer_info_with_algo(md4)
      p7.add_signer(si)

      assert_equal 2, p7.get_signed_and_enveloped.md_algs.size
      assert p7.get_signed_and_enveloped.md_algs.contains(md4)
      assert p7.get_signed_and_enveloped.md_algs.contains(md5)
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
      assert_equal X509Cert, p7.get_sign.cert.iterator.next
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
      assert_equal X509CRL, p7.get_sign.crl.iterator.next
    end

    def test_add_crl_on_signedAndEnveloped_adds_the_crl
      p7 = PKCS7.new
      p7.type = PKCS7::NID_pkcs7_signedAndEnveloped
      p7.add_crl(X509CRL)
      assert_equal 1, p7.get_signed_and_enveloped.crl.size
      assert_equal X509CRL, p7.get_signed_and_enveloped.crl.get(0)
    end
    
    def test_encrypt_integration_test
      certs = [X509Cert]
      cipher = Cipher.get_instance("AES", BCP.new)
      data = "aaaaa\nbbbbb\nccccc\n".to_java_bytes
      p PKCS7::encrypt(certs, data, cipher, 0)
    end
  end
end


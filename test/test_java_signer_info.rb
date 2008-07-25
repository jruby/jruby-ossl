module PKCS7Test
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
end

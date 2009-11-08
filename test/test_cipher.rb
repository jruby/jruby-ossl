if defined?(JRUBY_VERSION)
  require "java"
  base = File.dirname(__FILE__)
  $CLASSPATH << File.join(base, '..', 'pkg', 'classes')
  $CLASSPATH << File.join(base, '..', 'lib', 'bcprov-jdk14-139.jar')
end

begin
  require "openssl"
rescue LoadError
end

require "test/unit"

class TestCipher < Test::Unit::TestCase
  def test_keylen
    cipher = OpenSSL::Cipher::Cipher.new('DES-EDE3-CBC')
    # must be 24 but it returns 16 on JRE6 without unlimited jurisdiction
    # policy. it returns 24 on JRE6 with the unlimited policy.
    assert_equal(24, cipher.key_len)
  end

  def test_encrypt_takes_parameter
    enc = OpenSSL::Cipher::Cipher.new('DES-EDE3-CBC')
    enc.encrypt("123")
    data = enc.update("password")
    data << enc.final
  end

  IV_TEMPLATE  = "aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjj"
  KEY_TEMPLATE = "aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjj"

  # JRUBY-1692
  def test_repeated_des
    do_repeated_test(
                     "des-ede3-cbc",
                     "foobarbazboofarf",
                     ":\022Q\211ex\370\332\374\274\214\356\301\260V\025",
                     "B\242\3531\003\362\3759\363s\203\374\240\030|\230"
                     )
  end

  # JRUBY-1692
  def test_repeated_aes
    do_repeated_test(
                     "aes-128-cbc",
                     "foobarbazboofarf",
                     "\342\260Y\344\306\227\004^\272|/\323<\016,\226",
                     "jqO\305/\211\216\b\373\300\274\bw\213]\310"
                     )
  end

  def test_rc2
    do_repeated_test(
                     "RC2",
                     "foobarbazboofarf",
                     "\x18imZ\x9Ed\x15\xF3\xD6\xE6M\xCDf\xAA\xD3\xFE",
		     "\xEF\xF7\x16\x06\x93)-##\xB2~\xAD,\xAD\x82\xF5"
		    )
  end

  private
  def do_repeated_test(algo, string, enc1, enc2)
    do_repeated_encrypt_test(algo, string, enc1, enc2)
    do_repeated_decrypt_test(algo, string, enc1, enc2)
  end
  
  def do_repeated_encrypt_test(algo, string, result1, result2)
    cipher = OpenSSL::Cipher::Cipher.new(algo)
    cipher.encrypt

    cipher.padding = 0
    cipher.iv      = IV_TEMPLATE[0, cipher.iv_len]
    cipher.key     = KEY_TEMPLATE[0, cipher.key_len]

    assert_equal result1, cipher.update(string)
    assert_equal "", cipher.final

    assert_equal result2, cipher.update(string) + cipher.final
  end

  def do_repeated_decrypt_test(algo, result, string1, string2)
    cipher = OpenSSL::Cipher::Cipher.new(algo)
    cipher.decrypt

    cipher.padding = 0
    cipher.iv      = IV_TEMPLATE[0, cipher.iv_len]
    cipher.key     = KEY_TEMPLATE[0, cipher.key_len]

    assert_equal result, cipher.update(string1)
    assert_equal "", cipher.final

    assert_equal result, cipher.update(string2) + cipher.final
  end
end

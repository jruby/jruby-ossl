begin
  require "openssl"
rescue LoadError
end

require "test/unit"

class TestCipher < Test::Unit::TestCase
  def test_encrypt_takes_parameter
    enc = OpenSSL::Cipher::Cipher.new('DES-EDE3-CBC')
    enc.encrypt("123")
    data = enc.update("password")
    data << enc.final
  end
end

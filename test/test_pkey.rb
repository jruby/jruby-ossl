if defined?(JRUBY_VERSION)
  require "java"
  base = File.dirname(__FILE__)
  $CLASSPATH << File.join(base, '..', 'pkg', 'classes')
  $CLASSPATH << File.join(base, '..', 'lib', 'bcprov-jdk15-144.jar')
end

begin
  require "openssl"
rescue LoadError
end

require "test/unit"

class TestPKey < Test::Unit::TestCase
  def test_has_correct_methods
    pkey_methods = OpenSSL::PKey::PKey.instance_methods(false).sort - ["initialize"]
    assert_equal ["sign", "verify"], pkey_methods

    rsa_methods = OpenSSL::PKey::RSA.instance_methods(false).sort - ["initialize"]
    assert_equal ["d", "d=", "dmp1", "dmp1=", "dmq1", "dmq1=", "e", "e=", "export", "iqmp", "iqmp=", "n", "n=", "p", "p=", "params", "private?", "private_decrypt", "private_encrypt", "public?", "public_decrypt", "public_encrypt", "public_key", "q", "q=", "to_der", "to_pem", "to_s", "to_text"], rsa_methods

    assert_equal ["generate"], OpenSSL::PKey::RSA.methods(false)
    
#     dsa_methods = OpenSSL::PKey::DSA.instance_methods(false).sort - ["initialize"]
#     assert_equal ["export", "g", "g=", "p", "p=", "params", "priv_key", "priv_key=", "private?", "pub_key", "pub_key=", "public?", "public_key", "q", "q=", "syssign", "sysverify", "to_der", "to_pem", "to_s", "to_text"], dsa_methods

#     assert_equal ["generate"], OpenSSL::PKey::DSA.methods(false)
  end
  
  #iqmp == coefficient
  #e == public exponent
  #n == modulus
  #d == private exponent
  #p == prime1
  #q == prime2
  #dmq1 == exponent2
  #dmp1 == exponent1
  
  def test_can_generate_rsa_key
    OpenSSL::PKey::RSA.generate(512)
  end

  def test_can_generate_dsa_key
  end

  # http://github.com/jruby/jruby-openssl/issues#issue/1
  def test_load_pkey
    pem = <<__EOP__
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
Lw03eHTNQghS0A==
-----END PRIVATE KEY-----
__EOP__
    pkey = OpenSSL::PKey::RSA.new(pem)
  end
end

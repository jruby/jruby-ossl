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
  def test_load_pkey_rsa
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
    assert_nothing_raised do
      pkey = OpenSSL::PKey::RSA.new(pem)
      pkey2 = OpenSSL::PKey::RSA.new(pkey.to_pem)
      assert_equal(pkey.n, pkey2.n)
      assert_equal(pkey.e, pkey2.e)
      assert_equal(pkey.d, pkey2.d)
    end
  end

  def test_load_pkey_rsa_enc
    # password is '1234'
    pem = <<__EOP__
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICoTAbBgkqhkiG9w0BBQMwDgQIfvehP6JEg2wCAggABIICgD7kzSr+xWgdAuzG
cYNkCEWyKF6V0cJ58AKSoL4FQ59OQvQP/hMnSZEMiUpeGNRE6efC7O02RUjNarIk
ciCYIBqd5EFG3OSypK5l777AbCChIkzZHbyE/pIbadr8ZX9C4pkwzPqS0Avzavxi
5s1WDX2GggJkBcQUijqG9QuOZcOvoYbojHPT4tdJq+J6s+0LFas9Jp3a6dYkxtgv
u8Z6EFDZoLGOSVy/jCSMuZAnhoOxUCYqd9FFo2jryV7tQ/CaYAUApAQFTLgBA9qk
4WmyKRpwzIx6EG1pkqulvPXJCcTat9YwllEDVuQ2rKVwDepSl9O7X170Kx1sBecz
mGcfqviU9xwP5mkXO/TLoTZExkHF08Y3d/PTMdxGEDZH37/yRqCIb3Uyqv/jLibM
/s9fm52aWsfO1ndHEhciovlMJvGXq3+e+9gmq1w2TyNQahRc5fwfhwWKhPKfYDBk
7AtjPGfELDX61WZ5m+4Kb70BcGSAEgXCaBydVsMROy0B8jkYgtAnVBb4EMrGOsCG
jmNeW9MRIhrhDcifdyq1DMNg7IONMF+5mDdQ3FhK6WzlFU+8cTN517qA8L3A3+ZX
asiS+rx5/50InINknjuvVkmTGMzjl89nMNrZCjhx9sIDfXQ3ZKFmh1mvnXq/fLan
CgXn/UtLoykrSlobgqIxZslhj3p01kMCgGe62S3kokYrDTQEc57rlKWWR3Xyjy/T
LsecXAKEROj95IHSMMnT4jl+TJnbvGKQ2U9tOOB3W+OOOlDEFE59pQlcmQPAwdzr
mzI4kupi3QRTFjOgvX29leII9sPtpr4dKMKVIRxKnvMZhUAkS/n3+Szfa6zKexLa
4CHVgDo=
-----END ENCRYPTED PRIVATE KEY-----
__EOP__
    assert_nothing_raised do
      pkey = OpenSSL::PKey::RSA.new(pem, '1234')
      pkey2 = OpenSSL::PKey::RSA.new(pkey.to_pem)
      assert_equal(pkey.n, pkey2.n)
      assert_equal(pkey.e, pkey2.e)
      assert_equal(pkey.d, pkey2.d)
    end
  end
end

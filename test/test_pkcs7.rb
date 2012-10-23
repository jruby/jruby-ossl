require 'openssl'
require "test/unit"

class TestPkcs7 < Test::Unit::TestCase

  CERT_PEM = <<END
-----BEGIN CERTIFICATE-----
MIIC8zCCAdugAwIBAgIBATANBgkqhkiG9w0BAQQFADA9MRMwEQYKCZImiZPyLGQB
GRYDb3JnMRkwFwYKCZImiZPyLGQBGRYJcnVieS1sYW5nMQswCQYDVQQDDAJDQTAe
Fw0wOTA1MjMxNTAzNDNaFw0wOTA1MjMxNjAzNDNaMD0xEzARBgoJkiaJk/IsZAEZ
FgNvcmcxGTAXBgoJkiaJk/IsZAEZFglydWJ5LWxhbmcxCzAJBgNVBAMMAkNBMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuV9ht9J7k4NBs38jOXvvTKY9
gW8nLICSno5EETR1cuF7i4pNs9I1QJGAFAX0BEO4KbzXmuOvfCpD3CU+Slp1enen
fzq/t/e/1IRW0wkJUJUFQign4CtrkJL+P07yx18UjyPlBXb81ApEmAB5mrJVSrWm
qbjs07JbuS4QQGGXLc+Su96DkYKmSNVjBiLxVVSpyZfAY3hD37d60uG+X8xdW5v6
8JkRFIhdGlb6JL8fllf/A/blNwdJOhVr9mESHhwGjwfSeTDPfd8ZLE027E5lyAVX
9KZYcU00mOX+fdxOSnGqS/8JDRh0EPHDL15RcJjV2J6vZjPb0rOYGDoMcH+94wID
AQABMA0GCSqGSIb3DQEBBAUAA4IBAQB8UTw1agA9wdXxHMUACduYu6oNL7pdF0dr
w7a4QPJyj62h4+Umxvp13q0PBw0E+mSjhXMcqUhDLjrmMcvvNGhuh5Sdjbe3GI/M
3lCC9OwYYIzzul7omvGC3JEIGfzzdNnPPCPKEWp5X9f0MKLMR79qOf+sjHTjN2BY
SY3YGsEFxyTXDdqrlaYaOtTAdi/C+g1WxR8fkPLefymVwIFwvyc9/bnp7iBn7Hcw
mbxtLPbtQ9mURT0GHewZRTGJ1aiTq9Ag3xXME2FPF04eFRd3mclOQZNXKQ+LDxYf
k0X5FeZvsWf4srFxoVxlcDdJtHh91ZRpDDJYGQlsUm9CPTnO+e4E
-----END CERTIFICATE-----
END

  def test_pkcs7_des3_key_generation_for_encrypt
    # SunJCE requires DES/DES3 keybits = 21/168 for key generation.
    # BC allows 24/192 keybits and treats it as 21/168.
    msg = "Hello World"
    password = "password"
    cert = OpenSSL::X509::Certificate.new(CERT_PEM)
    certs = [cert]
    cipher = OpenSSL::Cipher.new("des-ede3-cbc")
    cipher.encrypt
    cipher.pkcs5_keyivgen(password)
    p7 = OpenSSL::PKCS7.encrypt(certs, msg, cipher, OpenSSL::PKCS7::BINARY)
    assert_equal(msg, p7.data)
  end

  EMPTY_PEM = <<END
-----BEGIN PKCS7-----
MAMGAQA=
-----END PKCS7-----
END

  def test_empty_pkcs7
    p7 = OpenSSL::PKCS7.new
    assert_equal(EMPTY_PEM, p7.to_pem)
  end

  def test_load_empty_pkcs7
    p7 = OpenSSL::PKCS7.new(EMPTY_PEM)
    assert_equal(EMPTY_PEM, p7.to_pem)
  end
  
  def test_set_type_signed
    p7 = OpenSSL::PKCS7.new
    p7.type = "signed"
    assert_equal(p7.type, :signed)
  end
  
  def test_set_type_data
    p7 = OpenSSL::PKCS7.new
    p7.type = "data"
    assert_equal(p7.type, :data)
  end
  
  def test_set_type_signed_and_enveloped
    p7 = OpenSSL::PKCS7.new
    p7.type = "signedAndEnveloped"
    assert_equal(p7.type, :signedAndEnveloped)
  end
  
  def test_set_type_enveloped
    p7 = OpenSSL::PKCS7.new
    p7.type = "enveloped"
    assert_equal(p7.type, :enveloped)
  end
  
  def test_set_type_encrypted
    p7 = OpenSSL::PKCS7.new
    p7.type = "encrypted"
    assert_equal(p7.type, :encrypted)
  end

  def test_degenerate_pkcs7
    ca_cert_pem = <<END
-----BEGIN CERTIFICATE-----
MIID4DCCAsigAwIBAgIJAL1oVI72wmQwMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNV
BAYTAkFVMQ4wDAYDVQQIEwVTdGF0ZTENMAsGA1UEBxMEQ2l0eTEQMA4GA1UEChMH
RXhhbXBsZTETMBEGA1UEAxMKRXhhbXBsZSBDQTAeFw0xMjEwMTgwOTE2NTBaFw0y
MjEwMTYwOTE2NTBaMFMxCzAJBgNVBAYTAkFVMQ4wDAYDVQQIEwVTdGF0ZTENMAsG
A1UEBxMEQ2l0eTEQMA4GA1UEChMHRXhhbXBsZTETMBEGA1UEAxMKRXhhbXBsZSBD
QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTSPNxOkd5NN19XO0fJ
tGVlWN4DWuvVL9WbWnXJXX9rU6X8sSOL9RrRA64eEZf2UBFjz9fMHZj/OGcxZpus
4YtzfSrMU6xfvsIHeqX+mT60ms2RfX4UXab50MQArBin3JVKHGnOi25uyAOylVFU
TuzzQJvKyB67vjuRPMlVAgVAZAP07ru9gW0ajt/ODxvUfvXxp5SFF68mVP2ipMBr
4fujUwQC6cVHmnuL6p87VFoo9uk87TSQVDOQGL8MK4moMFtEW9oUTU22CgnxnCsS
sCCELYhy9BdaTWQH26LzMfhnwSuIRHZyprW4WZtU0akrYXNiCj8o92rZmQWXJDbl
qNECAwEAAaOBtjCBszAdBgNVHQ4EFgQUNtVw4jvkZZbkdQbkYi2/F4QN79owgYMG
A1UdIwR8MHqAFDbVcOI75GWW5HUG5GItvxeEDe/aoVekVTBTMQswCQYDVQQGEwJB
VTEOMAwGA1UECBMFU3RhdGUxDTALBgNVBAcTBENpdHkxEDAOBgNVBAoTB0V4YW1w
bGUxEzARBgNVBAMTCkV4YW1wbGUgQ0GCCQC9aFSO9sJkMDAMBgNVHRMEBTADAQH/
MA0GCSqGSIb3DQEBBQUAA4IBAQBvJIsY9bIqliZ3WD1KoN4cvAQeRAPsoLXQkkHg
P6Nrcw9rJ5JvoHfYbo5aNlwbnkbt/B2xlVEXUYpJoBZFXafgxG2gJleioIgnaDS4
FPPwZf1C5ZrOgUBfxTGjHex4ghSAoNGOd35jQzin5NGKOvZclPjZ2vQ++LP3aA2l
9Fn2qASS46IzMGJlC75mlTOTQwDM16UunMAK26lNG9J6q02o4d/oU2a7x0fD80yF
64kNA1wDAwaVCYiUH541qKp+b4iDqer8nf8HqzYDFlpje18xYZMEd1hj8dVOharM
pISJ+D52hV/BGEYF8r5k3hpC5d76gSP2oCcaY0XvLBf97qik
-----END CERTIFICATE-----
END
    p7 = OpenSSL::PKCS7.new
    p7.type = "signed"
    ca_cert = OpenSSL::X509::Certificate.new(ca_cert_pem)
    p7.add_certificate ca_cert
    p7.add_data ""
    
    assert_nothing_raised do
      p7.to_pem
    end
  end
end

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

  def test_split_content
     pki_message_pem = <<END
-----BEGIN PKCS7-----
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
-----END PKCS7-----
END
    pki_message_content_pem = <<END
-----BEGIN PKCS7-----
MIIDawYJKoZIhvcNAQcDoIIDXDCCA1gCAQAxggEQMIIBDAIBADB1MHAxEDAOBgNV
BAoMB2V4YW1wbGUxFzAVBgNVBAMMDlRBUk1BQyBST09UIENBMSIwIAYJKoZIhvcN
AQkBFhNzb21lb25lQGV4YW1wbGUub3JnMQswCQYDVQQGEwJVUzESMBAGA1UEBwwJ
VG93biBIYWxsAgFmMA0GCSqGSIb3DQEBAQUABIGAbKV17HvGYRtRRBNz1QLpW763
UedhVj5KXi70o4BJGM04lItAgt6aFC9SruZjpWr1gCYKCaRSAg273DeGTQwsDoZ8
6CPXzBpptYLz0MteQXYYWUaPZT+xmvx4NgDyk9P9MoT7JifsPrtXuzqCRFXhGdu8
d/ru+OWxhHLvKH+bYekwggI9BgkqhkiG9w0BBwEwFAYIKoZIhvcNAwcECBNs2U5m
Msd/gIICGFOnLq/EAc9Nv+HjKR3ZVPSJMq0TImjGf5Mvc3nDgI572Hdo2aku0YXM
6WjSWkpYtxpg7Cqxfl6hPSefLPUnBqlIoM2qbrE7MSKEVD6+2bW9GqYPFVg4qQLL
sOxnxJIMfOvLFfd7guL+iLH424XfiUUxaf8EdZE4u2IEl4REvkS1FoEGwyA4BEGM
SeVPedQCbZ0qY7Pc2tmZE3XfEUhIsyStG0Nb6i6AKcAFYGapbgE6kAB0gwsYcHlW
MOvsvdAfcTq6jwtHlO1s68qtvkWquTQ9lpX+fzddUUNxEHSqv5eU3oo6fT3Vj5ZF
IVlaA5ThZMrI5PgRPuwJM4GL8/VLwY5mbDLFqn/irGeEvP99J3S87ornLLunjpxS
y1/AymcVep2H32Tj82WS/IRQXBOzz4EnQRJGszKxAV6tY+Zje3sWyTTgObhlsiTQ
TDgnvtSW8RvVHqKrwgkxxEsRHg7u8UdzZ0jg+O5+3F8B6/NWMyts0OaFqT9wvI8y
O7VIy3dUtGdz7Hde6Ggp/iTn1LbgdJ3N8Hzxf1j6NMWUKHVsadvwpRJbUeqq9c3+
QuxsJi8wWemxxQCE+tPyc1dP+ej5/M7bERbSOHMGgX03758IvP7A/fy2DjGPv2+l
AwlEke0Uze1367QKgxM0nc3SZDlptY7zPIJC5saWXb8Rt2bw2JxEBOTavrp+ZwJ8
tcH961onq8Tme2ICaCzk
-----END PKCS7-----
END
    pki_msg = OpenSSL::PKCS7.new(pki_message_pem)
    store = OpenSSL::X509::Store.new
    pki_msg.verify(nil, store, nil, OpenSSL::PKCS7::NOVERIFY)
    p7enc = OpenSSL::PKCS7.new(pki_msg.data)
    assert_equal(p7enc.to_pem, pki_message_content_pem) 
  end

end

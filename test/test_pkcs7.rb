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

  PKCS7_ENCODED = <<END
MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEH
AaCAJIAEggNDMIAGCSqGSIb3DQEHA6CAMIACAQAxge8wgewCAQAwVTBPMQ0w
CwYDVQQKDAROb25lMT4wPAYDVQQDDDVtaGF1Y2sgUm9vdCBDQSAoMjc3YWYy
YjMtYWMzZC00YjUzLTg4YzItOGMxOWYzZTY5YWE3KQICAgkwDQYJKoZIhvcN
AQEBBQAEgYBO/v799CxX01nBuOE0HbQlJeZY9DD0dcpyss8C7rqLwuAbNf5F
Ctb63amW/If8MgCFYTZoQgbleDugJBEGDa6+9t/VYivPX4E4Gy8lwn5giQsC
E4O17Xj2w9Dnina5YlaSWFX16rCRXFJcGnRtAh37luM8hBVlhvtTEIGzO7pG
mzCABgkqhkiG9w0BBwEwFAYIKoZIhvcNAwcECBwGOYbO/8iyoIAEggIAE5fd
HnQILZOp1jOg0lU3ycXNew+6O75htpilXT7WsMXWR/veFbN+FfC1QjzjC5jj
Ze7JqJ5cCP7jYQJ5sUFED6xU+m2iB4Tp8akCW4solC7bn3tbqVLYZeIGeP1Y
lCAswysgFNX+SQixkXYRi6Hpjr3VsNcqBPgtSxMF1thPJDJH0IctIWPjsY1y
YU75vsNpW5H4XdaPyhb7L9PH8EFwjZGHs13SjRI2QHN2jv818+0jMisEfRV0
NOKZC7GAc2fiZEfnOclfs0CByS5TbkfRXSIXffDevGrf6xDldCnSlj5/BrxV
vKpWmsIaZBzOMlVYOLbGdNKCiWabX4tEN2ZI3G5Cl9HXkvsJD0Yyfws9Hm+k
S8bieL89AsgOkcraF1/ovvYFb+j1LggsyGggvc8g8sChOMyaej/GHzdF+ITe
Q4JSKP2ULVkgnZw3BAsQkgKYSfX9vX2QGGkIdu4B/RUkT4/zLEzpsrPr6YI2
NO+pz19Ye4ixQHEjAq1A2/d3JAlPK7ilm1LsyoMxte0Z3YT3UL1x/I7eukeo
RZWfVTK6eWEOvI2y/Lb4TH9LCTWG9yzohC/I27FyDU2WO/DbuxNxHSisSAe8
nRn/qu7lAa4i9hQhM9yCAzfCDcape1q7KAGMmDfEsHHl4dPgEStD9BD+kjRk
9/7VwesBGk1REenz/1gECLNU/weFEqHDAAAAAAAAAAAAAAAAAAAAAKCCAeow
ggHmMIIBT6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMC8xLTArBgNVBAMTJDE4
Q0I2RUM0LUVEMzItNEI1MS1CNjhCLUYxMTc2M0YxQUIzQTAeFw0xMjA1MDEw
NzExMzVaFw0xMzA1MDEwNzExMzVaMC8xLTArBgNVBAMTJDE4Q0I2RUM0LUVE
MzItNEI1MS1CNjhCLUYxMTc2M0YxQUIzQTCBnzANBgkqhkiG9w0BAQEFAAOB
jQAwgYkCgYEAtsSbSGPJ66FAPKXpeTloXZ2Et0y5HqfbBsckq/7ZYyYXYH0e
kSHcq1AXb80d4Os7fUg2g+v8JWOJ5/glauHX16LELZu+n69DnHmf7zKMBMl9
ZpmfDPKPId2vc9uhJZrztmx7oR7c/3o3VzxwiXJYuOrzG0MFoq1tjDQV8F/w
mikCAwEAAaMSMBAwDgYDVR0PAQH/BAQDAgWgMA0GCSqGSIb3DQEBBQUAA4GB
AGfsA2uxZnMEl1UDSFP3hX+Y+71AxYqYbOMbuXIKyO7T2OCUBt1UdP5tmMN4
LTpaTk1BrbXVoDxxNnjCGIWvEkafSK4b4yr9DPrBVF1n9CgtR4W0qkpLG1jP
AcCKN6uBxDqyr7VCQXzVlYeKgj8TtO4B7xWQ+2dZ7E6E+QlxNePIMYIBqjCC
AaYCAQEwNDAvMS0wKwYDVQQDEyQxOENCNkVDNC1FRDMyLTRCNTEtQjY4Qi1G
MTE3NjNGMUFCM0ECAQEwCQYFKw4DAhoFAKCBzTASBgpghkgBhvhFAQkCMQQT
AjE5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8X
DTEyMDUwMTA3MTEzNVowIAYKYIZIAYb4RQEJBTESBBCjDtiprW/z/yhpXTez
P3j7MCMGCSqGSIb3DQEJBDEWBBTRqZ0CJJnkCJNn148ZdfBYS1u0dDA4Bgpg
hkgBhvhFAQkHMSoTKEE1NEQ3NTdDQjhEOTA0M0IxQzFFOTJDNzc3NUU1ODU3
QjRGQ0E0MzIwDQYJKoZIhvcNAQEBBQAEgYBEmCQpweH01WUzed+GIN93+Rfc
c1QT8j+w/m0UzCOtZwHs9PcxZeabNXgGXd9tfP5UqTna1Rpq4byyYBsyYXca
DsYHCOlb0vH4UqfXJxt2P/ZsA2Oab/RR6in8YnpkJfvy+iaXK9U7Czkfv7q3
NV1hYCfOJGunDqHTNx8dMwWkWgAAAAAAAA==
END

  PKCS7_DECODED = <<END
-----BEGIN PKCS7-----
MIIDOQYJKoZIhvcNAQcDoIIDKjCCAyYCAQAxge8wgewCAQAwVTBPMQ0wCwYDVQQK
DAROb25lMT4wPAYDVQQDDDVtaGF1Y2sgUm9vdCBDQSAoMjc3YWYyYjMtYWMzZC00
YjUzLTg4YzItOGMxOWYzZTY5YWE3KQICAgkwDQYJKoZIhvcNAQEBBQAEgYBO/v79
9CxX01nBuOE0HbQlJeZY9DD0dcpyss8C7rqLwuAbNf5FCtb63amW/If8MgCFYTZo
QgbleDugJBEGDa6+9t/VYivPX4E4Gy8lwn5giQsCE4O17Xj2w9Dnina5YlaSWFX1
6rCRXFJcGnRtAh37luM8hBVlhvtTEIGzO7pGmzCCAi0GCSqGSIb3DQEHATAUBggq
hkiG9w0DBwQIHAY5hs7/yLKAggIIE5fdHnQILZOp1jOg0lU3ycXNew+6O75htpil
XT7WsMXWR/veFbN+FfC1QjzjC5jjZe7JqJ5cCP7jYQJ5sUFED6xU+m2iB4Tp8akC
W4solC7bn3tbqVLYZeIGeP1YlCAswysgFNX+SQixkXYRi6Hpjr3VsNcqBPgtSxMF
1thPJDJH0IctIWPjsY1yYU75vsNpW5H4XdaPyhb7L9PH8EFwjZGHs13SjRI2QHN2
jv818+0jMisEfRV0NOKZC7GAc2fiZEfnOclfs0CByS5TbkfRXSIXffDevGrf6xDl
dCnSlj5/BrxVvKpWmsIaZBzOMlVYOLbGdNKCiWabX4tEN2ZI3G5Cl9HXkvsJD0Yy
fws9Hm+kS8bieL89AsgOkcraF1/ovvYFb+j1LggsyGggvc8g8sChOMyaej/GHzdF
+ITeQ4JSKP2ULVkgnZw3BAsQkgKYSfX9vX2QGGkIdu4B/RUkT4/zLEzpsrPr6YI2
NO+pz19Ye4ixQHEjAq1A2/d3JAlPK7ilm1LsyoMxte0Z3YT3UL1x/I7eukeoRZWf
VTK6eWEOvI2y/Lb4TH9LCTWG9yzohC/I27FyDU2WO/DbuxNxHSisSAe8nRn/qu7l
Aa4i9hQhM9yCAzfCDcape1q7KAGMmDfEsHHl4dPgEStD9BD+kjRk9/7VwesBGk1R
Eenz/1izVP8HhRKhww==
-----END PKCS7-----
END

  def test_signed_pkcs7_octet_sequence
    p7signed = OpenSSL::PKCS7.new(PKCS7_ENCODED.unpack('m*').first)
    p7signed.verify(nil, OpenSSL::X509::Store.new, nil, OpenSSL::PKCS7::NOVERIFY)

    p7 = OpenSSL::PKCS7.new(p7signed.data)

    assert_equal(p7.to_pem, PKCS7_DECODED)
  end

  def test_degenerate_pkcs7_add_cert
    p7 = OpenSSL::PKCS7.new
    cert = OpenSSL::X509::Certificate.new(CERT_PEM)
    p7.type = 'signed'

    assert_nothing_raised do
      p7.add_certificate(cert)
    end
  end
end

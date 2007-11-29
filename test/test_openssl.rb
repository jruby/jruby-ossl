
if RUBY_PLATFORM =~ /java/
  require 'java'
  runTests = false
  begin
    java.lang.StringBuilder
    runTests = true
  rescue 
    nil
  end
else
  runTests = true
end

if runTests
# won't work, since kill and pid is used.
#  require 'test/openssl/test_ssl'
  require 'test/openssl/test_asn1'
  require 'test/openssl/test_cipher'
  require 'test/openssl/test_digest'
  require 'test/openssl/test_hmac'
  require 'test/openssl/test_ns_spki'
  require 'test/openssl/test_pkey_rsa'
  require 'test/openssl/test_x509cert'
  require 'test/openssl/test_x509crl'
  require 'test/openssl/test_x509name'
  require 'test/openssl/test_x509ext'
  require 'test/openssl/test_x509req'
  require 'test/openssl/test_x509store'
end

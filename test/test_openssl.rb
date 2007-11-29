
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
  require 'openssl/test_asn1'
  require 'openssl/test_cipher'
  require 'openssl/test_digest'
  require 'openssl/test_hmac'
  require 'openssl/test_ns_spki'
  require 'openssl/test_pair'
  require 'openssl/test_pkey_rsa'
#  require 'openssl/test_ssl' # won't work, since kill and pid is used.
  require 'openssl/test_x509cert'
  require 'openssl/test_x509crl'
  require 'openssl/test_x509name'
  require 'openssl/test_x509ext'
  require 'openssl/test_x509req'
  require 'openssl/test_x509store'
end


run_tests = true
if RUBY_PLATFORM =~ /java/
  require 'java'
  run_tests = false
  begin
    java.lang.StringBuilder
    run_tests = true
  rescue 
    nil
  end
end

if run_tests
  require 'openssl/test_asn1'
  require 'openssl/test_cipher'
  require 'openssl/test_digest'
  require 'openssl/test_hmac'
  require 'openssl/test_ns_spki'
  # require 'openssl/test_pair'
  require 'openssl/test_pkey_rsa'
  # require 'openssl/test_ssl' # won't work, since kill and pid is used.
  require 'openssl/test_x509cert'
  require 'openssl/test_x509crl'
  require 'openssl/test_x509name'
  require 'openssl/test_x509ext'
  require 'openssl/test_x509req'
  require 'openssl/test_x509store'
end

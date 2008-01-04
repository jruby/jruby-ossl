
require 'java' if RUBY_PLATFORM =~ /java/
begin
  require 'openssl/test_asn1'
  require 'openssl/test_cipher'
  require 'openssl/test_digest'
  require 'openssl/test_hmac'
  require 'openssl/test_ns_spki'
  # require 'openssl/test_pair'
  require 'openssl/test_pkey_rsa'
  require 'openssl/test_ssl'
  require 'openssl/test_x509cert'
  require 'openssl/test_x509crl'
  require 'openssl/test_x509name'
  require 'openssl/test_x509ext'
  require 'openssl/test_x509req'
  require 'openssl/test_x509store'
rescue Exception => e
  $stderr.puts "Had exception: #{e.inspect}"
  $stderr.puts(*(e.backtrace))
end

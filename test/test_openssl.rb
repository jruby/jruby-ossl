
require 'java' if RUBY_PLATFORM =~ /java/

def protect_require(name)
  require name
rescue Exception => e
  $stderr.puts "Had exception in #{name}: #{e.inspect}"
  $stderr.puts(*(e.backtrace))
end

protect_require 'openssl/test_asn1'
protect_require 'openssl/test_cipher'
protect_require 'openssl/test_digest'
protect_require 'openssl/test_hmac'
protect_require 'openssl/test_ns_spki'
protect_require 'openssl/test_pair'
protect_require 'openssl/test_pkcs7'
protect_require 'openssl/test_pkey_rsa'
protect_require 'openssl/test_ssl'
protect_require 'openssl/test_x509cert'
protect_require 'openssl/test_x509crl'
protect_require 'openssl/test_x509ext'
protect_require 'openssl/test_x509name'
protect_require 'openssl/test_x509req'
protect_require 'openssl/test_x509store'
protect_require 'test_cipher'

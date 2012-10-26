# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "jruby-openssl"
  s.version = "0.7.8"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Ola Bini and JRuby contributors"]
  s.date = "2012-10-26"
  s.description = "JRuby-OpenSSL is an add-on gem for JRuby that emulates the Ruby OpenSSL native library."
  s.email = "ola.bini@gmail.com"
  s.extra_rdoc_files = ["History.txt", "Manifest.txt", "README.txt", "License.txt"]
  s.files = ["Rakefile", "History.txt", "Manifest.txt", "README.txt", "License.txt", "lib/shared/jopenssl.jar", "lib/shared/openssl.rb", "lib/shared/jopenssl/version.rb", "lib/shared/openssl/pkcs12.rb", "lib/shared/openssl/dummyssl.rb", "lib/shared/openssl/ssl.rb", "lib/shared/openssl/dummy.rb", "lib/shared/openssl/x509.rb", "lib/1.9/openssl.rb", "lib/1.9/openssl/config.rb", "lib/1.9/openssl/ssl.rb", "lib/1.9/openssl/buffering.rb", "lib/1.9/openssl/x509-internal.rb", "lib/1.9/openssl/x509.rb", "lib/1.9/openssl/cipher.rb", "lib/1.9/openssl/digest.rb", "lib/1.9/openssl/ssl-internal.rb", "lib/1.9/openssl/bn.rb", "lib/1.8/openssl.rb", "lib/1.8/openssl/config.rb", "lib/1.8/openssl/ssl.rb", "lib/1.8/openssl/buffering.rb", "lib/1.8/openssl/pkcs7.rb", "lib/1.8/openssl/x509-internal.rb", "lib/1.8/openssl/x509.rb", "lib/1.8/openssl/cipher.rb", "lib/1.8/openssl/digest.rb", "lib/1.8/openssl/ssl-internal.rb", "lib/1.8/openssl/bn.rb", "test/test_all.rb", "test/test_certificate.rb", "test/test_imaps.rb", "test/test_parse_certificate.rb", "test/test_java.rb", "test/test_cipher.rb", "test/ut_eof.rb", "test/test_pkcs7.rb", "test/test_integration.rb", "test/test_pkey_dsa.rb", "test/cert_with_ec_pk.cer", "test/test_openssl.rb", "test/test_pkey_rsa.rb", "test/test_ssl.rb", "test/test_x509store.rb", "test/java/test_java_mime.rb", "test/java/pkcs7_mime_signed.message", "test/java/pkcs7_multipart_signed.message", "test/java/test_java_pkcs7.rb", "test/java/pkcs7_mime_enveloped.message", "test/java/test_java_bio.rb", "test/java/test_java_smime.rb", "test/java/test_java_attribute.rb", "test/ruby/envutil.rb", "test/ruby/ut_eof.rb", "test/1.9/ssl_server.rb", "test/1.9/utils.rb", "test/1.9/test_hmac.rb", "test/1.9/test_x509cert.rb", "test/1.9/test_pkey_dh.rb", "test/1.9/test_asn1.rb", "test/1.9/test_cipher.rb", "test/1.9/test_pkcs7.rb", "test/1.9/test_x509name.rb", "test/1.9/test_pkey_dsa.rb", "test/1.9/test_x509ext.rb", "test/1.9/test_ns_spki.rb", "test/1.9/test_x509crl.rb", "test/1.9/test_pkcs12.rb", "test/1.9/test_engine.rb", "test/1.9/test_digest.rb", "test/1.9/test_pkey_ec.rb", "test/1.9/test_bn.rb", "test/1.9/test_ocsp.rb", "test/1.9/test_pkey_rsa.rb", "test/1.9/test_x509req.rb", "test/1.9/test_config.rb", "test/1.9/test_ssl_session.rb", "test/1.9/test_ssl.rb", "test/1.9/test_pair.rb", "test/1.9/test_buffering.rb", "test/1.9/test_x509store.rb", "test/ref/a.out", "test/ref/compile.rb", "test/ref/pkcs1.c", "test/ref/pkcs1", "test/fixture/common.pem", "test/fixture/key_then_cert.pem", "test/fixture/verisign.pem", "test/fixture/cert_localhost.pem", "test/fixture/ids_in_subject_rdn_set.pem", "test/fixture/max.pem", "test/fixture/localhost_keypair.pem", "test/fixture/verisign_c3.pem", "test/fixture/selfcert.pem", "test/fixture/ca-bundle.crt", "test/fixture/cacert.pem", "test/fixture/keypair.pem", "test/fixture/purpose/sslclient.pem", "test/fixture/purpose/sslserver_no_dsig_in_keyUsage.pem", "test/fixture/purpose/sslserver.pem", "test/fixture/purpose/b70a5bc1.0", "test/fixture/purpose/cacert.pem", "test/fixture/purpose/sslserver/sslserver.pem", "test/fixture/purpose/sslserver/csr.pem", "test/fixture/purpose/sslserver/keypair.pem", "test/fixture/purpose/scripts/init_ca.rb", "test/fixture/purpose/scripts/gen_cert.rb", "test/fixture/purpose/scripts/gen_csr.rb", "test/fixture/purpose/ca/PASSWD_OF_CA_KEY_IS_1234", "test/fixture/purpose/ca/ca_config.rb", "test/fixture/purpose/ca/cacert.pem", "test/fixture/purpose/ca/serial", "test/fixture/purpose/ca/newcerts/2_cert.pem", "test/fixture/purpose/ca/newcerts/3_cert.pem", "test/fixture/purpose/ca/newcerts/4_cert.pem", "test/fixture/purpose/ca/private/cakeypair.pem", "test/fixture/purpose/sslclient/sslclient.pem", "test/fixture/purpose/sslclient/csr.pem", "test/fixture/purpose/sslclient/keypair.pem", "test/fixture/imaps/server.key", "test/fixture/imaps/server.crt", "test/fixture/imaps/cacert.pem", "test/fixture/ca_path/72fa7371.0", "test/fixture/ca_path/verisign.pem", "test/1.8/ssl_server.rb", "test/1.8/utils.rb", "test/1.8/test_hmac.rb", "test/1.8/test_x509cert.rb", "test/1.8/test_ec.rb", "test/1.8/test_asn1.rb", "test/1.8/test_cipher.rb", "test/1.8/test_pkcs7.rb", "test/1.8/test_x509name.rb", "test/1.8/test_x509ext.rb", "test/1.8/test_ns_spki.rb", "test/1.8/test_x509crl.rb", "test/1.8/test_digest.rb", "test/1.8/test_pkey_rsa.rb", "test/1.8/test_x509req.rb", "test/1.8/test_config.rb", "test/1.8/test_ssl.rb", "test/1.8/test_pair.rb", "test/1.8/test_x509store.rb", ".gemtest"]
  s.homepage = "https://github.com/jruby/jruby-ossl"
  s.rdoc_options = ["--main", "README.txt"]
  s.require_paths = ["lib/shared"]
  s.rubyforge_project = "jruby-extras"
  s.rubygems_version = "1.8.24"
  s.summary = "OpenSSL add-on for JRuby"
  s.test_files = ["test/test_all.rb"]

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<bouncy-castle-java>, [">= 1.5.0146.1"])
    else
      s.add_dependency(%q<bouncy-castle-java>, [">= 1.5.0146.1"])
    end
  else
    s.add_dependency(%q<bouncy-castle-java>, [">= 1.5.0146.1"])
  end
end

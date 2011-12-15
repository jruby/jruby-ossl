# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{jruby-openssl}
  s.version = "0.7.5.dev"

  s.required_rubygems_version = Gem::Requirement.new("> 1.3.1") if s.respond_to? :required_rubygems_version=
  s.authors = [%q{Ola Bini and JRuby contributors}]
  s.date = %q{2011-12-15}
  s.description = %q{JRuby-OpenSSL is an add-on gem for JRuby that emulates the Ruby OpenSSL native library.}
  s.email = %q{ola.bini@gmail.com}
  s.extra_rdoc_files = [%q{History.txt}, %q{Manifest.txt}, %q{README.txt}, %q{License.txt}]
  s.files = [%q{Rakefile}, %q{History.txt}, %q{Manifest.txt}, %q{README.txt}, %q{License.txt}, %q{lib/jopenssl.jar}, %q{lib/openssl.rb}, %q{lib/openssl}, %q{lib/jopenssl}, %q{lib/openssl/bn.rb}, %q{lib/openssl/dummyssl.rb}, %q{lib/openssl/pkcs7.rb}, %q{lib/openssl/cipher.rb}, %q{lib/openssl/digest.rb}, %q{lib/openssl/ssl.rb}, %q{lib/openssl/buffering.rb}, %q{lib/openssl/x509.rb}, %q{lib/openssl/config.rb}, %q{lib/openssl/dummy.rb}, %q{lib/jopenssl/version.rb}, %q{test/ref}, %q{test/test_all.rb}, %q{test/test_pkey_dsa.rb}, %q{test/fixture}, %q{test/test_integration.rb}, %q{test/test_ssl.rb}, %q{test/test_parse_certificate.rb}, %q{test/test_openssl.rb}, %q{test/cert_with_ec_pk.cer}, %q{test/java}, %q{test/ut_eof.rb}, %q{test/test_x509store.rb}, %q{test/test_imaps.rb}, %q{test/test_certificate.rb}, %q{test/test_pkcs7.rb}, %q{test/test_cipher.rb}, %q{test/test_pkey_rsa.rb}, %q{test/openssl}, %q{test/test_java.rb}, %q{test/ref/a.out}, %q{test/ref/pkcs1}, %q{test/ref/pkcs1.c}, %q{test/ref/compile.rb}, %q{test/fixture/common.pem}, %q{test/fixture/ca_path}, %q{test/fixture/key_then_cert.pem}, %q{test/fixture/imaps}, %q{test/fixture/keypair.pem}, %q{test/fixture/cacert.pem}, %q{test/fixture/verisign.pem}, %q{test/fixture/purpose}, %q{test/fixture/cert_localhost.pem}, %q{test/fixture/selfcert.pem}, %q{test/fixture/max.pem}, %q{test/fixture/localhost_keypair.pem}, %q{test/fixture/ids_in_subject_rdn_set.pem}, %q{test/fixture/ca-bundle.crt}, %q{test/fixture/verisign_c3.pem}, %q{test/fixture/ca_path/72fa7371.0}, %q{test/fixture/ca_path/verisign.pem}, %q{test/fixture/imaps/cacert.pem}, %q{test/fixture/imaps/server.crt}, %q{test/fixture/imaps/server.key}, %q{test/fixture/purpose/ca}, %q{test/fixture/purpose/sslclient}, %q{test/fixture/purpose/scripts}, %q{test/fixture/purpose/sslserver_no_dsig_in_keyUsage.pem}, %q{test/fixture/purpose/cacert.pem}, %q{test/fixture/purpose/sslserver}, %q{test/fixture/purpose/sslserver.pem}, %q{test/fixture/purpose/sslclient.pem}, %q{test/fixture/purpose/b70a5bc1.0}, %q{test/fixture/purpose/ca/serial}, %q{test/fixture/purpose/ca/gen_cert.rb}, %q{test/fixture/purpose/ca/PASSWD_OF_CA_KEY_IS_1234}, %q{test/fixture/purpose/ca/ca_config.rb}, %q{test/fixture/purpose/ca/cacert.pem}, %q{test/fixture/purpose/ca/private}, %q{test/fixture/purpose/ca/newcerts}, %q{test/fixture/purpose/ca/private/cakeypair.pem}, %q{test/fixture/purpose/ca/newcerts/4_cert.pem}, %q{test/fixture/purpose/ca/newcerts/3_cert.pem}, %q{test/fixture/purpose/ca/newcerts/2_cert.pem}, %q{test/fixture/purpose/sslclient/csr.pem}, %q{test/fixture/purpose/sslclient/keypair.pem}, %q{test/fixture/purpose/sslclient/sslclient.pem}, %q{test/fixture/purpose/scripts/gen_cert.rb}, %q{test/fixture/purpose/scripts/init_ca.rb}, %q{test/fixture/purpose/scripts/gen_csr.rb}, %q{test/fixture/purpose/sslserver/csr.pem}, %q{test/fixture/purpose/sslserver/keypair.pem}, %q{test/fixture/purpose/sslserver/sslserver.pem}, %q{test/java/pkcs7_mime_enveloped.message}, %q{test/java/test_java_attribute.rb}, %q{test/java/test_java_pkcs7.rb}, %q{test/java/test_java_mime.rb}, %q{test/java/pkcs7_mime_signed.message}, %q{test/java/test_java_smime.rb}, %q{test/java/pkcs7_multipart_signed.message}, %q{test/java/test_java_bio.rb}, %q{test/openssl/test_asn1.rb}, %q{test/openssl/ssl_server.rb}, %q{test/openssl/test_x509ext.rb}, %q{test/openssl/utils.rb}, %q{test/openssl/test_ssl.rb}, %q{test/openssl/test_ec.rb}, %q{test/openssl/test_ns_spki.rb}, %q{test/openssl/test_digest.rb}, %q{test/openssl/test_pair.rb}, %q{test/openssl/test_x509crl.rb}, %q{test/openssl/test_x509store.rb}, %q{test/openssl/test_pkcs7.rb}, %q{test/openssl/test_cipher.rb}, %q{test/openssl/test_pkey_rsa.rb}, %q{test/openssl/test_x509req.rb}, %q{test/openssl/test_x509name.rb}, %q{test/openssl/test_hmac.rb}, %q{test/openssl/test_x509cert.rb}, %q{test/openssl/test_config.rb}, %q{.gemtest}]
  s.homepage = %q{http://jruby-extras.rubyforge.org/jruby-openssl}
  s.rdoc_options = [%q{--main}, %q{README.txt}]
  s.require_paths = [%q{lib}]
  s.rubyforge_project = %q{jruby-extras}
  s.rubygems_version = %q{1.8.9}
  s.summary = %q{OpenSSL add-on for JRuby}
  s.test_files = [%q{test/test_all.rb}]

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

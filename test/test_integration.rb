if defined?(JRUBY_VERSION)
  require "java"
  base = File.join(File.dirname(__FILE__), '..')
  $CLASSPATH << File.join(base, 'pkg', 'classes')
  $CLASSPATH << File.join(base, 'lib', 'bcprov-jdk14-139.jar')
end

begin
  require "openssl"
rescue LoadError
end
require "test/unit"

class TestIntegration < Test::Unit::TestCase
  # JRUBY-2471
  def _test_drb
    config = {
      :SSLVerifyMode => OpenSSL::SSL::VERIFY_PEER,
      :SSLCACertificateFile => File.join(File.dirname(__FILE__), "fixture", "cacert.pem"),
      :SSLPrivateKey => OpenSSL::PKey::RSA.new(File.read(File.join(File.dirname(__FILE__), "fixture", "localhost_keypair.pem"))),
      :SSLCertificate => OpenSSL::X509::Certificate.new(File.read(File.join(File.dirname(__FILE__), "fixture", "cert_localhost.pem"))),
    }
    p config
    DRb.start_service(nil, nil, config)
  end
end

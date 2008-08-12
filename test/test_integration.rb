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
require 'net/https'

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

  # JRUBY-2913
  # Warning - this test actually uses the internet connection.
  # If there is no connection, it will fail.
  def test_ca_path_name
    uri = URI.parse('https://www.paypal.com')

    http = Net::HTTP.new(uri.host, uri.port)
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.ca_path = "./"
    http.use_ssl = true

    response = http.start do |s|
      assert s.get(uri.request_uri).length > 0
    end
  end
end

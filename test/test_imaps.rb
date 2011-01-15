require "net/imap"
require "test/unit"

# This testcase is made for 1.8 based on test_imap.rb in CRuby 1.9
class IMAPTest < Test::Unit::TestCase
  CA_FILE = File.expand_path("fixture/imaps/cacert.pem", File.dirname(__FILE__))
  SERVER_KEY = File.expand_path("fixture/imaps/server.key", File.dirname(__FILE__))
  SERVER_CERT = File.expand_path("fixture/imaps/server.crt", File.dirname(__FILE__))

  SERVER_ADDR = "127.0.0.1"

  def setup
    @do_not_reverse_lookup = Socket.do_not_reverse_lookup
    Socket.do_not_reverse_lookup = true
  end

  def teardown
    Socket.do_not_reverse_lookup = @do_not_reverse_lookup
  end

  def test_imaps_unknown_ca
    assert_raise(OpenSSL::SSL::SSLError) do
      imaps_test do |port|
        begin
          Net::IMAP.new("localhost", port, true, nil, true)
        rescue SystemCallError
          skip $!
        end
      end
    end
  end

  def test_imaps_with_ca_file
    assert_nothing_raised do
      imaps_test do |port|
        begin
          Net::IMAP.new("localhost", port, true, CA_FILE, true)
        rescue SystemCallError
          skip $!
        end
      end
    end
  end

  def test_imaps_verify_none
    assert_nothing_raised do
      imaps_test do |port|
        Net::IMAP.new(SERVER_ADDR, port, true, nil, false)
      end
    end
  end

  def test_imaps_post_connection_check
    assert_raise(OpenSSL::SSL::SSLError) do
      imaps_test do |port|
        # SERVER_ADDR is different from the hostname in the certificate,
        # so the following code should raise a SSLError.
        Net::IMAP.new(SERVER_ADDR, port, true, CA_FILE, true)
      end
    end
  end

private

  def imaps_test
    server = create_tcp_server
    port = server.addr[1]
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.ca_file = CA_FILE
    ctx.key = OpenSSL::PKey::RSA.new(File.read(SERVER_KEY))
    ctx.cert = OpenSSL::X509::Certificate.new(File.read(SERVER_CERT))
    ssl_server = OpenSSL::SSL::SSLServer.new(server, ctx)
    Thread.start do
      begin
        sock = ssl_server.accept
        begin
          sock.print("* OK test server\r\n")
          sock.gets
          sock.print("* BYE terminating connection\r\n")
          sock.print("RUBY0001 OK LOGOUT completed\r\n")
        ensure
          sock.close
        end
      rescue
      end
    end
    begin
      begin
        imap = yield(port)
        imap.logout
      ensure
        imap.disconnect if imap
      end
    ensure
      ssl_server.close
    end
  end

  def create_tcp_server
    return TCPServer.new(SERVER_ADDR, 0)
  end
end

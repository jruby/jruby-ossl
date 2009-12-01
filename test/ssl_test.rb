  require 'net/https'
  uri = URI.parse('https://www.amazon.com/')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.ca_file = 'test/fixture/verisign_c3.pem'
  # this code must raise OpenSSL::SSL::SSLError
  # because it's not a right trust anchor for
  # www.amazon.com 
  response = http.start do |s|
    s.get(uri.request_uri)
  end
  # this code must fail as well because of illegal
  # trust anchor setting (no certs is the dir)
  http.ca_path = '/tmp'
  response = http.start do |s|
    s.get(uri.request_uri)
  end
  # verisign.pem is a right trust anchor for www.amazon.com
  http.ca_file = 'test/fixture/verisign.pem'
  # only this request must be successful.
  response = http.start do |s|
    s.get(uri.request_uri)
  end

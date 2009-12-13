require 'openssl'
require 'base64'

K = Base64.decode64("LY+48E3dTPGyNoZOeMjetOAzhY99PdIybusLhgfNJXs=")
I = Base64.decode64("4/XivbUeO4YPJgBt78m7KQ==")

cipher = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
cipher.encrypt
cipher.key, cipher.iv = K, I

secure = cipher.update("hello world")
secure << cipher.final

puts Base64.encode64(secure)

cipher = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
cipher.decrypt
cipher.key, cipher.iv = K, I
plain = cipher.update(secure)
plain << cipher.final

puts plain



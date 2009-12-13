require 'openssl'

unencrypted_data = "test"

des = OpenSSL::Cipher::Cipher.new("des-ede3-cbc")
des.encrypt
des.key = '0123456789abcdef01234567890'

des.iv = "ed87acdcca419954edccb736f7dc77a74f5ac8dfe3861c3d5f77248e21592131a5423d63ff91f07956ce1aa386f8359931b5" # 100 characters
encrypted_data = des.update(unencrypted_data) + des.final  

p encrypted_data

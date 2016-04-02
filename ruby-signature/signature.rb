require 'openssl'
require 'base64'
require 'json'

def get_digest
  OpenSSL::Digest::SHA256.new
end

## Verifying

# get key
ecdsa_public = OpenSSL::PKey::EC.new File.read('public_key.ecdsa.pem')

# get document
document = JSON.parse File.read('document.json')

# get signature
signature = Base64.decode64(document['signature'])

result = false
begin
  result = ecdsa_public.verify(get_digest, signature, document['cleartext'])
rescue => ex
  puts "error during verification. #{ ex.message }"
  exit 1
end

if result
  puts "ok"
else
  puts "failed"
  exit 1
end

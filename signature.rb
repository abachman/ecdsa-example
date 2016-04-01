require 'openssl'
require 'base64'
require 'json'

def get_digest
  OpenSSL::Digest::SHA256.new
end

## Verifying
# ecdsa_public = OpenSSL::PKey::EC.new File.read('public_key.ecdsa.pem')

## Signing
puts "loading signing key"
ecdsa_private = OpenSSL::PKey::EC.new File.read('private.ecdsa.secure.pem'), 'my secure pass phrase goes here'

# Patch to suport ECDSA signature generation in Ruby
# https://redmine.ruby-lang.org/issues/5600
OpenSSL::PKey::EC.send(:alias_method, :private?, :private_key?)

known_cleartext = (0..64).inject("") {|memo, obj| memo += "%02x" % [rand(255)]}

document = %[{
  "cleartext": "#{known_cleartext}",
  "signature": "#{Base64.encode64(ecdsa_private.sign(get_digest, known_cleartext)).gsub("\n",'').chomp}"
}]

# export signed document
open 'document.json', 'w' do |io|
  io.write document
end

puts "generated document:"
puts document

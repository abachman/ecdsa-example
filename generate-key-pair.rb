require 'openssl'

# parse arguments
require 'optparse'
given_passphrase = nil
decrypt_passphrase = nil
file = __FILE__
ARGV.options do |opts|
  opts.on("-p", "--passphrase=val", String) {|val| given_passphrase = val }
  opts.on("-d", "--decrypt=val", String) {|val| decrypt_passphrase = val }
  opts.on_tail("-h", "--help") { exec "grep ^#/<'#{file}'|cut -c4-" }
  opts.parse!
end

PASSPHRASE = given_passphrase || 'my secure pass phrase goes here'
DECRYPT_PASSPHRASE = decrypt_passphrase || PASSPHRASE

class Generator
  def encrypt_private_key(private_key)
    cipher = OpenSSL::Cipher.new 'AES-256-CBC'
    private_key.export(cipher, PASSPHRASE)
  end

  def encypt_and_store(private_key, file_name)
    # encrypt and store private key
    open file_name, 'w' do |io|
      io.write encrypt_private_key(private_key)
    end
  end

  # Generate 384 bit ECDSA keypair
  def generate_ecdsa!
    if !File.exists?('public_key.ecdsa.pem')
      puts 'generating new ECDSA key pair'

      # First, choose a recommended curve
      ecdsa_key = OpenSSL::PKey::EC.new 'secp384r1'

      # Generate private key
      ecdsa_key.generate_key

      # Now generate a corresponding public key
      ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
      ecdsa_public.private_key = nil

      # store public key
      open 'public_key.ecdsa.pem', 'w' do |io|
        io.write ecdsa_public.to_pem
      end

      # encrypt and store private key
      encypt_and_store(ecdsa_key, 'private.ecdsa.secure.pem')

      # return the private key
      key = ecdsa_key
    else
      puts 'loading existing ECDSA key pair'
      key_pem = File.read 'private.ecdsa.secure.pem'
      key = OpenSSL::PKey::EC.new key_pem, DECRYPT_PASSPHRASE
    end

    return key
  end
end

if __FILE__ == $0
  gen = Generator.new
  gen.generate_ecdsa!

  puts "GENERATED public_key.pem"
  puts "GENERATED private.ecdsa.secure.pem WITH PASSPHRASE `#{PASSPHRASE}`"
end


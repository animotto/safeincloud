# frozen_string_literal: true

require 'openssl'

module SafeInCloud
  ##
  # PBKDF2 key
  class SecretKey
    HASH = 'sha1'
    USERKEY_ITER = 10_000
    CHECKSUM_ITER = 1_000
    LENGTH = 32

    attr_reader :key

    def initialize(password, salt, iter)
      @key = OpenSSL::KDF.pbkdf2_hmac(
        password,
        salt: salt,
        iterations: iter,
        length: LENGTH,
        hash: HASH
      )
    end
  end

  ##
  # Random generator
  class Generator
    KEY_SIZE = 32
    SALT_SIZE = 64
    IV_SIZE = 16

    class << self
      ##
      # Generates random key
      def key
        OpenSSL::Random.random_bytes(KEY_SIZE)
      end

      ##
      # Generates random salt
      def salt
        OpenSSL::Random.random_bytes(SALT_SIZE)
      end

      ##
      # Generates random IV
      def iv
        OpenSSL::Random.random_bytes(IV_SIZE)
      end
    end
  end

  ##
  # Cipher
  class Cipher
    ALGORITHM = 'AES-256-CBC'

    def initialize(key, iv)
      @cipher = OpenSSL::Cipher.new(ALGORITHM)
      @key = key
      @iv = iv
    end

    def encrypt(data)
      @cipher.encrypt
      @cipher.key = @key
      @cipher.iv = @iv
      @cipher.update(data) + @cipher.final
    end

    def decrypt(data)
      @cipher.decrypt
      @cipher.key = @key
      @cipher.iv = @iv
      @cipher.update(data) + @cipher.final
    end
  end
end

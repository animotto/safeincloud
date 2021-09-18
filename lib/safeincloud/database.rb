# frozen_string_literal: true

require 'zlib'

module SafeInCloud
  ##
  # Encrypted database
  #
  # File format:
  #  MAGIC              = 2 bytes
  #  VERSION            = 1 byte
  #  USERKEY SALT       = array
  #  USERKEY IV         = array
  #  DATA SALT          = array
  #  ENCRYPTED CHECKSUM = array
  #   DATA IV       = array
  #   DATA PASSWORD = array
  #   DATA KEY      = array
  #  ENCRYPTED DATA     = till EOF
  class Database
    MAGIC = 0x0505
    VERSION = 1

    attr_accessor :filename, :password

    def initialize(filename, password)
      @filename = filename
      @password = password
    end

    ##
    # Loads and decrypts database from file
    def load
      file = File.open(@filename, 'r')
      reader = Reader.new(file)

      magic = reader.read_short
      raise DatabaseError, 'Database format is incorrect' if magic != MAGIC

      version = reader.read_byte
      raise DatabaseError, 'Database version mismatch' if version != VERSION

      userkey_salt = reader.read_array
      userkey_iv = reader.read_array
      userkey_key = SecretKey.new(
        @password,
        userkey_salt,
        SecretKey::USERKEY_ITER
      )

      data_salt = reader.read_array
      checksum = reader.read_array
      cipher = Cipher.new(userkey_key.key, userkey_iv)
      begin
        checksum = cipher.decrypt(checksum)
      rescue OpenSSL::Cipher::CipherError => e
        raise DatabaseError, e
      end
      checksum_reader = Reader.new(StringIO.new(checksum))
      data_iv = checksum_reader.read_array
      data_password = checksum_reader.read_array
      data_key = checksum_reader.read_array

      checksum_key = SecretKey.new(
        data_password,
        data_salt,
        SecretKey::CHECKSUM_ITER
      )

      raise DatabaseError, 'Wrong password' if data_key != checksum_key.key

      cipher = Cipher.new(data_password, data_iv)
      begin
        data = cipher.decrypt(reader.read)
      rescue OpenSSL::Cipher::CipherError => e
        raise DatabaseError, e
      ensure
        file.close
      end

      Zlib::Inflate.inflate(data)
    end

    ##
    # Encrypts and saves database to file
    def save(data)
      file = File.open(@filename, 'w')
      writer = Writer.new(file)

      writer.write_short(MAGIC)
      writer.write_byte(VERSION)
      userkey_salt = Generator.salt
      writer.write_array(userkey_salt)
      userkey_iv = Generator.iv
      writer.write_array(userkey_iv)
      userkey_key = SecretKey.new(
        @password,
        userkey_salt,
        SecretKey::USERKEY_ITER
      )

      data_salt = Generator.salt
      writer.write_array(data_salt)
      checksum = StringIO.new
      checksum_writer = Writer.new(checksum)
      data_iv = Generator.iv
      checksum_writer.write_array(data_iv)
      data_password = Generator.key
      checksum_writer.write_array(data_password)
      data_key = SecretKey.new(
        data_password,
        data_salt,
        SecretKey::CHECKSUM_ITER
      )
      checksum_writer.write_array(data_key.key)
      cipher = Cipher.new(userkey_key.key, userkey_iv)
      checksum.rewind
      writer.write_array(cipher.encrypt(checksum.read))

      data = Zlib::Deflate.deflate(data)
      cipher = Cipher.new(data_password, data_iv)
      data = cipher.encrypt(data)
      writer.write(data)

      file.close
    end
  end

  ##
  # Data reader
  class Reader
    def initialize(io)
      @io = io
    end

    def read_byte
      @io.read(1).unpack1('C')
    end

    def read_short
      @io.read(2).unpack1('S')
    end

    def read_array
      size = read_byte
      @io.read(size)
    end

    def read
      @io.read
    end
  end

  ##
  # Data writer
  class Writer
    def initialize(io)
      @io = io
    end

    def write_byte(data)
      @io.write([data].pack('C'))
    end

    def write_short(data)
      @io.write([data].pack('S'))
    end

    def write_array(data)
      write_byte(data.bytesize)
      @io.write(data)
    end

    def write(data)
      @io.write(data)
    end
  end

  ##
  # Database error exception
  class DatabaseError < StandardError; end
end

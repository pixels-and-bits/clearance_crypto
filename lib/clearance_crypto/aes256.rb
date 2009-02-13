require "digest/sha2"

module ClearanceCrypto
  module AES256
    def self.included(model)
      model.send(:include, InstanceMethods)
    end

    module InstanceMethods
      attr_writer :key

      def encrypt(string)
        aes.encrypt
        aes.key = @key
        [aes.update(string) + aes.final].pack("m").chomp
      end

      def authenticated?(string)
          aes.decrypt
          aes.key = @key
          (aes.update(encrypted_password.unpack("m").first) + aes.final) == string
        rescue OpenSSL::CipherError
          false
      end

      def aes_plain
          aes.decrypt
          aes.key = @key
          (aes.update(encrypted_password.unpack("m").first) + aes.final)
        rescue OpenSSL::CipherError
          ''
      end

    private

      def aes
        @key ||= salt
        @aes ||= OpenSSL::Cipher::Cipher.new("AES-256-ECB")
      end
    end
  end
end

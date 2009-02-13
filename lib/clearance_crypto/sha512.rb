require "digest/sha2"

module ClearanceCrypto
  module SHA512
    def self.included(model)
      model.send(:include, InstanceMethods)
    end

    module InstanceMethods
      # The number of times to loop through the encryption.
      def stretches
        @stretches ||= 20
      end
      attr_writer :stretches

      # Turns your raw password into a Sha512 hash.
      def encrypt(string)
        digest = "--#{salt}--#{string}--"
        stretches.times { digest = Digest::SHA512.hexdigest(digest) }
        digest
      end

      def authenticated?(string)
        encrypt(string) == encrypted_password
      end
    end
  end
end

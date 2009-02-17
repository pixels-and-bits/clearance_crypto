require "bcrypt"

module ClearanceCrypto
  module BCrypt
    def self.included(model)
      model.send(:include, InstanceMethods)
    end

    module InstanceMethods
      def cost
        @cost ||= 10
      end
      attr_writer :cost

      # Creates a BCrypt hash for the password passed.
      def encrypt(string)
        ::BCrypt::Password.create("--#{salt}--#{string}--")
      end

      # Does the hash match the tokens? Uses the same tokens that were used to encrypt.
      def authenticated?(string)
        ::BCrypt::Password.new(self.encrypted_password) == "--#{salt}--#{string}--" rescue false
      end
    end
  end
end

module GPG
  class Message
    def initialize(content, user_key, system_key)
      @content = content
      @user_key = user_key
      @system_key = system_key

      gpg_context  # test if keys can be imported at all
    end

    def gpg_context
      GPG.context(@user_key, @system_key) do |*args|
        yield(*args) if block_given?
      end
    end

    def signed?
      raise NotImplementedError
    end

    def verified?(signature = nil)
      raise NotImplementedError
    end

    def signature_error
      raise NotImplementedError
    end

    def signature_key
      raise NotImplementedError
    end

    def encrypted?
      return @content.start_with?('-----BEGIN PGP MESSAGE-----') &&
          @content.end_with?('-----END PGP MESSAGE-----')
    end

    def decryptable?
      encrypted?
    end

    def plaintext
      if not encrypted?
        @content
      else
        gpg_context do |ctx, *args|
          # TODO: think about wrapping this in GPG::Context, so we do not have to deal with GPGME:: directly
          data = ctx.decrypt(GPGME::Data.new(@content))
          return data.to_s
        end
      end
    end

    def decryption_error
      raise NotImplementedError
    end

    def encrypt(sign_key = nil)
      raise NotImplementedError
    end

    def sign(key)
      raise NotImplementedError
    end
  end
end

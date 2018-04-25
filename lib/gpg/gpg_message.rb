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
      return false unless encrypted?
      return false if plaintext.nil?  # TODO: cache result, this is expensive
      return true
    end

    def plaintext
      if not encrypted?
        @content
      else
        gpg_context do |ctx, *args|
          begin
            # TODO: think about wrapping this in GPG::Context, so we do not have to deal with GPGME:: directly
            data = ctx.decrypt(GPGME::Data.new(@content))
            return data.to_s
          rescue Exception => e  # TODO: scope this to GPG errors only
            @decryption_error = e
            return nil
          end
        end
      end
    end

    def decryption_error
      # TODO: what if we did not attempt to decrypt yet?
      return @decryption_error
    end

    def encrypt(sign_key = nil)
      raise NotImplementedError
    end

    def sign
      if encrypted?
        raise ArgumentError, "cannot sign an encrypted message"
      end

      gpg_context do |ctx, user_key, system_key|
        # TODO: make convince GPG.context to make system_key into a GPGME::Key object
        ctx.add_signer(GPGME::Key.get(system_key))
        r = ctx.sign(GPGME::Data.new(@content), GPGME::Data.new(), GPGME::SIG_MODE_DETACH)
        return r.to_s
      end
    end
  end
end

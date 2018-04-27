module GPG
  class Message
    def initialize(content, user_key, system_key)
      @content = content
      @user_key = user_key  # TODO: enforce that this is public key
      @system_key = system_key  # TODO: enforce that this is secret key

      gpg_context  # test if keys can be imported at all
    end

    def gpg_context
      GPG.context(@user_key, @system_key) do |*args|
        yield(*args) if block_given?
      end
    end

    def inline_signed?
      # "normal" signature starting with '-----BEGIN PGP MESSAGE-----', have to ask API
      # "clear" signature, not encrypted starting with '-----BEGIN PGP SIGNED MESSAGE-----'
      raise NotImplementedError
    end

    def verified?(detached_signature = nil)
      raise NotImplementedError
    end

    def verify_error
      raise NotImplementedError
    end

    def verified_key
      raise NotImplementedError
    end

    def encrypted?
      @content.start_with?('-----BEGIN PGP MESSAGE-----') && @content.end_with?('-----END PGP MESSAGE-----')
    end

    def decryptable?
      return false unless encrypted?
      return false if plaintext.nil?  # TODO: cache result, this is expensive
      true
    end

    def plaintext
      if !encrypted?
        @content
      else
        gpg_context do |crypto, *_|
          begin
            data = crypto.decrypt(@content) do |signature|
              nil
            end
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
      @decryption_error
    end

    def encrypt(sign = true)
      raise NotImplementedError
    end

    def detached_signature
      if encrypted?
        raise ArgumentError, 'cannot sign an encrypted message'
      end

      gpg_context do |crypto, _, system_key|
        r = crypto.sign @content, signer: system_key, mode: GPGME::SIG_MODE_DETACH
        return r.to_s
      end
    end
  end
end

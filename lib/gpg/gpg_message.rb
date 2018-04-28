module GPG
  class Message
    def initialize(content, user_key, system_key)
      @content = content
      @user_key = user_key  # TODO: enforce that this is public key
      @system_key = system_key  # TODO: enforce that this is secret key

      process
    end

    def gpg_context
      GPG.context(@user_key, @system_key) do |*args|
        yield(*args)
      end
    end

    def process
      # TODO: reuse GPG.context?
      @encrypted, c_signed, c_valid, c_plaintext, @decryption_error = try_decrypt
      i_signed, i_valid, i_plaintext = try_inline_verify

      @inline_signed = c_signed || i_signed

      @valid = []
      @valid << c_valid if c_signed
      @valid << i_valid if i_signed
      @valid = @inline_signed && @valid.all?

      @plaintext = @content if !@encrypted
      @plaintext = i_plaintext if i_plaintext
      @plaintext = c_plaintext if c_plaintext
    end

    def try_decrypt
      signed = false
      valid = true
      decryption_error = nil

      gpg_context do |crypto, *_|
        begin
          data = crypto.decrypt(@content) do |signature|
            signed = true
            valid &= signature.valid?
          end

          plaintext = data.to_s
        rescue GPGME::Error::NoData => exc
          return false, false, false, nil, exc
        rescue GPGME::Error::DecryptFailed => exc
          return true, false, false, nil, exc
        rescue GPGME::Error => exc
          return true, false, false, nil, exc
        end
      end

      valid = false if !signed
      [true, signed, valid, plaintext, nil]
    end

    def try_inline_verify
      signed = false
      valid = true
      plaintext = nil

      gpg_context do |crypto, *_|
        begin
          signature_plaintext = crypto.verify(@content) do |signature|
            signed = true
            valid &= signature.valid?
          end

          plaintext = signature_plaintext.to_s
        rescue GPGME::Error::NoData => e
          signed = false
        rescue GPGME::Error::General => e
          signed = true
          valid = false
        end
      end

      valid = false if !signed
      [signed, valid, plaintext]
    end

    def inline_signed?
      @inline_signed
    end

    def verified?(detached_signature = nil)
      if detached_signature.nil?
        @inline_signed && @valid
      else
        begin
          gpg_context do |crypto, *_|
            valid = true
            crypto.verify(detached_signature, :signed_text => @content) do |signature|
              valid &= signature.valid?
            end
            valid
          end
        rescue GPGME::Error
          return false
        end
      end
    end

    def encrypted?
      @encrypted
    end

    def decryptable?
      encrypted? && !@plaintext.nil?
    end

    # TODO: return input when decryption failed?
    attr_reader :plaintext
    attr_reader :decryption_error

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

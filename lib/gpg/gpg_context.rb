require 'gpgme'
require 'tmpdir'

module GPG
  def self.parse_key(key)
    importstatus = GPGME::Key.import key

    # secret keys cause two imports with identical key IDs
    fingerprints = importstatus.imports.map(&:fpr)
    fingerprints.uniq!

    if fingerprints.length.zero?
      raise ArgumentError, 'key cannot be imported'
    end
    if fingerprints.length > 1
      raise ArgumentError, 'only one key can be imported at a time, got ' + fingerprints.join(', ')
    end

    fingerprints[0]
  end

  def self.parse_keysets(keysets)
    keys = []

    keysets.each do |keyset|
      keys << if keyset.is_a?(Array)
                # TODO: think about usecases for this again and maybe remove it to keep things simple
                keyset.map { |k| parse_key(k) }
              else
                parse_key(keyset)
              end
    end

    keys
  end

  def self.context(*keysets)
    home_dir = Dir.mktmpdir()

    # TODO: lock
    begin
      GPGME::Engine.home_dir = home_dir
      # TODO: use GPGME::Crypto.new
      ctx = GPGME::Ctx.new(armor: true)

      yield(ctx, *parse_keysets(keysets))
    ensure
      ctx.release
      # TODO: find the right agent and kill it, or even better: tell the gpgme API to do it
      system('killall gpg-agent')
      FileUtils.remove_dir(home_dir)
    end
  end
end

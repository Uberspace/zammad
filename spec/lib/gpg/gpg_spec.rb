require 'gpgme'
# TODO: this gotta be possible with autoload somehow
require 'gpg/gpg_context'
require 'gpg/gpg_message'

def load_key_samples(root)
  keys = {}

  Dir[root + '/*.sec', root + '/*.pub'].each do |key|
    email, _, type = key.rpartition('.')
    email = File.basename(email)
    keys[email] = {} if not keys[email]
    keys[email][type] = File.read(key)
  end

  return keys
end

keys = load_key_samples(File.dirname(__FILE__) + '/data')

RSpec.describe "GPG.context" do
  specify { expect { |b| GPG.context(&b) }.to yield_control }
  specify { expect { |b| GPG.context(&b) }.to yield_with_args(GPGME::Ctx) }
  specify { expect { |b| GPG.context(keys['zammad-user@example.org']['pub'], &b) }.to yield_with_args(GPGME::Ctx, "25B6F98D353D3395A138255E6AF9F44B125ABB64") }
  specify { expect { |b| GPG.context(keys['zammad-system@example.com']['sec'], &b) }.to yield_with_args(GPGME::Ctx, "8F8A943A9DF60FB782DE3ED5719FFA72B62E79AD") }
  specify { expect {
      |b| GPG.context(
        keys['zammad-user@example.org']['pub'],
        [
          keys['zammad-user@example.org']['pub'],
          keys['zammad-system@example.com']['pub'],
        ],
      &b)
    }.to yield_with_args(
      GPGME::Ctx,
      "25B6F98D353D3395A138255E6AF9F44B125ABB64",
      [
        "25B6F98D353D3395A138255E6AF9F44B125ABB64",
        "8F8A943A9DF60FB782DE3ED5719FFA72B62E79AD",
      ],
    )
  }

  specify { expect { |b| GPG.context("", &b) }.to raise_error("key cannot be imported") }
  specify { expect { |b| GPG.context("foo", &b) }.to raise_error("key cannot be imported") }
end

user_key = keys['zammad-user@example.org']['pub']
system_key = keys['zammad-system@example.com']['sec']
message_to_system = '-----BEGIN PGP MESSAGE-----

hQEMAykSl5H8xcQ9AQgAqKiPOZyir8r3yZGhFosuSBlDUPU32imVkOPKkFfH8kgs
y2BWilHeaOiW6KSGRRQlQ9cLGGQrTV2CPHFS/q5KA7c6DtBbedrDZ/+IamjIhQX1
1Ezfhws+SiAT1CrFfD5gcOFjKTXizS9tyV7cWrzlgSS1ZBS5Bwm7XKHvCQJbjtiV
O30/NDL+nEOW5PBeu1lv50lKhtyY28/hDzIiPP8R0k/ogtIGTJhS/BVRLpu4YPKn
oiUH3lMnnwWH/EeG3H7NfB52aNRihJ5lsltrsDTa8QasZESxY8vjJJQ1Ydd/qSOW
DhNWerYiAbRI1Cbj7f7W7rmVzRPrMMS4Ga/GJSETs9JFAUp3F/PZncPpLriTRR6D
QGjZEwPlaIv4fNiQddBwG7fxhCAb7YKbR7j/wafKmao1876jQ35kTS+F6di5VtR2
CUfm92g2
=3R2k
-----END PGP MESSAGE-----'

RSpec.describe "GPG.message" do
  # TODO: do not construct the same message over and over again
  specify { expect(GPG::Message.new('foo', user_key, system_key)).not_to be_encrypted }
  specify { expect(GPG::Message.new('foo', user_key, system_key)).not_to be_decryptable }
  specify { expect(GPG::Message.new('foo', user_key, system_key).plaintext).to eq 'foo' }
  specify { expect(GPG::Message.new(message_to_system, user_key, system_key)).to be_encrypted }
  specify { expect(GPG::Message.new(message_to_system, user_key, system_key)).to be_decryptable }
  specify { expect(GPG::Message.new(message_to_system, user_key, system_key).plaintext).to eq "hi zammad\n" }
end

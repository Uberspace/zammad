require 'gpgme'
# TODO: this gotta be possible with autoload somehow
require 'gpg/gpg_context'
require 'gpg/gpg_message'

def load_key_samples(root)
  keys = {}

  Dir[root + '/*.sec', root + '/*.pub'].each do |key|
    email, _, type = key.rpartition('.')
    email = File.basename(email)
    keys[email] = {} unless keys[email]
    keys[email][type] = File.read(key)
  end

  keys
end

keys = load_key_samples(File.dirname(__FILE__) + '/data')

RSpec.describe 'GPG.context' do
  it 'should yield control' do
    expect { |b| GPG.context(&b) }.to yield_control
    expect { |b| GPG.context(&b) }.to yield_with_args(GPGME::Crypto)
  end

  it 'should accept public keys' do
    key = keys['zammad-user@example.org']['pub']
    fpr = '25B6F98D353D3395A138255E6AF9F44B125ABB64'
    expect { |b| GPG.context(key, &b) }.to yield_with_args(GPGME::Crypto, fpr)
  end

  it 'should accept private keys' do
    key = keys['zammad-system@example.com']['sec']
    fpr = '8F8A943A9DF60FB782DE3ED5719FFA72B62E79AD'
    expect { |b| GPG.context(key, &b) }.to yield_with_args(GPGME::Crypto, fpr)
  end

  it 'should accept multiple keys and sets of keys' do
    expect {
      |b| GPG.context(
        keys['zammad-user@example.org']['pub'],
        [
          keys['zammad-user@example.org']['pub'],
          keys['zammad-system@example.com']['pub'],
        ],
      &b)
    }.to yield_with_args(
      GPGME::Crypto,
      '25B6F98D353D3395A138255E6AF9F44B125ABB64',
      %w[25B6F98D353D3395A138255E6AF9F44B125ABB64 8F8A943A9DF60FB782DE3ED5719FFA72B62E79AD]
    )
  end

  it 'should not accept an empty key' do
    expect { |b| GPG.context('', &b) }.to raise_error('key cannot be imported')
  end

  it 'should not accept an non-key string' do
    expect { |b| GPG.context('foo', &b) }.to raise_error('key cannot be imported')
  end

  it 'should not accept an invalid key' do
    expect { |b| GPG.context(keys['zammad-user@example.org']['pub'].tr('A', 'B'), &b) }.to raise_error('key cannot be imported')
  end
end

user_key = keys['zammad-user@example.org']['pub']
system_key = keys['zammad-system@example.com']['sec']
# TODO: move messages to fixtures: https://relishapp.com/rspec/rspec-rails/v/3-5/docs/file-fixture
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
message_to_system_invalid = message_to_system.tr('=3R2k', '=2R2k')
message_to_unknown_key = '-----BEGIN PGP MESSAGE-----

hQIMAwAAAAAAAAAAARAAhDveX4y7SZOFv1LCk2YfMYiizQSBwqS5OkleqCBGaI6T
ihcJ+Jztb9qENOT1bb2umh7csPaGYbkoy4L9Z9jcR8gN6foBUMcNWbX0lRk95W1s
Q8+KJ3zhUa8KrNqEr/bXEMhh182Twp6bSs44LlAJQw1wAiMSMDG4YhO0EwfLaSxX
04O6ogSB+WhbzgEBKf0R14wcM5bHn1miLUebPdDpn53rHUn9jnmYzXQHlFnvTQvX
xUNmuQOtYcA0WwB64UGZpVOZRR/ybRPV35nidDqDCTGhJtEJbilMIhHcxixq8vwp
0asACw8ng81aMlxHTVImvFmy5pSYwQMbUXb/swIfOjL3jNkWHRQbcKQ/Pk1sGxRn
U5Wml1HHi7rf5F+zm2tPtdImxpWBVb+BlNTDNMRRyTauzgBgpJ0hxZLCBMY4TORC
Z3zHsBQinn7yHh8VqHVxHHyJweXHMfYoLgUrpncbpFSURVlCDASvlysjgv1KiNpF
8nfpGQLtHibg0IypR9tBNnPQBvZD/88O+FkWscmuJIZfX2UoMhTnPZdlQnk5hFE4
M577JdKsqj0VakULk4+nMWJk3/Erq7qhbL3y6M0UyITWrC8kd+dinzDRZCV9TnRH
844ZY0SOokruO9J0hIhdY0Nkb/VbO9BjAK+Y0EoELUdtLd7gl0x5kS0jhEQBnhaF
AQwDAAAAAAAAAAABB/0fd3kYwvUYS2aa41PXFvmLEMsbyNUk7kEmq+lN6CflJRkk
2/BjVyc5sZ28UCjlr1dFqAaJKt3qWRKRgtU3eZsHGX4ikH5KFQNqG7L4STKcUuFY
d2UX3zl0cxOwMSokziTcIYqdkuiq9hqRICeZfeG4ESVjsQlFsn+rHy3kAjUcBFYY
y3EQ8rOkuxTEJCDK8A2/t303GQYN0whNHUuEF4Dd2wvBbnN14dX6758RNuU+OA90
kRwQ/FjKrBZBea0XGWWlu1hD6CC+QhFu+R0zYkv7jTWPqhR5pNz7fABtb33FwfR8
HdB9HL0WxPhmC+TOtFE8YSYpGW1uzPRm+owZWj2u0sASAZxcmAqMg+CLQ4oJBjoY
bxLMXlBEANDlltnUF6I6KT7xutp+SHd1E9FgbR5vxzznow6stimrFMjGK69jhGKQ
/VZXV81IdCLmTlShVg0Ds99RWwMVcZfUsgvUx8u3U22ngJZfq4tPcoqpQghr0I+p
kiwp2U1hivWyvlAbT/7tXFhSFy9A3wDXXnw0kU+JMZlN/BczlsrYOHCFzdJ3CwYF
ot2YLdEgHHcSu1G6DcKnyedn8OofZKKhiso2SicQmX2wvvbNxB84H5dugpqWAKlc
MOui
=RkRs
-----END PGP MESSAGE-----'
message_signed_normal = '-----BEGIN PGP MESSAGE-----

owGbwMvMwMGY9fOLt1DU7hTG04JJDFGPYk0yMhWqEnNzE1OMuDoZfVgYGDkYzMQU
WVS3/ew1tTWeutBCNQ6mh5UJqMFcQgaiXre0OLXIIbUiMbcgJ1UvvyidgYtTAKZ0
KQv7f2/XTAnX/dVWrFxH9v7KO/Z+6Z/LF4wuHXY4kfk/pvHu5fP3H08+KTp3Huvc
gkf3boZsfRB0wVjmo8MGuyz3/qr9E7ZOfXoo/NT+x2zBIv5qe9JlVjc0xN0M/h1o
Fr4u6u3E8izezmOrnTlXbvy84vU6AdPCnjVF/3TY1v+buuysa1Oz1j4m+TO/Jz2b
Vrx1ruWEO1Fiu1XTlZ2WX5zJwvqiRPpgm6uT4U0+xsklHeomS310xDKTvOXmrYnY
K7XDZNVfg6Yqzx/Gy5tWWentyt8dWshg+/uyqwyT5susY/eON/38+8Rap3L/apt3
W2e/vSvWZeSaIPSH78vdDWnbup14BO0CJwq90lLTitdNywMA
=UAkO
-----END PGP MESSAGE-----'
message_signed_clear = '-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

hi zammad3
-----BEGIN PGP SIGNATURE-----

iQFMBAEBCAA2FiEEJbb5jTU9M5WhOCVeavn0SxJau2QFAlriXVAYHHphbW1hZC11
c2VyQGV4YW1wbGUub3JnAAoJEGr59EsSWrtkINAIAIBTBpbwRn1w0sgVGNsKO8y9
Gee7Ijnd1q6iRn2Z1AKhMUvpkK3xxaYs9mS2R0A+c+38/DO/DIBkMA6SpVdkE19M
0JnfB/SyigFPwGgv6io4m77ldvTunhHW9XZr3J3nO+Db77Jklg9amhT+4UKdXM0O
Mx833OdPVe78lny00/9AYTk3kRTuOX4kI61XqFfh7pTZ5zhiqVaPb54sBJKwWbsh
g++YB+4FI6v63m85Tk6f1eFvaPkglHe2U3R+7l8l5NQADfxDPnL8IsxTS0cwnfOE
B5HrA2Xywqwxblo+TwsKfV3owNox/jT3v+qaD/jsIFk/ekZpP5t26vYKEP2ik5U=
=RifJ
-----END PGP SIGNATURE-----'
message_signed_clear_invalid = message_signed_clear.tr('zammad3', 'zammad4')
message_signed_clear_fake = '-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

is fake
-----BEGIN PGP SIGNATURE-----

much
-----END PGP SIGNATURE-----'
# "hi zammad4\n"
message_signed_detach = '-----BEGIN PGP SIGNATURE-----

iQFMBAABCAA2FiEEJbb5jTU9M5WhOCVeavn0SxJau2QFAlriXYYYHHphbW1hZC11
c2VyQGV4YW1wbGUub3JnAAoJEGr59EsSWrtkUw8IALNA52uIdAAcHxgWAekUpS6J
tF0sZvVfdkJiEG0lXvcHbpNmXRNgrEevexQTjSdd/k8JABEeC4MwEZlnD1b5S8r6
nR0rFkKFl4G+Q6kWNDFopdu5CHlxNL+YngO6XylrOBNw+jBR3O5MgbSuh5E5xY6g
g4Ccp1HNaU9F2GBTFOsw3uT8gpXUCu7WD9+RXy18gfoOOa6eHt48ZZXl5q3FbfPN
7XdPwxg/4nHQ+f36z4EBjHpihjB8iTlas693s9haOWSYBvjJpxuBQ1PZJuD5ruia
q8k7XPAkMKUoQh3KWVZF3sSkSlLquOV/LYwXWFKxWZUF4bfFsjHPMybYqTY9ui8=
=+Jsu
-----END PGP SIGNATURE-----'
message_signed_encrypted = '-----BEGIN PGP MESSAGE-----

hQEMAykSl5H8xcQ9AQgAnX1rPOg6VBHte1R/IqPCFdw1EFNBt4vnthAoH2oPy5Bd
I6+YNuFhmZTKBvYNK6fIkY30bKcH62lePFlQgAtOYv/CDaIbEuPeNnlCgX8Q3BBm
0cEDOhCbGQrOR1Vtpo1brSx72XVoYvqCLq4GxCWWO8H0ieXRnDk2L6FkhAakCKfj
eOSB4JGznLcJyCxKGHSnW7qt43fcymh5CmS2M/dzuriLnLiU1NmOcsbzv4Qtc9jv
evc8vlqwsUZHrSAZxXb4SO7MViBZuZMLDJwtK7vFo9fljpgvLqLxuZ21DjtudFv4
rAyKsZLdGsTvFMcaRZguxKOtYbd9tyf4OyQYGUhx09LA8gFm+QhTgN53hUSSvotk
YdoeG0fq6ieXNYz6ESXEPWn3D4GcpJJM98wtP4O+XFxSCZtW5zwrRdcFTclWGIBe
jLJ140OjDk/XPT5VGi8uR0hRHtCipc8MYgubenXj0hqKluxWphWM5+CTZs6ayo0j
vbXp7uwltlFHmEdtL4P3gCQ7mvSqponKYJUo9K9glgnD/bwi8Q41VOKwhvpBqXHT
NQd2xc8L7jyR1gcVAoNbegQbdWyO5+LdCz0SLMXbly1xa1h6KBYxKIlqOVPBcKZH
5uwnSxiuinj6X7Jv7lXF277CCXID8P3r+ITEkGUYluycF/1g/kP4oxCeRRoqwLo8
IJ5thnbLva0reNuMQRSQ+bf6ZWbAO+t7TV0A/lrhBQsfb6ajcUhqD6nQs2zAagL6
80HlgmimaNBIdpubw5/bdRJZdk9UT6xyRdyA8L+jL8+Pz2XYhFKVjWFUYZf6q9hO
tuLlXruVL/YFn/UdQlR7f8pmWnEQJOSWMmbdLAdRwzbsF1lPl5Hjxqt6cXy5FvCK
7J6hnvXvESM0qTi+sY1A2I7Po74RSkl9VShuVhijUBXQZKu3
=6o03
-----END PGP MESSAGE-----'

RSpec.describe 'GPG.message' do
  it 'should handle unecrypted messages' do
    msg = GPG::Message.new('foo', user_key, system_key)
    expect(msg).not_to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).to have_attributes(plaintext: 'foo')
  end

  it 'should decrypt encrypted, valid messages' do
    msg = GPG::Message.new(message_to_system, user_key, system_key)
    expect(msg).to be_encrypted
    expect(msg).to be_decryptable
    expect(msg).to have_attributes(plaintext: "hi zammad\n")
  end

  it 'should handle encrypted messages to unknown recipients' do
    msg = GPG::Message.new(message_to_unknown_key, user_key, system_key)
    expect(msg).to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).to have_attributes(plaintext: nil, decryption_error: be_a(GPGME::Error::DecryptFailed))
  end

  it 'should handle invalid encrypted messages' do
    msg = GPG::Message.new(message_to_system_invalid, user_key, system_key)
    expect(msg).to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).to have_attributes(plaintext: nil, decryption_error: be_a(GPGME::Error::NoData))
  end

  it 'should generate detached signatures' do
    signature = GPG::Message.new('foo', user_key, system_key).detached_signature
    expect(signature).to start_with '-----BEGIN PGP SIGNATURE-----'
    expect(signature).to end_with "-----END PGP SIGNATURE-----\n"
    expect(signature).not_to include 'foo'
  end

  it 'should refuse to sign encrypted content' do
    msg = GPG::Message.new(message_to_system, user_key, system_key)
    expect { msg.detached_signature }.to raise_error('cannot sign an encrypted message')
  end

  it 'should decrypt encrypted, signed, valid messages' do
    msg = GPG::Message.new(message_signed_encrypted, user_key, system_key)
    expect(msg).to be_encrypted
    expect(msg).to be_decryptable
    expect(msg).to have_attributes(plaintext: "hi zammad, secretly signed\n")
    expect(msg).to be_inline_signed
    expect(msg).to be_verified
  end

  it 'should handle signed, but unecrypted messages' do
    msg = GPG::Message.new(message_signed_normal, user_key, system_key)
    expect(msg.plaintext).not_to be_nil
    expect(msg).not_to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).to be_inline_signed
    expect(msg).to be_verified
    expect(msg).to have_attributes(plaintext: "hi zammad2\n")
  end

  it 'should handle clear signed messages' do
    msg = GPG::Message.new(message_signed_clear, user_key, system_key)
    expect(msg.plaintext).not_to be_nil
    expect(msg).not_to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).to be_inline_signed
    expect(msg).to be_verified
    expect(msg).to have_attributes(plaintext: "hi zammad3\n")
  end

  it 'should handle messages formatted like clear signed messages' do
    msg = GPG::Message.new(message_signed_clear_fake, user_key, system_key)
    expect(msg.plaintext).not_to be_nil
    expect(msg).not_to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).not_to be_inline_signed
    expect(msg).not_to be_verified
  end

  it 'should reject invalid clear signed messages' do
    msg = GPG::Message.new(message_signed_clear_invalid, user_key, system_key)
    expect(msg.plaintext).not_to be_nil
    expect(msg).not_to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).to be_inline_signed
    expect(msg).not_to be_verified
    expect(msg).to have_attributes(plaintext: include("hi zammad4"))
  end

  it 'should handle detached signed messages' do
    pending
    msg = GPG::Message.new("hi zammad4\n", user_key, system_key)
    expect(msg.plaintext).not_to be_nil
    expect(msg).not_to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).not_to be_inline_signed
    expect(msg).not_to be_verified
    expect(msg.verified?(message_signed_clear)).to be true
  end
end

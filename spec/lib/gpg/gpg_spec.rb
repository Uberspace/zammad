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
user_key_sec = keys['zammad-user@example.org']['sec']
system_key = keys['zammad-system@example.com']['sec']
system_key_pub = keys['zammad-system@example.com']['pub']
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
message_signed_normal_unkown = '-----BEGIN PGP MESSAGE-----

owEBdgGJ/pANAwAIAZuhdrZ0L1DrAcsQYgBa5Jiid2hvIGFtIGk/CokBUgQAAQgA
PBYhBNNFXwuvk9cAZ4ARz5uhdrZ0L1DrBQJa5JirHhx6YW1tYWQtb3RoZXItdXNl
ckBleGFtcGxlLm9yZwAKCRCboXa2dC9Q67ROB/9dpeSU1pgSiOweWaNxJ1qI+yxt
+fA0l5nRr0ZWKtvhwzzCoQ1lcQoI5B9e2smFUBO2UcAFkCd7d52zLnhgaEFigMQ0
uLc504v08QWebkxYYAC6HeqY5ghlcAzTJX/mIANLDNXqFV5AG+Pd4exIxdzVpsj1
KVSGzLs2xnv8zlQO2YDV983fnQKqf/89QbrrayjWb+T/6QaSH1clA+8F2dyXjBBs
ptdq2TGleSCgiSY4orIrdkae9QpFEGgnHgvXlMcmJZTbBqGICYrRFCAcWE13jWlN
rw8PVeNiTGAAEW5RiyVIWlS3zilL4LivjOevIRFe7nAEmyAEkjZNhdD59yb9
=7Tbz
-----END PGP MESSAGE-----'
message_signed_normal_system = '-----BEGIN PGP MESSAGE-----

owGbwMvMwMFYOP9X0Ta9yrWMp8WSGKKezFTzVEjMVSjJSFUoriwuSc3l6mT0Y2Fg
5GCwEFNk6e+aYjX3G//2pnt2V2EaWZmAujSlZKoSc3MTU3QhuhxSKxJzC3JS9ZLz
cxm4OAVgip9LcTCsX/yjvUYgXHEyp7ij8DzWVqMpc54z/n7Edp21/2TUo7Zv9zS/
bb07bVGbyfLWLRUPeey5vt6f8maFckTMLA/3xZvn28vyTliskexUVygwd6cgR6W/
7mTTbt6TblMiCwyqF0Wvn/40ZNK7Mxk75DaeUXtkn+7qkcDeYdMUw2NjxtJ6YfnE
DwozDwj8NHvBXjY1PPQY4+bnyp96Wrfb8dk4PxPS1d7WsElwvbr6qV0hl2NjTOeJ
LM1Q+NgYeMavft8bCbcPN6YlXTo149Tv4olP5L8cuGOyJu7BrPK+hmNRv10Xqly/
J3hwpXuWsVHNhWu3Y0T3TvrY5NR2f37zJNeHTCHRk1dHPot3jtfTf6UBAA==
=kpOC
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
message_wrong_key_signed_encrypted = '-----BEGIN PGP MESSAGE-----

hQEMAykSl5H8xcQ9AQf+MdTkjhBdfjjupLbvEDR2N5jdX0hBP7t8eiKB39dMh9rJ
D0NbRSStFOvJwy05u7Qy0hiDtJIbRDEVlf/b58GFP9vHEF4mHp1Z9f/ekRk0wUqp
9xOtMogLcCY29bLC99aIk7bS4KG5uAr6eHA8TJaA55WUYB8n3Gb+HleUe54XmQ2O
lXo2Bo7XLTpA4llFeounIa1eBAA6rAFl1t+Kqwr0cv8T1XR7P+10gZ5OU0ONwkiT
t17UPo73bwvGyfqiCMSm7qtWuYDH2tJ8gfne9pDoGtFmODsKTopIVZRhm4Z7vIrW
cDm7OPYpMVK98pu2xtpTxViRHBYdPLddQYwXBefaOtLA7QG+QkSvj2vGTH3I943B
ROvXC7faYdPer0zMgJ4YSmDnVJC+684265xAE6WWKTeJozHDZdDK9quNJeA8JhVt
H1zjb/P3PE9IpeiFPiiXI7PJ41CnMlF7Z3zM/yZ/e+obmbMHYJjRClG3oBHnglmG
1bUuaaUwS2pIlE/LaN3fqlR4nh6KrRMcqsmlj9WG35Hy6JyVqCWydeMhqr/lGV96
u2MSXa2ihCwe7ck/93mAQNeXrkdDvT0zqOcCyIfn/G4ZKCpadUqBX2sBpdGx8HuG
9nSBll9DnHYpFmuylMQzPfycyzgnHnPXt6Hy3pIxfakOqpESvsHTZ1n/HDQJiTUI
Fm7JVzVg1UOZ1fY/kLDKni38GuOOF/hvzYMDIleGC7wrqXU0IZx4l2BHQFWcIGve
gxcwmtGo60ajLS01d1tzg260M7oHAVLaE2B2rOfxFOHEbNOoOIHzYWyc1V5VzFvY
UozDNq8FZfSPfvMcpColtD/fL2kODQT8Jys64CBRtGiRQXaeip5BnHRm6cdFDUVL
lLD5DvjVK3KHWYnIHEM9JnRRrlYbj8UuU5jfoe6VfQ==
=o8gF
-----END PGP MESSAGE-----'

RSpec.describe 'GPG.message' do
  it 'should reject two public keys' do
    expect { GPG::Message.new('', user_key, system_key_pub) }.to raise_error 'no secret key provided'
  end

  it 'should reject two secret keys' do
    expect { GPG::Message.new('', user_key_sec, system_key) }.to raise_error 'no public key provided'
  end

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

  it 'should handle messages, which are encrypted and signed with the wrong key' do
    msg = GPG::Message.new(message_wrong_key_signed_encrypted, user_key, system_key)
    expect(msg).to be_encrypted
    expect(msg).to be_decryptable
    expect(msg).to have_attributes(plaintext: "hi zammad, this is zammad\n")
    expect(msg).to be_inline_signed
    expect(msg).not_to be_verified
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

  it 'should reject messages signed by unknown key' do
    msg = GPG::Message.new(message_signed_normal_unkown, user_key, system_key)
    expect(msg.plaintext).not_to be_nil
    expect(msg).not_to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).to be_inline_signed
    expect(msg).not_to be_verified
    pending
    expect(msg).to have_attributes(plaintext: "who am i?\n")
  end

  it 'should reject messages signed by system key' do
    msg = GPG::Message.new(message_signed_normal_system, user_key, system_key)
    expect(msg.plaintext).not_to be_nil
    expect(msg).not_to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).to be_inline_signed
    expect(msg).not_to be_verified
    expect(msg).to have_attributes(plaintext: "I am the system\n")
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
    msg = GPG::Message.new("hi zammad4\n", user_key, system_key)
    expect(msg.plaintext).not_to be_nil
    expect(msg).not_to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).not_to be_inline_signed
    expect(msg).not_to be_verified
    expect(msg.verified?(message_signed_detach)).to be true
  end

  it 'should reject invalid detached signed messages' do
    msg = GPG::Message.new("hi zammad5\n", user_key, system_key)
    expect(msg.plaintext).not_to be_nil
    expect(msg).not_to be_encrypted
    expect(msg).not_to be_decryptable
    expect(msg).not_to be_inline_signed
    expect(msg).not_to be_verified
    expect(msg.verified?(message_signed_detach)).to be false
  end

  it 'should refuse to encrypt a message' do
    msg = GPG::Message.new(message_to_system, user_key, system_key)
    expect { msg.encrypt() }.to raise_error('cannot encrypt an encrypted message')
  end

  it 'should encrypt messages' do
    msg = GPG::Message.new('hi zammad, make secure plz', user_key, system_key)
    encrypted = msg.encrypt()
    expect(encrypted).to start_with '-----BEGIN PGP MESSAGE-----'
    expect(encrypted).to end_with "-----END PGP MESSAGE-----\n"
  end

  it 'should decrypt its own encrypted, signed messages' do
    msg = GPG::Message.new('hi', user_key, system_key)
    encrypted = msg.encrypt()
    expect(encrypted).to start_with '-----BEGIN PGP MESSAGE-----'  # just for sanity
    msg = GPG::Message.new(encrypted, system_key_pub, user_key_sec)
    expect(msg).to be_encrypted
    expect(msg).to be_inline_signed
    expect(msg).to be_verified
    expect(msg).to have_attributes(plaintext: 'hi')
  end

  it 'should decrypt its own encrypted messages' do
    msg = GPG::Message.new('hi2', user_key, system_key)
    encrypted = msg.encrypt(false)
    expect(encrypted).to start_with '-----BEGIN PGP MESSAGE-----'  # just for sanity
    msg = GPG::Message.new(encrypted, system_key_pub, user_key_sec)
    expect(msg).to be_encrypted
    expect(msg).not_to be_inline_signed
    expect(msg).not_to be_verified
    expect(msg).to have_attributes(plaintext: 'hi2')
  end
end

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

RSpec.describe "GPG.message" do
  # TODO: do not construct the same message over and over again
  specify { expect(GPG::Message.new('foo', user_key, system_key)).not_to be_encrypted }
  specify { expect(GPG::Message.new('foo', user_key, system_key)).not_to be_decryptable }
  specify { expect(GPG::Message.new('foo', user_key, system_key).plaintext).to eq 'foo' }
  specify { expect(GPG::Message.new(message_to_system, user_key, system_key)).to be_encrypted }
  specify { expect(GPG::Message.new(message_to_system, user_key, system_key)).to be_decryptable }
  specify { expect(GPG::Message.new(message_to_system, user_key, system_key).plaintext).to eq "hi zammad\n" }
  specify { expect(GPG::Message.new(message_to_unknown_key, user_key, system_key)).not_to be_decryptable }
  specify { expect(GPG::Message.new(message_to_unknown_key, user_key, system_key).plaintext).to be_nil }
  specify {
    msg = GPG::Message.new(message_to_unknown_key, user_key, system_key)
    msg.plaintext  # trigger decryption
    expect(msg.decryption_error).to be_a(GPGME::Error::DecryptFailed)
    expect(msg).not_to be_decryptable
  }
  specify {
    msg = GPG::Message.new('-----BEGIN PGP MESSAGE-----

hQIMAwAAAAAAAAAAARAAhDveX4y7SZOFv1LCk2YfMYiizQSBwqS5OkleqCBGaI6T
-----END PGP MESSAGE-----', user_key, system_key)
    msg.plaintext  # trigger decryption
    expect(msg.decryption_error).to be_a(GPGME::Error::NoData)
    expect(msg).not_to be_decryptable
  }
end

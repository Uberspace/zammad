require 'gpgme'
require 'gpg/gpg_context'  # TODO: this gotta be possible with autoload somehow

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

RSpec.describe "GPG" do
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

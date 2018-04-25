#!/usr/bin/env bash
set -e

tmpdir=$(mktemp -d)

echo keyring: $tmpdir

function finish {
    echo delete keyring
    rm -rf $tmpdir
}
trap finish EXIT

gpg="gpg -q --armor --homedir $tmpdir"

for path in keyspecs/*; do
    email=$(basename $path)

    echo generate $email
    $gpg --batch --generate-key $path

    echo export $email
    $gpg --export $email > $email.pub
    $gpg --export-secret-keys $email > $email.sec
done

#!/usr/bin/env bash

set -e


# Note: Uncomment the following line to create seed words and a spend account is needed.
# cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  create-seed-words
#cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  create-account -ntest


# Example usage of the transfer commands in the CLI tool.
ADDRESS=xtr_loc_1j26ht0mvv5tmxd7d40s5vc2g8axva5stndm254xnrhp7dl3fvcsackujppl6sjzvn5q5mxjkmy675c8yvnzzuucp78dj4szdwu9mgtgv5aura
AMOUNT=10000000

cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  \
  transfer create --to-address=$ADDRESS --amount=$AMOUNT --message="first transfer" -o /tmp/transfer.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  transfer transaction /tmp/transfer.json /tmp/tx1.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  transfer sign /tmp/tx1.json /tmp/tx1_signed.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  transfer send /tmp/tx1_signed.json

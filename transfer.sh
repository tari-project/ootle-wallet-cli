#!/usr/bin/env bash

set -e


# Note: Uncomment the following line to create seed words and a spend account is needed.
# cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  create-seed-words
#cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  create-account -ntest


# Example usage of the transfer commands in the CLI tool.
ADDRESS=otl_loc_1pr4383l9dkhlz6m2yach2lvdrpnkx6jmhqpua53fmsuftk205f7q3x73ces8lcepmphmkhpmn4v957wmrnny4lp2n6p9s8dunuxqzyqlxu87n
AMOUNT=10000000

cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  \
  transfer create --to-address=$ADDRESS --amount=$AMOUNT --num-outputs=7 --message="Transfer" --fee-amount=1300 -o /tmp/transfer.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  transfer transaction /tmp/transfer.json /tmp/tx1.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  transfer sign /tmp/tx1.json /tmp/tx1_signed.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  transfer send /tmp/tx1_signed.json

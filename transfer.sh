#!/usr/bin/env bash

set -e


# Note: Uncomment the following line to create seed words and a spend account is needed.
# cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12500  create-seed-words
#cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12500  create-account -ntest


# Example usage of the transfer commands in the CLI tool.
ADDRESS=otl_loc_1azl4ty0l9t7czfy8gk7vter08pgy20ex7ptj4lu3d0hm46wmceans07r4dfpqa9fhhv89ngs0h9rnlj0srrv8p9zayxrt8aslgjx68sk0smcz
AMOUNT=10000000

cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12500  \
  transfer create --to-address=$ADDRESS --amount=$AMOUNT --num-outputs=7 --message="Transfer" --fee-amount=1300 -o /tmp/transfer.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12500  transfer transaction /tmp/transfer.json /tmp/tx1.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12500  transfer sign /tmp/tx1.json /tmp/tx1_signed.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12500  transfer send /tmp/tx1_signed.json

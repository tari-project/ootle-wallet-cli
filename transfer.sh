#!/usr/bin/env bash

set -e


# Note: Uncomment the following line to create seed words and a spend account is needed.
# cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  create-seed-words
#cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  create-account -ntest


# Example usage of the transfer commands in the CLI tool.
ADDRESS=xtr_loc_12fp277020vd2cs70fjdwdfhfygzqxejrppdagvkm4jx4thjltflwqnljqh9w22dp3dat7jn6lnq29jzd99mlh47ydxl9p99hvxjj23q7alvpt
AMOUNT=10000000

cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  \
  transfer create --to-address=$ADDRESS --amount=$AMOUNT --message="first transfer" -o /tmp/transfer.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  transfer transaction /tmp/transfer.json /tmp/tx1.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  transfer sign /tmp/tx1.json /tmp/tx1_signed.json
cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  transfer send /tmp/tx1_signed.json

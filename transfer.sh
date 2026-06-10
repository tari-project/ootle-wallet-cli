#!/usr/bin/env bash

set -e

# Example usage of the CLI against a local network.
# Note: Uncomment the following line to create and fund an account if needed.
#cargo run --release -- --network=localnet -ihttp://localhost:12500 create-account -ntest

ADDRESS=otl_loc_1azl4ty0l9t7czfy8gk7vter08pgy20ex7ptj4lu3d0hm46wmceans07r4dfpqa9fhhv89ngs0h9rnlj0srrv8p9zayxrt8aslgjx68sk0smcz
AMOUNT=10000000

cargo run --release -- --network=localnet -ihttp://localhost:12500 \
  transfer --to-address=$ADDRESS --amount=$AMOUNT --fee-amount=1300
cargo run --release -- --network=localnet -ihttp://localhost:12500 balance
cargo run --release -- --network=localnet -ihttp://localhost:12500 history

#!/usr/bin/env pwsh

$ErrorActionPreference = "Stop"


# Note: Uncomment the following lines to create seed words and a spend account if needed.
# cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  create-seed-words
# cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017  create-account -ntest


# Example usage of the transfer commands in the CLI tool.
$ADDRESS = "xtr_loc_15rdukntc5swqk2kqmyn004tj4ap83ekyvcahzwstxfql22cpfsm9fxq0ax6qsm2ylh3kfadrkhnvp5xtcgszvtmpswk4a64les34kcgkr3aa5"
$AMOUNT = 10000000

cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017 `
  transfer create --to-address=$ADDRESS --amount=$AMOUNT --num-outputs=7 --message="Transfer" --fee-amount=1100 -o /tmp/transfer.json

cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017 `
  transfer transaction /tmp/transfer.json /tmp/tx1.json

cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017 `
  transfer sign /tmp/tx1.json /tmp/tx1_signed.json

cargo run --release -- --network=localnet --password=123 -ihttp://localhost:12017 `
  transfer send /tmp/tx1_signed.json

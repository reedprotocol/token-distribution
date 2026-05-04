use aiken/collection/list as list
use cardano/address.{Address, Credential}
use cardano/assets as value
use cardano/transaction.{InlineDatum, Output, OutputReference, Transaction, find_input}

use token_distribution/types as types
use token_distribution/utils

fn safe_add(a: Int, b: Int) -> Int {
  let s = a + b
  if b >= 0 {
    expect s >= a
  } else {
    expect s <= a
  }
  s
}

fn safe_mul(a: Int, b: Int) -> Int {
  if a == 0 || b == 0 {
    0
  } else {
    let p = a * b
    expect p / a == b
    p
  }
}

fn is_pure_vesting_value(
  v: value.Value,
  policy_id: value.PolicyId,
  asset_name: value.AssetName,
  qty: Int,
) -> Bool {
  let other =
    v
      |> value.without_lovelace
      |> value.add(policy_id, asset_name, 0 - qty)
  value.is_zero(other)
}

fn sum_token_qty(outputs: List<Output>, policy_id: value.PolicyId, asset_name: value.AssetName) -> Int {
  list.foldl(outputs, 0, fn(o, acc) { acc + value.quantity_of(o.value, policy_id, asset_name) })
}

fn sum_token_qty_to_cred(
  outputs: List<Output>,
  cred: Credential,
  policy_id: value.PolicyId,
  asset_name: value.AssetName,
) -> Int {
  list.foldl(
    outputs,
    0,
    fn(o, acc) {
      if o.address.payment_credential == cred {
        acc + value.quantity_of(o.value, policy_id, asset_name)
      } else {
        acc
      }
    },
  )
}

fn continuing_outputs(outputs: List<Output>, script_addr: Address) -> List<Output> {
  list.filter(outputs, fn(o) { o.address == script_addr })
}

fn token_outputs(outputs: List<Output>, policy_id: value.PolicyId, asset_name: value.AssetName) -> List<Output> {
  list.filter(outputs, fn(o) { value.quantity_of(o.value, policy_id, asset_name) != 0 })
}

fn vested_amount(
  total: Int,
  start_ms: Int,
  cliff_ms: Int,
  duration_ms: Int,
  now_ms: Int,
) -> Int {
  let vest_start = safe_add(start_ms, cliff_ms)
  if now_ms < vest_start {
    0
  } else {
    let elapsed = now_ms - vest_start
    if elapsed >= duration_ms {
      total
    } else {
      safe_mul(total, elapsed) / duration_ms
    }
  }
}

pub fn validate(
  params: types.TeamVestingParams,
  datum: types.TeamVestingDatum,
  red: types.TeamVestingRedeemer,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  expect params.cliff_ms >= 0
  expect params.duration_ms > 0
  expect params.min_ada >= 0

  expect value.quantity_of(tx.mint, params.policy_id, params.asset_name) == 0

  expect list.any(tx.extra_signatories, fn(s) { s == params.beneficiary })

  expect Some(own_input) =
    tx.inputs
      |> find_input(own_ref)

  expect Credential.Script(_own_hash) =
    own_input.output.address.payment_credential

  let script_inputs_count =
    list.foldl(
      tx.inputs,
      0,
      fn(i, acc) {
        if i.output.address == own_input.output.address {
          acc + 1
        } else {
          acc
        }
      },
    )
  expect script_inputs_count == 1

  let in_token_qty =
    value.quantity_of(
      own_input.output.value,
      params.policy_id,
      params.asset_name,
    )

  let out_token_qty = sum_token_qty(tx.outputs, params.policy_id, params.asset_name)
  expect out_token_qty == in_token_qty

  expect
    is_pure_vesting_value(
      own_input.output.value,
      params.policy_id,
      params.asset_name,
      in_token_qty,
    )

  expect datum.total_amount >= 0
  expect datum.claimed_amount >= 0
  expect datum.claimed_amount <= datum.total_amount

  expect in_token_qty == datum.total_amount - datum.claimed_amount

  let now_ms = utils.tx_lower_bound_ms(tx)

  let vested = vested_amount(
    datum.total_amount,
    datum.start_time_ms,
    params.cliff_ms,
    params.duration_ms,
    now_ms,
  )

  let available = vested - datum.claimed_amount
  expect available >= 0

  let types.Withdraw { amount } = red
  expect amount > 0
  expect amount <= available

  let beneficiary_cred = Credential.VerificationKey(params.beneficiary)

  let beneficiary_token_qty =
    sum_token_qty_to_cred(tx.outputs, beneficiary_cred, params.policy_id, params.asset_name)
  expect beneficiary_token_qty == amount

  let token_outs = token_outputs(tx.outputs, params.policy_id, params.asset_name)
  expect
    list.all(
      token_outs,
      fn(o) {
        o.address.payment_credential == beneficiary_cred ||
          o.address == own_input.output.address
      },
    )

  let continuing_outputs = continuing_outputs(tx.outputs, own_input.output.address)

  let end_ms =
    safe_add(
      safe_add(datum.start_time_ms, params.cliff_ms),
      params.duration_ms,
    )

  let final =
    now_ms >= end_ms &&
      amount == datum.total_amount - datum.claimed_amount

  if final {
    expect list.length(continuing_outputs) == 0
    True
  } else {
    let new_claimed = datum.claimed_amount + amount
    expect new_claimed <= datum.total_amount
    expect list.length(continuing_outputs) == 1
    expect Some(cont_out) = list.at(continuing_outputs, 0)
    expect cont_out.address == own_input.output.address

    expect value.lovelace_of(cont_out.value) >= params.min_ada

    let cont_token_qty =
      value.quantity_of(cont_out.value, params.policy_id, params.asset_name)
    expect
      is_pure_vesting_value(
        cont_out.value,
        params.policy_id,
        params.asset_name,
        cont_token_qty,
      )

    expect InlineDatum(cont_d) = cont_out.datum
    expect cont_datum: types.TeamVestingDatum = cont_d
    expect cont_datum.start_time_ms == datum.start_time_ms
    expect cont_datum.total_amount == datum.total_amount
    expect cont_datum.claimed_amount == new_claimed
    expect cont_token_qty == datum.total_amount - new_claimed
    True
  }
}

validator team(params: types.TeamVestingParams) {
  spend(
    datum_opt: Option<types.TeamVestingDatum>,
    red: types.TeamVestingRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(datum) = datum_opt
    validate(params, datum, red, own_ref, tx)
  }
}

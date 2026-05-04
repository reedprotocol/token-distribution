use aiken/cbor
use aiken/collection/dict as dict
use aiken/collection/list as list
use aiken/crypto as hash
use aiken/interval
use aiken/primitive/bytearray as bytearray
use cardano/address.{Credential}
use cardano/assets.{PolicyId}
use cardano/assets as value
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction, find_input}

use token_distribution/types as types
use token_distribution/utils

fn bucket_token_name(bucket_id: Int) -> ByteArray {
  bytearray.concat("SEED_BUCKET", bytearray.from_int_big_endian(bucket_id, 1))
}

fn bucket_id_for_beneficiary(params: types.SeedParams, beneficiary: ByteArray) -> Int {
  let h = hash.blake2b_256(beneficiary)
  let b0 = bytearray.at(h, 0)
  b0 % params.bucket_count
}

fn is_strictly_sorted_unique_pkhs(xs: List<ByteArray>) -> Bool {
  when xs is {
    [] -> True
    [_] -> True
    [a, b, ..rest] ->
      when bytearray.compare(a, b) is {
        Less -> is_strictly_sorted_unique_pkhs([b, ..rest])
        _ -> False
      }
  }
}

fn is_sorted_subsequence(xs: List<ByteArray>, ys: List<ByteArray>) -> Bool {
  when (xs, ys) is {
    ([], _) -> True
    (_, []) -> False
    ([x, ..xs_tail], [y, ..ys_tail]) ->
      when bytearray.compare(x, y) is {
        Equal -> is_sorted_subsequence(xs_tail, ys_tail)
        Greater -> is_sorted_subsequence([x, ..xs_tail], ys_tail)
        Less -> False
      }
  }
}

fn sorted_contains(x: ByteArray, xs: List<ByteArray>) -> Bool {
  when xs is {
    [] -> False
    [y, ..ys] ->
      when bytearray.compare(x, y) is {
        Equal -> True
        Less -> False
        Greater -> sorted_contains(x, ys)
      }
  }
}

fn expect_one_input(inputs: List<Input>, predicate: fn(Input) -> Bool) -> Input {
  let (count, in_opt) =
    list.foldl(
      inputs,
      (0, None),
      fn(i, acc) {
        let (c, found) = acc
        if predicate(i) {
          (c + 1, Some(i))
        } else {
          (c, found)
        }
      },
    )

  expect count == 1
  expect Some(i) = in_opt
  i
}

fn expect_one_output(outs: List<Output>, predicate: fn(Output) -> Bool) -> Output {
  let (count, out_opt) =
    list.foldl(
      outs,
      (0, None),
      fn(o, acc) {
        let (c, found) = acc
        if predicate(o) {
          (c + 1, Some(o))
        } else {
          (c, found)
        }
      },
    )

  expect count == 1
  expect Some(o) = out_opt
  o
}

fn all_in_bucket(params: types.SeedParams, bucket_id: Int, xs: List<ByteArray>) -> Bool {
  list.all(xs, fn(pkh) { bucket_id_for_beneficiary(params, pkh) == bucket_id })
}

fn verify_anchor_leaf(
  root: ByteArray,
  beneficiary: ByteArray,
  initial_remaining_b: Int,
  proof: List<ByteArray>,
) -> Bool {
  expect list.length(proof) <= 32

  let leaf =
    hash.blake2b_256(
      bytearray.concat(
        "SEED_ANCHOR",
        bytearray.concat(
          beneficiary,
          cbor.serialise(initial_remaining_b),
        ),
      ),
    )

  let computed =
    list.foldl(
      proof,
      leaf,
      fn(sibling, acc) {
        when bytearray.compare(acc, sibling) is {
          Less | Equal ->
            hash.blake2b_256(
              bytearray.concat(
                "SEED_NODE",
                bytearray.concat(acc, sibling),
              ),
            )
          Greater ->
            hash.blake2b_256(
              bytearray.concat(
                "SEED_NODE",
                bytearray.concat(sibling, acc),
              ),
            )
        }
      },
    )

  computed == root
}

fn end_time_ms(params: types.SeedParams) -> Int {
  params.start_time_ms + params.duration_ms
}

fn tx_now_lb_ms(tx: Transaction) -> Int {
  when tx.validity_range.lower_bound.bound_type is {
    interval.Finite(lb) -> lb
    // Conservatively default to 0 (no time passed) if no lower bound set.
    // This prevents tx failures from wallets/builders that omit lower bounds,
    // while maintaining safety: vesting calculations default to "nothing released yet".
    _ -> 0
  }
}

fn minted_under_policy(tx: Transaction, pid: value.PolicyId) -> Pairs<ByteArray, Int> {
  let toks = value.tokens(tx.mint, pid)
  dict.to_pairs(toks)
}

fn minted_keys_sorted(tx: Transaction, pid: value.PolicyId) -> List<ByteArray> {
  minted_under_policy(tx, pid)
    |> list.map(fn(p) {
      let Pair(k, _) = p
      k
    })
    |> list.sort(bytearray.compare)
}

fn anchors_keys_sorted(anchors: List<types.SeedAnchorMint>) -> List<ByteArray> {
  anchors
    |> list.map(fn(a) { a.beneficiary })
    |> list.sort(bytearray.compare)
}

fn validate_mint_init(
  params: types.SeedParams,
  own_policy: PolicyId,
  r: types.SeedMintRedeemer,
  tx: Transaction,
) -> Bool {
  when r is {
    types.SeedInitPool { pool_output_index, registry_output_start_index } -> {
      trace @"SeedInitPool: start"
      expect list.any(tx.inputs, fn(i) { i.output_reference == params.seed_out_ref })

      trace @"SeedInitPool: has seed_out_ref input"

      expect value.quantity_of(tx.mint, own_policy, params.pool_nft_asset_name) == 1

      trace @"SeedInitPool: minted pool nft == 1"

      expect Some(pool_out) = list.at(tx.outputs, pool_output_index)
      expect pool_out.address.payment_credential == Credential.Script(own_policy)
      expect value.quantity_of(pool_out.value, own_policy, params.pool_nft_asset_name) == 1

      trace @"SeedInitPool: pool output ok (addr + nft)"

      expect InlineDatum(pool_d_any) = pool_out.datum
      expect pool_d: types.SeedDatum = pool_d_any
      expect types.Pool { distributed_a } = pool_d
      expect distributed_a == 0

      trace @"SeedInitPool: pool datum ok"

      let reg_ok =
        list.all(
          list.range(0, params.bucket_count - 1),
          fn(i) {
            let an = bucket_token_name(i)
            expect value.quantity_of(tx.mint, own_policy, an) == 1
            expect Some(o) = list.at(tx.outputs, registry_output_start_index + i)
            expect o.address == pool_out.address
            expect value.quantity_of(o.value, own_policy, an) == 1
            expect InlineDatum(d_any) = o.datum
            expect d: types.SeedDatum = d_any
            expect types.RegistryBucket { bucket_id, entries } = d
            bucket_id == i && list.is_empty(entries) &&
              is_pure_state_nft(o.value, params, own_policy, an)
          },
        )

      trace @"SeedInitPool: registry outputs ok"

      let minted_pairs = minted_under_policy(tx, own_policy)
      expect list.length(minted_pairs) == 1 + params.bucket_count

      trace @"SeedInitPool: minted_pairs length ok"
      reg_ok
    }

    types.SeedInitAnchors { pool_output_index: _, anchors } -> {
      expect value.quantity_of(tx.mint, own_policy, params.pool_nft_asset_name) == 0

      let pool_in =
        expect_one_input(
          tx.reference_inputs,
          fn(i) {
            i.output.address.payment_credential == Credential.Script(own_policy) &&
              value.quantity_of(i.output.value, own_policy, params.pool_nft_asset_name) == 1
          },
        )
      expect InlineDatum(pool_d_any) = pool_in.output.datum
      expect pool_d: types.SeedDatum = pool_d_any
      expect types.Pool { .. } = pool_d

      let ok = list.all(
        anchors,
        fn(a) {
          let ben = a.beneficiary
          expect bytearray.length(ben) == 28
          expect a.initial_remaining_b >= 0

          // Hardening: require the beneficiary to co-sign anchor initialization.
          expect list.any(tx.extra_signatories, fn(s) { s == ben })

          let bucket_id = bucket_id_for_beneficiary(params, ben)
          let bucket_an = bucket_token_name(bucket_id)

          let bucket_in =
            expect_one_input(
              tx.inputs,
              fn(i) {
                i.output.address.payment_credential == Credential.Script(own_policy) &&
                  value.quantity_of(i.output.value, own_policy, bucket_an) == 1
              },
            )

          let bucket_out =
            expect_one_output(
              tx.outputs,
              fn(o) {
                o.address.payment_credential == Credential.Script(own_policy) &&
                  value.quantity_of(o.value, own_policy, bucket_an) == 1
              },
            )

          expect InlineDatum(b_in_any) = bucket_in.output.datum
          expect b_in: types.SeedDatum = b_in_any
          expect types.RegistryBucket { bucket_id, entries: entries_in } = b_in
          expect bucket_id >= 0
          expect bucket_id < params.bucket_count
          expect is_strictly_sorted_unique_pkhs(entries_in)
          expect all_in_bucket(params, bucket_id, entries_in)
          expect sorted_contains(ben, entries_in) == False

          expect InlineDatum(b_out_any) = bucket_out.datum
          expect b_out: types.SeedDatum = b_out_any
          expect types.RegistryBucket { bucket_id: out_id, entries: out_entries } = b_out
          expect out_id == bucket_id
          expect is_strictly_sorted_unique_pkhs(out_entries)
          expect all_in_bucket(params, bucket_id, out_entries)
          expect list.length(out_entries) == list.length(entries_in) + 1
          expect list.length(out_entries) <= params.bucket_max_entries
          expect sorted_contains(ben, out_entries)
          expect is_sorted_subsequence(entries_in, out_entries)

          let proof_ok = verify_anchor_leaf(params.anchors_root, ben, a.initial_remaining_b, a.merkle_proof)
          let minted_ok = value.quantity_of(tx.mint, own_policy, ben) == 1

          let anchor_outs =
            list.filter(
              tx.outputs,
              fn(o) {
                o.address.payment_credential == Credential.Script(own_policy) &&
                  value.quantity_of(o.value, own_policy, ben) == 1
              },
            )

          let out_ok =
            if list.length(anchor_outs) == 1 {
              expect [ao] = anchor_outs
              // Enforce all state UTxOs use the exact same script address (incl stake credential)
              expect ao.address == pool_in.output.address
              expect InlineDatum(anchor_d_any) = ao.datum
              expect anchor_d: types.SeedDatum = anchor_d_any
              expect types.Anchor { beneficiary, remaining_b, initial_remaining_b } = anchor_d
              beneficiary == ben && remaining_b == a.initial_remaining_b && initial_remaining_b == a.initial_remaining_b &&
                is_pure_state_nft(ao.value, params, own_policy, ben)
            } else {
              False
            }

          proof_ok && minted_ok && out_ok
        },
      )

      // Defensive: forbid minting any extra asset names under this policy.
      let minted_pairs = minted_under_policy(tx, own_policy)
      expect list.all(minted_pairs, fn(p) {
        let Pair(_, q) = p
        q == 1
      })
      expect anchors_keys_sorted(anchors) == minted_keys_sorted(tx, own_policy)
      ok
    }
    _ -> False
  }
}

fn validate_mint_burn(params: types.SeedParams, own_policy: PolicyId, tx: Transaction) -> Bool {
  let now = tx_now_lb_ms(tx)
  expect now >= end_time_ms(params)

  let minted = minted_under_policy(tx, own_policy)

  list.all(minted, fn(p) {
    let Pair(_, amt) = p
    amt == -1
  }) && value.quantity_of(tx.mint, own_policy, params.pool_nft_asset_name) == -1
}

fn validate_mint_burn_anchor(
  params: types.SeedParams,
  own_policy: PolicyId,
  beneficiary: ByteArray,
  tx: Transaction,
) -> Bool {
  let now = tx_now_lb_ms(tx)
  expect now >= end_time_ms(params)
  // Strict: burn exactly one Anchor auth token for the given beneficiary.
  dict.to_pairs(value.tokens(tx.mint, own_policy)) == [Pair(beneficiary, -1)]
}

fn validate_mint_burn_anchors(
  params: types.SeedParams,
  own_policy: PolicyId,
  beneficiaries: List<ByteArray>,
  tx: Transaction,
) -> Bool {
  let now = tx_now_lb_ms(tx)
  expect now >= end_time_ms(params)

  // Anchor-first cleanup: forbid burning Pool/Bucket NFTs in this mode.
  expect value.quantity_of(tx.mint, own_policy, params.pool_nft_asset_name) == 0
  expect list.all(list.range(0, params.bucket_count - 1), fn(i) {
    let an = bucket_token_name(i)
    value.quantity_of(tx.mint, own_policy, an) == 0
  })

  let minted = minted_under_policy(tx, own_policy)

  // Burn-only and no extras under this policy.
  expect list.all(minted, fn(p) {
    let Pair(_, amt) = p
    amt == -1
  })

  // Defensive: minted keys must be exactly the provided beneficiaries (no extras, no duplicates).
  let bs_sorted = beneficiaries |> list.sort(bytearray.compare)
  expect bs_sorted == minted_keys_sorted(tx, own_policy)
  True
}

fn validate_mint_burn_any(params: types.SeedParams, own_policy: PolicyId, tx: Transaction) -> Bool {
  expect interval.Finite(now) = tx.validity_range.lower_bound.bound_type
  expect now >= end_time_ms(params)

  let minted = minted_under_policy(tx, own_policy)

  // Burn-only under this policy.
  expect list.all(minted, fn(p) {
    let Pair(_, amt) = p
    amt < 0
  })

  // For each burned asset name, burn exactly the quantity present across all script inputs.
  // This supports end-of-life cleanup (Drain) where arbitrary leftover state NFTs can be burned.
  list.all(minted, fn(p) {
    let Pair(an, amt) = p
    let in_qty =
      tx.inputs
        |> list.filter(fn(i) { i.output.address.payment_credential == Credential.Script(own_policy) })
        |> list.foldl(0, fn(i, acc) { acc + value.quantity_of(i.output.value, own_policy, an) })
    amt == 0 - in_qty
  })
}

fn is_only_allowed_assets(
  v: value.Value,
  token_a_pid: value.PolicyId,
  token_a_an: value.AssetName,
  token_a_qty: Int,
  token_b_pid: value.PolicyId,
  token_b_an: value.AssetName,
  token_b_qty: Int,
  extra_pid: value.PolicyId,
  extra_an: value.AssetName,
  extra_qty: Int,
) -> Bool {
  let other =
    v
      |> value.without_lovelace
      |> value.add(token_a_pid, token_a_an, 0 - token_a_qty)
      |> value.add(token_b_pid, token_b_an, 0 - token_b_qty)
      |> value.add(extra_pid, extra_an, 0 - extra_qty)

  value.is_zero(other)
}

fn is_pure_state_nft(
  v: value.Value,
  params: types.SeedParams,
  own_policy: value.PolicyId,
  an: value.AssetName,
) -> Bool {
  is_only_allowed_assets(
    v,
    params.token_a_policy_id,
    params.token_a_asset_name,
    0,
    params.token_b_policy_id,
    params.token_b_asset_name,
    0,
    own_policy,
    an,
    1,
  )
}

fn is_pure_pool_state(
  v: value.Value,
  params: types.SeedParams,
  own_policy: value.PolicyId,
  a_qty: Int,
  b_qty: Int,
) -> Bool {
  is_only_allowed_assets(
    v,
    params.token_a_policy_id,
    params.token_a_asset_name,
    a_qty,
    params.token_b_policy_id,
    params.token_b_asset_name,
    b_qty,
    own_policy,
    params.pool_nft_asset_name,
    1,
  )
}

fn released_amount(total: Int, start_ms: Int, duration_ms: Int, initial_bps: Int, now_ms: Int) -> Int {
  if now_ms < start_ms {
    0
  } else {
    let initial = (total * initial_bps) / 10_000
    if now_ms >= start_ms + duration_ms {
      total
    } else {
      let remaining = total - initial
      let elapsed = now_ms - start_ms
      // Note: integer division rounds down; dust remains until Sweep.
      initial + (remaining * elapsed) / duration_ms
    }
  }
}

pub fn validate(
  params: types.SeedParams,
  _datum: types.SeedDatum,
  red: types.SeedRedeemer,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  expect params.duration_ms > 0
  expect params.initial_unlock_bps >= 0
  expect params.initial_unlock_bps <= 10_000
  expect params.y > 0
  expect params.bucket_max_entries > 0

  expect interval.Finite(now_lb_ms) = tx.validity_range.lower_bound.bound_type
  expect interval.Finite(now_ub_ms) = tx.validity_range.upper_bound.bound_type

  expect value.quantity_of(tx.mint, params.token_a_policy_id, params.token_a_asset_name) == 0
  expect value.quantity_of(tx.mint, params.token_b_policy_id, params.token_b_asset_name) == 0

  expect Some(own_input) = tx.inputs |> find_input(own_ref)
  expect Credential.Script(own_hash) = own_input.output.address.payment_credential

  let own_addr = own_input.output.address
  let own_inputs = list.filter(tx.inputs, fn(i) { i.output.address == own_addr })
  let own_outputs = list.filter(tx.outputs, fn(o) { o.address == own_addr })

  let paid_to_vault = utils.paid_to_cred(tx.outputs, params.vault_cred)

  when red is {
    types.Swap { b_in } -> {
      // Use upper bound to ensure the tx cannot be included after the deadline.
      expect now_ub_ms < params.start_time_ms + params.duration_ms
      expect b_in >= params.y

      // Safe-side slippage: accept any b_in and round down the effective amount to a multiple of y.
      // Any remainder is effectively donated to the pool (user receives slightly less A).
      let effective_b = (b_in / params.y) * params.y

      let a_out = effective_b / params.y

      let own_inputs_with_inline_datum =
        list.filter(own_inputs, fn(i) {
          when i.output.datum is {
            InlineDatum(_) -> True
            _ -> False
          }
        })
      expect list.length(own_inputs_with_inline_datum) == 2

      // Defensive: forbid any other inline-datum state inputs at this script address.
      // Extra script inputs are permitted only if they do not carry InlineDatum.
      expect list.length(own_inputs_with_inline_datum) ==
        list.length(
          list.filter(own_inputs, fn(i) {
            when i.output.datum is {
              InlineDatum(_) -> True
              _ -> False
            }
          }),
        )

      let own_outputs_with_inline_datum =
        list.filter(own_outputs, fn(o) {
          when o.datum is {
            InlineDatum(_) -> True
            _ -> False
          }
        })
      expect list.length(own_outputs_with_inline_datum) == 2

      // Defensive: forbid any other inline-datum state outputs at this script address.
      // Extra script outputs are permitted only if they do not carry InlineDatum.
      expect list.length(own_outputs_with_inline_datum) ==
        list.length(
          list.filter(own_outputs, fn(o) {
            when o.datum is {
              InlineDatum(_) -> True
              _ -> False
            }
          }),
        )

      expect [in_1, in_2] = own_inputs_with_inline_datum

      expect InlineDatum(state_d_1) = in_1.output.datum
      expect state_datum_1: types.SeedDatum = state_d_1

      expect InlineDatum(state_d_2) = in_2.output.datum
      expect state_datum_2: types.SeedDatum = state_d_2

      // Enforce: exactly one Pool and one Anchor among state inputs
      let (pool_in, anchor_in, distributed_a, beneficiary, remaining_b, initial_remaining_b) =
        when (state_datum_1, state_datum_2) is {
          (types.Pool { distributed_a }, types.Anchor { beneficiary, remaining_b, initial_remaining_b }) ->
            (in_1, in_2, distributed_a, beneficiary, remaining_b, initial_remaining_b)
          (types.Anchor { beneficiary, remaining_b, initial_remaining_b }, types.Pool { distributed_a }) ->
            (in_2, in_1, distributed_a, beneficiary, remaining_b, initial_remaining_b)
          _ -> fail
        }

      // Beneficiary encoding constraint: must be a payment key hash (28 bytes)
      expect bytearray.length(beneficiary) == 28

      expect list.any(tx.extra_signatories, fn(s) { s == beneficiary })

      expect initial_remaining_b >= 0
      expect remaining_b >= 0
      expect remaining_b <= initial_remaining_b

      expect effective_b <= remaining_b
      let new_remaining = remaining_b - effective_b

      // Strict: bind b_in to non-script inputs.
      let external_b_in =
        tx.inputs
          |> list.filter(fn(i) { i.output.address != own_addr })
          |> list.foldl(0, fn(i, acc) {
            acc + value.quantity_of(i.output.value, params.token_b_policy_id, params.token_b_asset_name)
          })
      expect external_b_in == b_in

      let pool_nft_qty_in =
        value.quantity_of(pool_in.output.value, own_hash, params.pool_nft_asset_name)
      expect pool_nft_qty_in == 1

      let anchor_auth_qty_in =
        value.quantity_of(anchor_in.output.value, own_hash, beneficiary)
      expect anchor_auth_qty_in == 1

      // Enforce: there is only one auth token for this beneficiary present across all tx inputs.
      let total_anchor_auth_in_tx =
        tx.inputs
          |> list.foldl(0, fn(i, acc) {
            acc + value.quantity_of(i.output.value, own_hash, beneficiary)
          })
      expect total_anchor_auth_in_tx == 1

      let a_in_pool = value.quantity_of(pool_in.output.value, params.token_a_policy_id, params.token_a_asset_name)
      let b_in_pool = value.quantity_of(pool_in.output.value, params.token_b_policy_id, params.token_b_asset_name)

      expect is_pure_pool_state(pool_in.output.value, params, own_hash, a_in_pool, b_in_pool)

      expect is_pure_state_nft(anchor_in.output.value, params, own_hash, beneficiary)

      expect [out_1, out_2] = own_outputs_with_inline_datum

      expect InlineDatum(state_out_d_1) = out_1.datum
      expect state_out_datum_1: types.SeedDatum = state_out_d_1

      expect InlineDatum(state_out_d_2) = out_2.datum
      expect state_out_datum_2: types.SeedDatum = state_out_d_2

      // Enforce: exactly one Pool and one Anchor among state outputs
      let (pool_out, anchor_out, new_distributed, out_beneficiary, out_remaining, out_initial) =
        when (state_out_datum_1, state_out_datum_2) is {
          (types.Pool { distributed_a: new_distributed }, types.Anchor { beneficiary: out_beneficiary, remaining_b: out_remaining, initial_remaining_b: out_initial }) ->
            (out_1, out_2, new_distributed, out_beneficiary, out_remaining, out_initial)
          (types.Anchor { beneficiary: out_beneficiary, remaining_b: out_remaining, initial_remaining_b: out_initial }, types.Pool { distributed_a: new_distributed }) ->
            (out_2, out_1, new_distributed, out_beneficiary, out_remaining, out_initial)
          _ -> fail
        }

      // Explicitly enforce outputs stay at the script address.
      let pool_nft_qty_out =
        value.quantity_of(pool_out.value, own_hash, params.pool_nft_asset_name)
      expect pool_nft_qty_out == 1

      let anchor_auth_qty_out =
        value.quantity_of(anchor_out.value, own_hash, beneficiary)
      expect anchor_auth_qty_out == 1

      let a_out_pool = value.quantity_of(pool_out.value, params.token_a_policy_id, params.token_a_asset_name)
      let b_out_pool = value.quantity_of(pool_out.value, params.token_b_policy_id, params.token_b_asset_name)

      expect is_pure_pool_state(pool_out.value, params, own_hash, a_out_pool, b_out_pool)

      expect is_pure_state_nft(anchor_out.value, params, own_hash, beneficiary)

      let pool_in_ada = value.lovelace_of(pool_in.output.value)
      let pool_out_ada = value.lovelace_of(pool_out.value)
      expect pool_out_ada >= pool_in_ada

      let anchor_in_ada = value.lovelace_of(anchor_in.output.value)
      let anchor_out_ada = value.lovelace_of(anchor_out.value)
      expect anchor_out_ada >= anchor_in_ada

      expect a_out_pool == a_in_pool - a_out
      expect b_out_pool == b_in_pool + b_in

      // Ensure at least a_out token A leaves the script to external outputs.
      let external_a_out =
        tx.outputs
          |> list.filter(fn(o) { o.address != own_addr })
          |> list.foldl(0, fn(o, acc) {
            acc + value.quantity_of(o.value, params.token_a_policy_id, params.token_a_asset_name)
          })
      expect external_a_out == a_out

      // Bind the Token A payout to the beneficiary.
      let paid_to_beneficiary =
        utils.paid_to_cred(tx.outputs, Credential.VerificationKey(beneficiary))
      let beneficiary_a_out =
        value.quantity_of(
          paid_to_beneficiary,
          params.token_a_policy_id,
          params.token_a_asset_name,
        )
      expect beneficiary_a_out == a_out
      expect new_distributed == distributed_a + a_out

      let total_pool_a = distributed_a + a_in_pool
      let released = released_amount(
        total_pool_a,
        params.start_time_ms,
        params.duration_ms,
        params.initial_unlock_bps,
        now_lb_ms,
      )
      expect new_distributed <= released

      expect out_beneficiary == beneficiary
      expect out_initial == initial_remaining_b
      expect out_remaining == new_remaining

      True
    }

    types.FlushB -> {
      expect [state_in] = own_inputs
      expect InlineDatum(state_d) = state_in.output.datum
      expect state_datum: types.SeedDatum = state_d
      expect types.Pool { distributed_a } = state_datum

      let pool_nft_qty_in =
        value.quantity_of(state_in.output.value, own_hash, params.pool_nft_asset_name)
      expect pool_nft_qty_in == 1

      let pool_in_a = value.quantity_of(state_in.output.value, params.token_a_policy_id, params.token_a_asset_name)
      let pool_in_b = value.quantity_of(state_in.output.value, params.token_b_policy_id, params.token_b_asset_name)

      expect [pool_out] = own_outputs
      expect InlineDatum(pool_out_d) = pool_out.datum
      expect pool_out_datum: types.SeedDatum = pool_out_d
      expect types.Pool { distributed_a: new_distributed } = pool_out_datum
      expect new_distributed == distributed_a

      let pool_nft_qty_out =
        value.quantity_of(pool_out.value, own_hash, params.pool_nft_asset_name)
      expect pool_nft_qty_out == 1

      let pool_out_a = value.quantity_of(pool_out.value, params.token_a_policy_id, params.token_a_asset_name)
      let pool_out_b = value.quantity_of(pool_out.value, params.token_b_policy_id, params.token_b_asset_name)

      expect pool_out_a == pool_in_a
      expect pool_out_b == 0

      let pool_in_ada = value.lovelace_of(state_in.output.value)
      let pool_out_ada = value.lovelace_of(pool_out.value)
      expect pool_out_ada >= pool_in_ada

      expect is_pure_pool_state(state_in.output.value, params, own_hash, pool_in_a, pool_in_b)
      expect is_pure_pool_state(pool_out.value, params, own_hash, pool_out_a, 0)

      let vault_b = value.quantity_of(paid_to_vault, params.token_b_policy_id, params.token_b_asset_name)
      expect vault_b == pool_in_b
      True
    }

    types.Sweep -> {
      expect now_lb_ms >= params.start_time_ms + params.duration_ms
      expect list.is_empty(own_outputs)

      // Shutdown is atomic: require burning the Pool NFT in the same tx.
      expect value.quantity_of(tx.mint, own_hash, params.pool_nft_asset_name) == -1

      let is_pool_input =
        value.quantity_of(own_input.output.value, own_hash, params.pool_nft_asset_name) == 1

      if is_pool_input {

      // Strict atomic shutdown: the Pool UTxO must be consumed in this tx.
      let pool_in =
        expect_one_input(
          own_inputs,
          fn(i) {
            value.quantity_of(i.output.value, own_hash, params.pool_nft_asset_name) == 1
          },
        )
      expect InlineDatum(pool_d_any) = pool_in.output.datum
      expect pool_d: types.SeedDatum = pool_d_any
      expect types.Pool { .. } = pool_d

      let vault_a = value.quantity_of(paid_to_vault, params.token_a_policy_id, params.token_a_asset_name)

      let (a_in_script, b_in_script) =
        own_inputs
          |> list.foldl((0, 0), fn(i, acc) {
            let (a_acc, b_acc) = acc
            (
              a_acc + value.quantity_of(i.output.value, params.token_a_policy_id, params.token_a_asset_name),
              b_acc + value.quantity_of(i.output.value, params.token_b_policy_id, params.token_b_asset_name),
            )
          })

      expect vault_a == a_in_script
      let vault_b = value.quantity_of(paid_to_vault, params.token_b_policy_id, params.token_b_asset_name)
      expect vault_b == b_in_script
      True
      } else {
        expect InlineDatum(d_in_any) = own_input.output.datum
        expect d_in: types.SeedDatum = d_in_any

        when d_in is {
          types.RegistryBucket { bucket_id, .. } -> {
            let an = bucket_token_name(bucket_id)
            expect value.quantity_of(own_input.output.value, own_hash, an) == 1
            expect value.quantity_of(tx.mint, own_hash, an) == -1
            expect is_pure_state_nft(own_input.output.value, params, own_hash, an)
            True
          }

          types.Anchor { beneficiary, .. } -> {
            expect bytearray.length(beneficiary) == 28
            expect value.quantity_of(own_input.output.value, own_hash, beneficiary) == 1
            expect value.quantity_of(tx.mint, own_hash, beneficiary) == -1
            expect is_pure_state_nft(own_input.output.value, params, own_hash, beneficiary)
            True
          }

          _ -> False
        }
      }
    }

    types.SweepAnchor -> {
      expect now_lb_ms >= params.start_time_ms + params.duration_ms
      expect list.is_empty(own_outputs)

      expect InlineDatum(state_d) = own_input.output.datum
      expect state_datum: types.SeedDatum = state_d
      expect types.Anchor { beneficiary, .. } = state_datum

      // Beneficiary encoding constraint: must be a payment key hash (28 bytes)
      expect bytearray.length(beneficiary) == 28

      let anchor_auth_qty_in =
        value.quantity_of(own_input.output.value, own_hash, beneficiary)
      expect anchor_auth_qty_in == 1

      // Strict: burn the Anchor auth token atomically in the same tx.
      expect value.quantity_of(tx.mint, own_hash, beneficiary) == -1

      // Anchor UTxOs should not hold Token A or Token B.
      expect is_pure_state_nft(own_input.output.value, params, own_hash, beneficiary)

      True
    }

    types.UpdateBucketForAnchor { beneficiary, initial_remaining_b, merkle_proof } -> {
      // Strict bucket update coupled to a single anchor creation.
      // Consumes one RegistryBucket and produces one updated RegistryBucket with +1 entry.

      // Validate the spent datum is a RegistryBucket
      expect InlineDatum(d_in_any) = own_input.output.datum
      expect d_in: types.SeedDatum = d_in_any
      expect types.RegistryBucket { bucket_id, entries: entries_in } = d_in

      expect bytearray.length(beneficiary) == 28
      expect initial_remaining_b >= 0

      // Ensure this bucket id corresponds to beneficiary
      expect bucket_id == bucket_id_for_beneficiary(params, beneficiary)
      let bucket_an = bucket_token_name(bucket_id)

      // Ensure the bucket NFT is present on input
      expect value.quantity_of(own_input.output.value, own_hash, bucket_an) == 1

      // Bucket UTxOs should not hold Token A or Token B (or any extra assets beyond the bucket NFT).
      expect is_pure_state_nft(own_input.output.value, params, own_hash, bucket_an)

      // Find the corresponding bucket output
      let bucket_out =
        expect_one_output(
          own_outputs,
          fn(o) { value.quantity_of(o.value, own_hash, bucket_an) == 1 },
        )

      expect InlineDatum(d_out_any) = bucket_out.datum
      expect d_out: types.SeedDatum = d_out_any
      expect types.RegistryBucket { bucket_id: out_id, entries: entries_out } = d_out
      expect out_id == bucket_id

      let bucket_in_ada = value.lovelace_of(own_input.output.value)
      let bucket_out_ada = value.lovelace_of(bucket_out.value)
      expect bucket_out_ada >= bucket_in_ada

      // Bucket UTxOs should not hold Token A or Token B (or any extra assets beyond the bucket NFT).
      expect is_pure_state_nft(bucket_out.value, params, own_hash, bucket_an)

      expect is_strictly_sorted_unique_pkhs(entries_in)
      expect is_strictly_sorted_unique_pkhs(entries_out)

      // Enforce beneficiary insertion constraints
      expect sorted_contains(beneficiary, entries_in) == False
      expect sorted_contains(beneficiary, entries_out)
      expect is_sorted_subsequence(entries_in, entries_out)
      expect list.length(entries_out) == list.length(entries_in) + 1
      expect list.length(entries_out) <= params.bucket_max_entries
      expect all_in_bucket(params, bucket_id, entries_out)

      // Must mint exactly 1 anchor auth token for beneficiary under this policy
      expect value.quantity_of(tx.mint, own_hash, beneficiary) == 1
      expect dict.to_pairs(value.tokens(tx.mint, own_hash)) == [Pair(beneficiary, 1)]

      // Must create exactly one Anchor output at this script address holding the auth token
      let ao =
        expect_one_output(
          own_outputs,
          fn(o) { value.quantity_of(o.value, own_hash, beneficiary) == 1 },
        )

      expect InlineDatum(anchor_d_any) = ao.datum
      expect anchor_d: types.SeedDatum = anchor_d_any
      expect types.Anchor { beneficiary: out_ben, remaining_b, initial_remaining_b: out_initial } = anchor_d
      expect out_ben == beneficiary
      expect remaining_b == initial_remaining_b
      expect out_initial == initial_remaining_b

      // Anchor UTxOs should not hold Token A or Token B (or any extra assets beyond the auth token).
      expect is_pure_state_nft(ao.value, params, own_hash, beneficiary)

      // Merkle proof must validate
      expect verify_anchor_leaf(params.anchors_root, beneficiary, initial_remaining_b, merkle_proof)

      True
    }

    types.Drain -> {
      expect now_lb_ms >= end_time_ms(params)
      expect list.is_empty(own_outputs)

      let total_in_script =
        own_inputs
          |> list.foldl(value.zero, fn(i, acc) {
            value.merge(acc, i.output.value)
          })

      // Enforce: all lovelace from script inputs is paid to vault.
      expect value.lovelace_of(paid_to_vault) == value.lovelace_of(total_in_script)

      // Enforce: all non-seed-policy assets from script inputs are paid to vault.
      // Seed-policy assets (own_hash) may be burned via SeedBurnAny.
      let non_seed_assets =
        value.flatten_with(total_in_script, fn(pid, an, qty) {
          if pid == own_hash {
            None
          } else {
            Some((pid, an, qty))
          }
        })

      list.all(non_seed_assets, fn(t) {
        let (pid, an, qty) = t
        value.quantity_of(paid_to_vault, pid, an) == qty
      })
    }
  }
}

validator seed(params: types.SeedParams) {
  mint(r: types.SeedMintRedeemer, own_policy: PolicyId, tx: Transaction) {
    when r is {
      types.SeedInitPool { .. } -> validate_mint_init(params, own_policy, r, tx)
      types.SeedInitAnchors { .. } -> validate_mint_init(params, own_policy, r, tx)
      types.SeedBurn -> validate_mint_burn(params, own_policy, tx)
      types.SeedBurnAnchor { beneficiary } -> validate_mint_burn_anchor(params, own_policy, beneficiary, tx)
      types.SeedBurnAnchors { beneficiaries } -> validate_mint_burn_anchors(params, own_policy, beneficiaries, tx)
      types.SeedBurnAny -> validate_mint_burn_any(params, own_policy, tx)
    }
  }

  spend(
    datum_opt: Option<types.SeedDatum>,
    red: types.SeedRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(datum) = datum_opt
    validate(params, datum, red, own_ref, tx)
  }

  else(_) {
    fail
  }
}

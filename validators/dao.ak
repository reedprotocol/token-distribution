use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{Blake2b_224, Hash, VerificationKey, blake2b_256}
use cardano/address.{Address, Credential}
use cardano/assets.{AssetName, PolicyId}
use cardano/assets as assets_mod
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction, find_input}

use token_distribution/types as types

fn unique_token_name(out_ref: OutputReference) -> AssetName {
  blake2b_256(cbor.serialise(out_ref))
}

fn dao_token_name(out_ref: OutputReference) -> AssetName {
  unique_token_name(out_ref)
}

fn has_enough_signers(
  all_signers: List<Hash<Blake2b_224, VerificationKey>>,
  threshold: Int,
  actual_signers: List<Hash<Blake2b_224, VerificationKey>>,
) -> Bool {
  list.length(
    list.filter(all_signers, fn(s) { list.has(actual_signers, s) }),
  ) >= threshold
}

fn signed_within_threshold(
  datum: types.DaoDatum,
  extra_signatories: List<Hash<Blake2b_224, VerificationKey>>,
) -> Bool {
  has_enough_signers(datum.signers, datum.threshold, extra_signatories)
}

fn all_unique(signers: List<Hash<Blake2b_224, VerificationKey>>) -> Bool {
  when signers is {
    [] -> True
    [head, ..tail] -> !list.has(tail, head) && all_unique(tail)
  }
}

fn validate_datum(d: types.DaoDatum) -> Bool {
  let n = list.length(d.signers)
  d.threshold > 0 && d.threshold <= n && n <= 20 && all_unique(d.signers)
}

fn validate_init(
  seed_out_ref: OutputReference,
  own_policy: PolicyId,
  r: types.DaoMintRedeemer,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, extra_signatories, .. } = tx

  when r is {
    types.DaoInit { input_index, output_index } -> {
      expect Some(Input { output_reference: input_out_ref, .. }) =
        list.at(inputs, input_index)

      let seed_input_ok = input_out_ref == seed_out_ref

      expect Some(Output {
        address: output_address,
        datum: InlineDatum(output_datum),
        value: output_value,
        ..
      }) = list.at(outputs, output_index)

      let expected_addr =
        Address { payment_credential: Credential.Script(own_policy), stake_credential: None }
      let address_correct = output_address == expected_addr

      let tn = dao_token_name(seed_out_ref)

      let minted_correct =
        assets_mod.quantity_of(tx.mint, own_policy, tn) == 1

      let minted_pairs = dict.to_pairs(assets_mod.tokens(tx.mint, own_policy))
      let minted_ok = minted_pairs == [Pair(tn, 1)]

      let output_has_token =
        assets_mod.quantity_of(output_value, own_policy, tn) == 1

      expect dao_datum: types.DaoDatum = output_datum
      let datum_ok = validate_datum(dao_datum)
      let signed_ok = signed_within_threshold(dao_datum, extra_signatories)

      seed_input_ok && address_correct && minted_correct && minted_ok && output_has_token && datum_ok && signed_ok
    }
    _ -> False
  }
}

fn validate_end(seed_out_ref: OutputReference, own_policy: PolicyId, tx: Transaction) -> Bool {
  let tn = dao_token_name(seed_out_ref)
  dict.to_pairs(assets_mod.tokens(tx.mint, own_policy)) == [Pair(tn, -1)]
}

fn state_input(tx: Transaction, own_policy: PolicyId) -> (Input, AssetName) {
  let state_candidates =
    list.filter(tx.inputs, fn(i) {
      if i.output.address.payment_credential == Credential.Script(own_policy) {
        let in_tokens = assets_mod.tokens(i.output.value, own_policy)
        when dict.to_pairs(in_tokens) is {
          [Pair(_, 1)] -> True
          _ -> False
        }
      } else {
        False
      }
    })

  expect list.length(state_candidates) == 1
  expect [st_in] = state_candidates

  let in_tokens = assets_mod.tokens(st_in.output.value, own_policy)
  expect [Pair(tn, 1)] = dict.to_pairs(in_tokens)
  (st_in, tn)
}

fn validate_sign(
  datum_opt: Option<types.DaoDatum>,
  own_ref: OutputReference,
  r: types.DaoSpendRedeemer,
  tx: Transaction,
) -> Bool {
  expect Some(own_input) =
    tx.inputs |> find_input(own_ref)

  expect Credential.Script(own_policy) =
    own_input.output.address.payment_credential

  let (st_in, tn) = state_input(tx, own_policy)
  expect InlineDatum(st_datum_any) = st_in.output.datum
  expect st_datum: types.DaoDatum = st_datum_any

  let own_is_state = own_ref == st_in.output_reference

  let spend_datum_ok =
    if own_is_state {
      when datum_opt is {
        Some(d) -> d == st_datum
        None -> False
      }
    } else {
      True
    }

  let in_has_token =
    assets_mod.quantity_of(own_input.output.value, own_policy, tn) == 1

  expect if own_is_state { in_has_token } else { !in_has_token }

  let datum_ok = validate_datum(st_datum)
  let enough_signers = signed_within_threshold(st_datum, tx.extra_signatories)

  when r is {
    types.Sign { output_index } -> {
      expect Some(own_output) = list.at(tx.outputs, output_index)
      expect InlineDatum(out_datum) = own_output.datum
      expect out_dao_datum: types.DaoDatum = out_datum

      let continuing_candidates =
        list.filter(
          tx.outputs,
          fn(o) {
            o.address == own_input.output.address &&
              assets_mod.quantity_of(o.value, own_policy, tn) == 1
          },
        )

      expect [only_candidate] = continuing_candidates
      let output_index_ok = own_output == only_candidate

      let out_address_ok = own_output.address == st_in.output.address
      let out_datum_ok = out_dao_datum == st_datum

      let out_has_token =
        assets_mod.quantity_of(own_output.value, own_policy, tn) == 1

      let in_without_ada = assets_mod.without_lovelace(st_in.output.value)
      let out_without_ada = assets_mod.without_lovelace(own_output.value)
      let value_unchanged = out_without_ada == in_without_ada

      if own_is_state {
        datum_ok && enough_signers && output_index_ok && out_address_ok && out_datum_ok && spend_datum_ok && in_has_token && out_has_token && value_unchanged
      } else {
        datum_ok && enough_signers && output_index_ok && out_address_ok && out_datum_ok && spend_datum_ok && out_has_token && value_unchanged
      }
    }

    types.Update { output_index } -> {
      expect own_is_state
      expect Some(own_output) = list.at(tx.outputs, output_index)
      expect InlineDatum(out_datum) = own_output.datum
      expect updated: types.DaoDatum = out_datum

      let continuing_candidates =
        list.filter(
          tx.outputs,
          fn(o) {
            o.address == own_input.output.address &&
              assets_mod.quantity_of(o.value, own_policy, tn) == 1
          },
        )

      expect [only_candidate] = continuing_candidates
      let output_index_ok = own_output == only_candidate

      let out_address_ok = own_output.address == st_in.output.address

      let out_datum_ok =
        validate_datum(updated)

      let out_has_token =
        assets_mod.quantity_of(own_output.value, own_policy, tn) == 1

      let in_without_ada =
        assets_mod.without_lovelace(st_in.output.value)

      let out_without_ada =
        assets_mod.without_lovelace(own_output.value)

      let value_unchanged =
        out_without_ada == in_without_ada

      datum_ok && enough_signers && output_index_ok && out_address_ok && out_datum_ok && spend_datum_ok && in_has_token && out_has_token && value_unchanged
    }

    types.Remove -> {
      expect own_is_state
      let burned =
        assets_mod.quantity_of(tx.mint, own_policy, tn) == -1

      let no_script_outputs =
        list.all(
          tx.outputs,
          fn(o) {
            o.address.payment_credential != Credential.Script(own_policy)
          },
        )

      datum_ok && enough_signers && spend_datum_ok && in_has_token && burned && no_script_outputs
    }
  }
}

validator dao(seed_out_ref: OutputReference) {
  mint(r: types.DaoMintRedeemer, own_policy: PolicyId, tx: Transaction) {
    when r is {
      types.DaoInit { .. } -> validate_init(seed_out_ref, own_policy, r, tx)
      types.DaoEnd -> validate_end(seed_out_ref, own_policy, tx)
    }
  }

  spend(
    datum_opt: Option<types.DaoDatum>,
    redeemer: types.DaoSpendRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    validate_sign(datum_opt, own_ref, redeemer, tx)
  }

  else(_) {
    fail
  }
}

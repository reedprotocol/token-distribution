use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto
use cardano/address.{Address, Credential}
use cardano/assets.{AssetName, PolicyId}
use cardano/assets as assets_mod
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction, find_input}

use token_distribution/types as types
use token_distribution/utils

fn unique_token_name(out_ref: OutputReference) -> AssetName {
  crypto.blake2b_256(cbor.serialise(out_ref))
}

fn vault_token_name(out_ref: OutputReference) -> AssetName {
  unique_token_name(out_ref)
}

fn controller_token_present(inputs: List<Input>, controller: types.DaoController) -> Bool {
  let (policy_id, asset_name) =
    when controller is {
      types.DaoControllerToken { policy_id, asset_name } -> (policy_id, asset_name)
      types.ExternalController { policy_id, asset_name } -> (policy_id, asset_name)
    }

  let total =
    list.foldl(inputs, 0, fn(i, acc) {
      acc + assets_mod.quantity_of(i.output.value, policy_id, asset_name)
    })

  total == 1
}

fn controller_token_cred(inputs: List<Input>, controller: types.DaoController) -> Credential {
  let (policy_id, asset_name) =
    when controller is {
      types.DaoControllerToken { policy_id, asset_name } -> (policy_id, asset_name)
      types.ExternalController { policy_id, asset_name } -> (policy_id, asset_name)
    }

  let (count, controller_in_opt) =
    list.foldl(
      inputs,
      (0, None),
      fn(i, acc) {
        let (c, found) = acc
        if assets_mod.quantity_of(i.output.value, policy_id, asset_name) == 1 {
          (c + 1, Some(i))
        } else {
          (c, found)
        }
      },
    )

  expect count == 1
  expect Some(controller_in) = controller_in_opt
  controller_in.output.address.payment_credential
}

fn state_token_name_and_policy(own_input: Input) -> (PolicyId, AssetName) {
  expect Credential.Script(own_policy) = own_input.output.address.payment_credential
  let in_tokens = assets_mod.tokens(own_input.output.value, own_policy)
  expect [Pair(tn, 1)] = dict.to_pairs(in_tokens)
  (own_policy, tn)
}

fn continuing_state_output(
  tx: Transaction,
  own_policy: PolicyId,
  token_name: AssetName,
) -> Output {
  let (count, out_opt) =
    list.foldl(
      tx.outputs,
      (0, None),
      fn(o, acc) {
        let (c, found) = acc
        if o.address.payment_credential == Credential.Script(own_policy) &&
          assets_mod.quantity_of(o.value, own_policy, token_name) == 1 {
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

fn validate_mint_init(
  seed_out_ref: OutputReference,
  own_policy: PolicyId,
  r: types.VaultMintRedeemer,
  tx: Transaction,
) -> Bool {
  let Transaction { inputs, outputs, mint, .. } = tx

  when r is {
    types.VaultInit { input_index, output_index } -> {
      expect Some(Input { output_reference: input_out_ref, .. }) = list.at(inputs, input_index)

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

      let tn = vault_token_name(seed_out_ref)
      let minted_correct = assets_mod.quantity_of(mint, own_policy, tn) == 1
      let output_has_token = assets_mod.quantity_of(output_value, own_policy, tn) == 1

      let minted_pairs = dict.to_pairs(assets_mod.tokens(mint, own_policy))
      let minted_ok = minted_pairs == [Pair(tn, 1)]

      expect _datum: types.VaultDatum = output_datum

      seed_input_ok && address_correct && minted_correct && output_has_token && minted_ok
    }
    _ -> False
  }
}

fn validate_mint_end(seed_out_ref: OutputReference, own_policy: PolicyId, tx: Transaction) -> Bool {
  let tn = vault_token_name(seed_out_ref)
  dict.to_pairs(assets_mod.tokens(tx.mint, own_policy)) == [Pair(tn, -1)]
}

fn validate_collect_stray(
  datum_opt: Option<Data>,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  expect Some(own_input) = tx.inputs |> find_input(own_ref)
  expect Credential.Script(own_policy) = own_input.output.address.payment_credential

  let script_inputs =
    list.filter(tx.inputs, fn(i) { i.output.address.payment_credential == Credential.Script(own_policy) })

  let (state_count, state_in_opt) =
    list.foldl(
      script_inputs,
      (0, None),
      fn(i, acc) {
        let (c, found) = acc
        let in_tokens = assets_mod.tokens(i.output.value, own_policy)
        let is_state =
          when dict.to_pairs(in_tokens) is {
            [Pair(_, 1)] -> True
            _ -> False
          }
        if is_state {
          (c + 1, Some(i))
        } else {
          (c, found)
        }
      },
    )

  expect state_count == 1
  expect Some(state_in) = state_in_opt
  let (policy, tn) = state_token_name_and_policy(state_in)

  expect InlineDatum(st_datum_any) = state_in.output.datum
  expect st_datum: types.VaultDatum = st_datum_any

  let out = continuing_state_output(tx, policy, tn)
  let address_ok = out.address == state_in.output.address
  expect InlineDatum(out_datum_any) = out.datum
  expect out_datum: types.VaultDatum = out_datum_any

  let controller_ok = controller_token_present(tx.inputs, st_datum.controller)
  let datum_ok = out_datum == st_datum

  let no_mint_or_burn = assets_mod.quantity_of(tx.mint, policy, tn) == 0

  let in_total =
    list.foldl(script_inputs, assets_mod.zero, fn(i, acc) { assets_mod.merge(acc, i.output.value) })
  let value_ok = out.value == in_total

  let own_is_state = own_ref == state_in.output_reference
  let own_datum_ok =
    if own_is_state {
      when datum_opt is {
        Some(d_any) -> {
          expect d: types.VaultDatum = d_any
          d == st_datum
        }
        None -> False
      }
    } else {
      datum_opt == None
    }

  let stray_inputs_have_no_inline_datum =
    list.all(script_inputs, fn(i) {
      if i.output_reference == state_in.output_reference {
        True
      } else {
        when i.output.datum is {
          InlineDatum(_) -> False
          _ -> True
        }
      }
    })

  controller_ok && datum_ok && no_mint_or_burn && value_ok && own_datum_ok && stray_inputs_have_no_inline_datum && address_ok
}

fn validate_spend(
  datum: types.VaultDatum,
  redeemer: types.VaultRedeemer,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  expect Some(own_input) = tx.inputs |> find_input(own_ref)
  let (own_policy, tn) = state_token_name_and_policy(own_input)

  let controller_ok = controller_token_present(tx.inputs, datum.controller)

  when redeemer is {
    types.VaultWithdraw -> {
      let out = continuing_state_output(tx, own_policy, tn)
      let address_ok = out.address == own_input.output.address
      expect InlineDatum(out_datum) = out.datum
      expect out_state: types.VaultDatum = out_datum

      let datum_ok = out_state == datum

      let controller_cred = controller_token_cred(tx.inputs, datum.controller)
      let paid_to_controller = utils.paid_to_cred(tx.outputs, controller_cred)
      let in_total =
        list.foldl(
          list.filter(tx.inputs, fn(i) { i.output.address.payment_credential == Credential.Script(own_policy) }),
          assets_mod.zero,
          fn(i, acc) { assets_mod.merge(acc, i.output.value) },
        )

      let out_state_value = out.value
      let expected_paid =
        assets_mod.merge(in_total, assets_mod.negate(out_state_value))

      let required_paid =
        expected_paid
          |> assets_mod.flatten
          |> list.filter(fn(t) {
            let (_, _, q) = t
            q > 0
          })
          |> list.foldl(assets_mod.zero, fn(t, acc) {
            let (pid, an, q) = t
            assets_mod.add(acc, pid, an, q)
          })

      controller_ok && datum_ok && address_ok && utils.value_geq(paid_to_controller, required_paid)
    }

    types.UpdateController { new_controller } -> {
      let out = continuing_state_output(tx, own_policy, tn)
      let address_ok = out.address == own_input.output.address
      expect InlineDatum(out_datum) = out.datum
      expect out_state: types.VaultDatum = out_datum

      let datum_ok = out_state.controller == new_controller

      let in_without_ada =
        assets_mod.without_lovelace(own_input.output.value)

      let out_without_ada =
        assets_mod.without_lovelace(out.value)

      let value_unchanged =
        out_without_ada == in_without_ada

      let no_other_proxy_inputs =
        list.all(tx.inputs, fn(i) {
          if i.output.address.payment_credential == Credential.Script(own_policy) {
            i.output_reference == own_ref
          } else {
            True
          }
        })

      controller_ok && datum_ok && value_unchanged && no_other_proxy_inputs && address_ok
    }

    types.Close -> {
      let burned = assets_mod.quantity_of(tx.mint, own_policy, tn) == -1

      let no_script_outputs =
        list.all(tx.outputs, fn(o) { o.address.payment_credential != Credential.Script(own_policy) })

      controller_ok && burned && no_script_outputs
    }

    types.CollectStray -> {
      validate_collect_stray(None, own_ref, tx)
    }
  }
}

validator vault(seed_out_ref: OutputReference) {
  mint(r: types.VaultMintRedeemer, own_policy: PolicyId, tx: Transaction) {
    when r is {
      types.VaultInit { .. } -> validate_mint_init(seed_out_ref, own_policy, r, tx)
      types.VaultEnd -> validate_mint_end(seed_out_ref, own_policy, tx)
    }
  }

  spend(
    datum_opt: Option<Data>,
    redeemer: types.VaultRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    when redeemer is {
      types.CollectStray -> validate_collect_stray(datum_opt, own_ref, tx)
      _ -> {
        expect Some(datum_any) = datum_opt
        expect datum: types.VaultDatum = datum_any
        validate_spend(datum, redeemer, own_ref, tx)
      }
    }
  }

  else(_) {
    fail
  }
}

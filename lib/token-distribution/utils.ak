use aiken/collection/list as list
use aiken/interval.{Finite}
use cardano/address.{Credential}
use cardano/assets as value
use cardano/transaction.{Output, Transaction}

pub fn tx_lower_bound_ms(tx: Transaction) -> Int {
  when tx.validity_range.lower_bound.bound_type is {
    Finite(lb) -> lb
    _ -> fail @"Expected finite lower validity bound"
  }
}

pub fn tx_upper_bound_ms(tx: Transaction) -> Int {
  when tx.validity_range.upper_bound.bound_type is {
    Finite(ub) -> ub
    _ -> fail @"Expected finite upper validity bound"
  }
}

pub fn paid_to_cred(outs: List<Output>, cred) -> value.Value {
  outs
    |> list.filter(fn(o) { o.address.payment_credential == cred })
    |> list.foldl(value.zero, fn(o, acc) { value.merge(acc, o.value) })
}

pub fn paid_to_pkh(outs: List<Output>, pkh) -> value.Value {
  paid_to_cred(outs, Credential.VerificationKey(pkh))
}

pub fn value_geq(a: value.Value, b: value.Value) -> Bool {
  list.all(
    value.flatten(b),
    fn(t) {
      let (pid, an, q) = t
      value.quantity_of(a, pid, an) >= q
    },
  )
}

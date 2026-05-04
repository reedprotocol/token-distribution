use aiken/crypto.{Blake2b_224, Hash, VerificationKey}
use cardano/address.{Credential}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{OutputReference}

pub type TeamVestingParams {
  policy_id: PolicyId,
  asset_name: AssetName,
  beneficiary: Hash<Blake2b_224, VerificationKey>,
  min_ada: Int,
  cliff_ms: Int,
  duration_ms: Int,
}

pub type SeedParams {
  token_a_policy_id: PolicyId,
  token_a_asset_name: AssetName,
  token_b_policy_id: PolicyId,
  token_b_asset_name: AssetName,
  vault_cred: Credential,
  start_time_ms: Int,
  duration_ms: Int,
  initial_unlock_bps: Int,
  y: Int,
  anchors_root: ByteArray,
  bucket_count: Int,
  bucket_max_entries: Int,
  seed_out_ref: OutputReference,
  pool_nft_asset_name: AssetName,
}

pub type LpToken {
  policy_id: PolicyId,
  asset_name: AssetName,
}

pub type WeightedLpToken {
  policy_id: PolicyId,
  asset_name: AssetName,
  weight: Int,
}

pub type ParticipationEpoch {
  start_time_ms: Int,
  pools: List<WeightedLpToken>,
}

pub type ParticipationConfigDatum {
  epochs: List<ParticipationEpoch>,
}

pub type ParticipationParams {
  token_a_policy_id: PolicyId,
  token_a_asset_name: AssetName,
  vault_cred: Credential,
  start_time_ms: Int,
  duration_ms: Int,
  emission_per_ms: Int,
  sweep_grace_ms: Int,
  seed_whitelist_root: ByteArray,
  config_nft_policy_id: PolicyId,
  config_nft_asset_name: AssetName,
  min_ada_distribution: Int,
  min_ada_pair_state: Int,
  min_ada_user_stake: Int,
}

pub type TeamVestingDatum {
  start_time_ms: Int,
  total_amount: Int,
  claimed_amount: Int,
}

pub type SeedDatum {
  Pool { distributed_a: Int }
  Anchor {
    beneficiary: Hash<Blake2b_224, VerificationKey>,
    remaining_b: Int,
    initial_remaining_b: Int,
  }
  RegistryBucket {
    bucket_id: Int,
    entries: List<Hash<Blake2b_224, VerificationKey>>,
  }
}

pub type ParticipationDatum {
  Distribution { distributed_a: Int, initial_total_a: Int }
  PairState {
    lp_policy_id: PolicyId,
    lp_asset_name: AssetName,
    total_staked_lp: Int,
    acc_reward_per_lp: Int,
    last_update_ms: Int,
  }
  UserStake {
    beneficiary: Hash<Blake2b_224, VerificationKey>,
    lp_policy_id: PolicyId,
    lp_asset_name: AssetName,
    staked_lp: Int,
    reward_debt: Int,
  }
}

pub type TeamVestingRedeemer {
  Withdraw { amount: Int }
}

pub type SeedRedeemer {
  Swap { b_in: Int }
  FlushB
  Sweep
  SweepAnchor
  UpdateBucketForAnchor {
    beneficiary: Hash<Blake2b_224, VerificationKey>,
    initial_remaining_b: Int,
    merkle_proof: List<ByteArray>,
  }
  Drain
}

pub type SeedAnchorMint {
  beneficiary: Hash<Blake2b_224, VerificationKey>,
  initial_remaining_b: Int,
  merkle_proof: List<ByteArray>,
}

pub type SeedMintRedeemer {
  SeedInitPool {
    pool_output_index: Int,
    registry_output_start_index: Int,
  }
  SeedInitAnchors {
    pool_output_index: Int,
    anchors: List<SeedAnchorMint>,
  }
  SeedBurn
  SeedBurnAnchor { beneficiary: Hash<Blake2b_224, VerificationKey> }
  SeedBurnAnchors { beneficiaries: List<Hash<Blake2b_224, VerificationKey>> }
  SeedBurnAny
}

pub type ParticipationRedeemer {
  Stake {
    lp_policy_id: PolicyId,
    lp_asset_name: AssetName,
    lp_amount: Int,
    merkle_proof: List<ByteArray>,
  }
  Unstake {
    lp_policy_id: PolicyId,
    lp_asset_name: AssetName,
    lp_amount: Int,
    merkle_proof: List<ByteArray>,
  }
  Claim {
    lp_policy_id: PolicyId,
    lp_asset_name: AssetName,
    merkle_proof: List<ByteArray>,
  }
  SweepParticipation
  SweepDistribution
  SweepPairState {
    lp_policy_id: PolicyId,
    lp_asset_name: AssetName,
  }
}

pub type DaoDatum {
  signers: List<Hash<Blake2b_224, VerificationKey>>,
  threshold: Int,
}

pub type DaoMintRedeemer {
  DaoInit { input_index: Int, output_index: Int }
  DaoEnd
}

pub type DaoSpendRedeemer {
  Sign { output_index: Int }
  Update { output_index: Int }
  Remove
}

pub type DaoController {
  DaoControllerToken {
    policy_id: PolicyId,
    asset_name: AssetName,
  }
  ExternalController {
    policy_id: PolicyId,
    asset_name: AssetName,
  }
}

pub type VaultDatum {
  controller: DaoController,
}

pub type VaultMintRedeemer {
  VaultInit { input_index: Int, output_index: Int }
  VaultEnd
}

pub type VaultRedeemer {
  VaultWithdraw
  UpdateController { new_controller: DaoController }
  Close
  CollectStray
}

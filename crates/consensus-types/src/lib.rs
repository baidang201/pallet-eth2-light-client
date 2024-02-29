// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use bitvec::{order::Lsb0, prelude::BitVec};
use eth_types::{
	eth2::{DomainType, Epoch, ForkData, ForkVersion, PublicKeyBytes, SigningData, Slot},
	H256,
};
use tree_hash::TreeHash;

pub mod network_config;

pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;
pub const MIN_SYNC_COMMITTEE_PARTICIPANTS: u64 = 1;
pub const SLOTS_PER_EPOCH: u64 = 32;
pub const DOMAIN_SYNC_COMMITTEE: DomainType = [0x07, 0x00, 0x00, 0x00];

pub const FINALIZED_ROOT_INDEX: u32 = 105;
pub const NEXT_SYNC_COMMITTEE_INDEX: u32 = 55;
pub const FINALITY_TREE_DEPTH: u32 = floorlog2(FINALIZED_ROOT_INDEX);
pub const FINALITY_TREE_INDEX: u32 = get_subtree_index(FINALIZED_ROOT_INDEX);
pub const SYNC_COMMITTEE_TREE_DEPTH: u32 = floorlog2(NEXT_SYNC_COMMITTEE_INDEX);
pub const SYNC_COMMITTEE_TREE_INDEX: u32 = get_subtree_index(NEXT_SYNC_COMMITTEE_INDEX);

pub const BEACON_BLOCK_BODY_TREE_DEPTH: usize = 4;
pub const L1_BEACON_BLOCK_BODY_TREE_EXECUTION_PAYLOAD_INDEX: usize = 9;
pub const L2_EXECUTION_PAYLOAD_TREE_EXECUTION_BLOCK_INDEX: usize = 12;
pub const L1_BEACON_BLOCK_BODY_PROOF_SIZE: usize = 4;
pub const L2_EXECUTION_PAYLOAD_PROOF_SIZE: usize = 4;
pub const EXECUTION_PROOF_SIZE: usize =
	L1_BEACON_BLOCK_BODY_PROOF_SIZE + L2_EXECUTION_PAYLOAD_PROOF_SIZE;

pub const fn compute_epoch_at_slot(slot: Slot) -> u64 {
	slot / SLOTS_PER_EPOCH
}

pub const fn compute_sync_committee_period(slot: Slot) -> u64 {
	compute_epoch_at_slot(slot) / EPOCHS_PER_SYNC_COMMITTEE_PERIOD
}

pub fn compute_fork_version(
	epoch: Epoch,
	bellatrix_epoch: Epoch,
	fork_version: ForkVersion,
) -> Option<ForkVersion> {
	if epoch >= bellatrix_epoch {
		return Some(fork_version)
	}

	None
}

pub fn compute_fork_version_by_slot(
	slot: Slot,
	bellatrix_epoch: Epoch,
	bellatrix_version: ForkVersion,
) -> Option<ForkVersion> {
	compute_fork_version(compute_epoch_at_slot(slot), bellatrix_epoch, bellatrix_version)
}

// Compute floor of log2 of a u32.
pub const fn floorlog2(x: u32) -> u32 {
	if x == 0 {
		return 0
	}
	31 - x.leading_zeros()
}

pub const fn get_subtree_index(generalized_index: u32) -> u32 {
	generalized_index % 2u32.pow(floorlog2(generalized_index))
}

pub fn compute_domain(
	domain_constant: DomainType,
	fork_version: ForkVersion,
	genesis_validators_root: H256,
) -> H256 {
	let fork_data_root =
		ForkData { current_version: fork_version, genesis_validators_root }.tree_hash_root();

	let mut domain = [0; 32];
	domain[0..4].copy_from_slice(&domain_constant);
	domain[4..].copy_from_slice(
		fork_data_root
			.as_bytes()
			.get(..28)
			.expect("fork has is 32 bytes so first 28 bytes should exist"),
	);

	H256::from(domain)
}

pub fn compute_signing_root(object_root: H256, domain: H256) -> H256 {
	H256(SigningData { object_root, domain }.tree_hash_root())
}

pub fn get_participant_pubkeys(
	public_keys: &[PublicKeyBytes],
	sync_committee_bits: &BitVec<u8, Lsb0>,
) -> Vec<PublicKeyBytes> {
	let mut result: Vec<PublicKeyBytes> = vec![];
	for (idx, bit) in sync_committee_bits.iter().by_vals().enumerate() {
		if bit {
			result.push(public_keys[idx].clone());
		}
	}
	result
}

/// Verify a proof that `leaf` exists at `index` in a Merkle tree rooted at `root`.
///
/// The `branch` argument is the main component of the proof: it should be a list of internal
/// node hashes such that the root can be reconstructed (in bottom-up order).
pub fn verify_merkle_proof(
	leaf: H256,
	branch: &[H256],
	depth: usize,
	index: usize,
	root: H256,
) -> bool {
	if branch.len() == depth {
		merkle_root_from_branch(leaf, branch, depth, index) == root
	} else {
		false
	}
}

/// Compute a root hash from a leaf and a Merkle proof.
pub fn merkle_root_from_branch(leaf: H256, branch: &[H256], depth: usize, index: usize) -> H256 {
	assert_eq!(branch.len(), depth, "proof length should equal depth");

	let mut merkle_root = leaf.0.as_bytes().to_vec();

	for (i, leaf) in branch.iter().enumerate().take(depth) {
		let ith_bit = (index >> i) & 0x01;
		if ith_bit == 1 {
			merkle_root = eth2_hashing::hash32_concat(leaf.0.as_bytes(), &merkle_root)[..].to_vec();
		} else {
			let mut input = merkle_root;
			input.extend_from_slice(leaf.0.as_bytes());
			merkle_root = eth2_hashing::hash(&input);
		}
	}

	H256(ethereum_types::H256::from_slice(&merkle_root))
}

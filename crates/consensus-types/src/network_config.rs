use crate::compute_epoch_at_slot;
use alloc::string::String;
use codec::{Decode, Encode};
use core::str::FromStr;
use eth_types::eth2::{Epoch, ForkVersion, Slot};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Encode, Decode, scale_info::TypeInfo, Serialize, Deserialize)]
pub enum Network {
	Mainnet,
	Goerli,
	Sepolia,
}

impl FromStr for Network {
	type Err = String;
	fn from_str(input: &str) -> Result<Network, Self::Err> {
		match input.to_lowercase().as_str() {
			"mainnet" => Ok(Network::Mainnet),
			"goerli" => Ok(Network::Goerli),
			"sepolia" => Ok(Network::Sepolia),
			_ => Err(alloc::format!("Unknown network: {input}")),
		}
	}
}

#[derive(Clone, Debug, PartialEq, Encode, Decode, scale_info::TypeInfo, Serialize, Deserialize)]
pub struct NetworkConfig {
	pub genesis_validators_root: [u8; 32],
	pub bellatrix_fork_version: ForkVersion,
	pub bellatrix_fork_epoch: u64,
	pub capella_fork_version: ForkVersion,
	pub capella_fork_epoch: u64,
	pub deneb_fork_version: ForkVersion,
	pub deneb_fork_epoch: u64,
}

impl NetworkConfig {
	pub fn new(network: &Network) -> Self {
		match network {
			Network::Mainnet => Self {
				genesis_validators_root: [
					0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34,
					0x0f, 0xdd, 0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a,
					0xd2, 0x7f, 0x51, 0x1b, 0xfe, 0x95,
				],
				bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
				bellatrix_fork_epoch: 144896,
				capella_fork_version: [0x03, 0x00, 0x00, 0x00],
				capella_fork_epoch: 194048,
				deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
				deneb_fork_epoch: 269568,
			},
			Network::Goerli => Self {
				genesis_validators_root: [
					0x04, 0x3d, 0xb0, 0xd9, 0xa8, 0x38, 0x13, 0x55, 0x1e, 0xe2, 0xf3, 0x34, 0x50,
					0xd2, 0x37, 0x97, 0x75, 0x7d, 0x43, 0x09, 0x11, 0xa9, 0x32, 0x05, 0x30, 0xad,
					0x8a, 0x0e, 0xab, 0xc4, 0x3e, 0xfb,
				],
				bellatrix_fork_version: [0x02, 0x00, 0x10, 0x20],
				bellatrix_fork_epoch: 112260,
				capella_fork_version: [0x03, 0x00, 0x10, 0x20],
				capella_fork_epoch: 162304,
				deneb_fork_version: [0x04, 0x00, 0x10, 0x20],
				deneb_fork_epoch: 231680,
			},
			Network::Sepolia => Self {
				genesis_validators_root: [
					0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed,
					0x61, 0x05, 0x2a, 0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd,
					0xac, 0x09, 0xed, 0x9b, 0x80, 0x78,
				],
				bellatrix_fork_version: [144, 0, 0, 113],
				bellatrix_fork_epoch: 100,
				capella_fork_version: [144, 0, 0, 114],
				capella_fork_epoch: 56832,
				deneb_fork_version: [144, 0, 0, 115],
				deneb_fork_epoch: 132608,
			},
		}
	}

	pub fn compute_fork_version(&self, epoch: Epoch) -> Option<ForkVersion> {
		if epoch >= self.deneb_fork_epoch {
			return Some(self.deneb_fork_version)
		}

		if epoch >= self.capella_fork_epoch {
			return Some(self.capella_fork_version)
		}

		if epoch >= self.bellatrix_fork_epoch {
			return Some(self.bellatrix_fork_version)
		}

		None
	}

	pub fn compute_fork_version_by_slot(&self, slot: Slot) -> Option<ForkVersion> {
		self.compute_fork_version(compute_epoch_at_slot(slot))
	}
}

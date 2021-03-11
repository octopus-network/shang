// This file is part of Substrate.

// Copyright (C) 2020-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::*;
use crate as example_offchain_worker;
use std::sync::Arc;
use codec::Decode;
use frame_support::parameter_types;
use sp_core::{
	H256,
	offchain::{OffchainExt, TransactionPoolExt, testing},
};

use sp_keystore::{
	{KeystoreExt, SyncCryptoStore},
	testing::KeyStore,
};
use sp_runtime::{
	RuntimeAppPublic, MultiSignature,
	testing::{Header, TestXt},
	traits::{
		BlakeTwo256, IdentityLookup, Extrinsic as ExtrinsicT,
		IdentifyAccount, Verify,
	},
};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

// For testing the module, we construct a mock runtime.
frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Module, Call, Config, Storage, Event<T>},
		Example: example_offchain_worker::{Module, Call, Storage, Event<T>, ValidateUnsigned},
	}
);

type Signature = MultiSignature;
type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub BlockWeights: frame_system::limits::BlockWeights =
		frame_system::limits::BlockWeights::simple_max(1024);
}
impl frame_system::Config for Test {
	type BaseCallFilter = ();
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type Origin = Origin;
	type Call = Call;
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = Event;
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
}

type Extrinsic = TestXt<Call, ()>;

impl frame_system::offchain::SigningTypes for Test {
	type Public = <Signature as Verify>::Signer;
	type Signature = Signature;
}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Test where
	Call: From<LocalCall>,
{
	type OverarchingCall = Call;
	type Extrinsic = Extrinsic;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Test where
	Call: From<LocalCall>,
{
	fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
		call: Call,
		_public: <Signature as Verify>::Signer,
		_account: AccountId,
		nonce: u64,
	) -> Option<(Call, <Extrinsic as ExtrinsicT>::SignaturePayload)> {
		Some((call, (nonce, ())))
	}
}

parameter_types! {
	pub const GracePeriod: u64 = 5;
	pub const UnsignedInterval: u64 = 128;
	pub const UnsignedPriority: u64 = 1 << 20;
}

impl Config for Test {
	type Event = Event;
	type AuthorityId = crypto::TestAuthId;
	type Call = Call;
	type GracePeriod = GracePeriod;
	type UnsignedInterval = UnsignedInterval;
	type UnsignedPriority = UnsignedPriority;
}

fn expected_set() -> Option<ValidatorSet<AccountId>>{
	let ocw_id = hex::decode("306721211d5404bd9da88e0204360a1a9ab8b87c66c1bc2fcdd37f3c2222cc20")
		.map(|b| AccountId::decode(&mut &b[..])).unwrap().unwrap();

	let id = hex::decode("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
		.map(|b| AccountId::decode(&mut &b[..])).unwrap().unwrap();

	let alice = Validator {
		ocw_id: ocw_id,
		id: id,
		weight: 100,
	};

	let ocw_id = hex::decode("e659a7a1628cdd93febc04a4e0646ea20e9f5f0ce097d9a05290d4a9e054df4e")
		.map(|b| AccountId::decode(&mut &b[..])).unwrap().unwrap();

	let id = hex::decode("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48")
		.map(|b| AccountId::decode(&mut &b[..])).unwrap().unwrap();

	let bob = Validator {
		ocw_id: ocw_id,
		id: id,
		weight: 100,
	};
	let expected_set = ValidatorSet {
		appchain_id: 100,
		validator_set_index: 0,
		validators: vec![alice, bob],
	};
	Some(expected_set)
}

#[test]
fn should_make_http_call_and_parse_result() {
	let (offchain, state) = testing::TestOffchainExt::new();
	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainExt::new(offchain));

	validator_set_response(&mut state.write());

	t.execute_with(|| {
		// when
		let set = Example::fetch_validator_set(0).ok();
		// then
		assert_eq!(set, expected_set());
	});
}

fn validator_set_response(state: &mut testing::OffchainState) {
	state.expect_request(testing::PendingRequest {
		method: "POST".into(),
		uri: "https://rpc.testnet.near.org".into(),
		headers: vec![("Content-Type".into(), "application/json".into())],
		body: br#"
		{
			"jsonrpc": "2.0",
			"id": "dontcare",
			"method": "query",
			"params": {
				"request_type": "call_function",
				"finality": "final",
				"account_id": "yuanchao.testnet",
				"method_name": "get",
				"args_base64": "eyJpbmRleCI6MH0="
			}
		}"#.to_vec(),
		response: Some(br#"
			{
				"jsonrpc": "2.0",
				"result": {
					"result": [
						123, 34, 97, 112, 112, 99, 104, 97, 105, 110, 95, 105, 100, 34, 58, 49, 48, 48, 44, 34, 118, 97, 108, 105, 100, 97, 116, 111, 114, 95, 115, 101, 116, 95, 105, 110, 100, 101, 120, 34, 58, 48, 44, 34, 118, 97, 108, 105, 100, 97, 116, 111, 114, 115, 34, 58, 91, 123, 34, 111, 99, 119, 95, 105, 100, 34, 58, 34, 48, 120, 51, 48, 54, 55, 50, 49, 50, 49, 49, 100, 53, 52, 48, 52, 98, 100, 57, 100, 97, 56, 56, 101, 48, 50, 48, 52, 51, 54, 48, 97, 49, 97, 57, 97, 98, 56, 98, 56, 55, 99, 54, 54, 99, 49, 98, 99, 50, 102, 99, 100, 100, 51, 55, 102, 51, 99, 50, 50, 50, 50, 99, 99, 50, 48, 34, 44, 34, 105, 100, 34, 58, 34, 48, 120, 100, 52, 51, 53, 57, 51, 99, 55, 49, 53, 102, 100, 100, 51, 49, 99, 54, 49, 49, 52, 49, 97, 98, 100, 48, 52, 97, 57, 57, 102, 100, 54, 56, 50, 50, 99, 56, 53, 53, 56, 56, 53, 52, 99, 99, 100, 101, 51, 57, 97, 53, 54, 56, 52, 101, 55, 97, 53, 54, 100, 97, 50, 55, 100, 34, 44, 34, 119, 101, 105, 103, 104, 116, 34, 58, 49, 48, 48, 125, 44, 123, 34, 111, 99, 119, 95, 105, 100, 34, 58, 34, 48, 120, 101, 54, 53, 57, 97, 55, 97, 49, 54, 50, 56, 99, 100, 100, 57, 51, 102, 101, 98, 99, 48, 52, 97, 52, 101, 48, 54, 52, 54, 101, 97, 50, 48, 101, 57, 102, 53, 102, 48, 99, 101, 48, 57, 55, 100, 57, 97, 48, 53, 50, 57, 48, 100, 52, 97, 57, 101, 48, 53, 52, 100, 102, 52, 101, 34, 44, 34, 105, 100, 34, 58, 34, 48, 120, 56, 101, 97, 102, 48, 52, 49, 53, 49, 54, 56, 55, 55, 51, 54, 51, 50, 54, 99, 57, 102, 101, 97, 49, 55, 101, 50, 53, 102, 99, 53, 50, 56, 55, 54, 49, 51, 54, 57, 51, 99, 57, 49, 50, 57, 48, 57, 99, 98, 50, 50, 54, 97, 97, 52, 55, 57, 52, 102, 50, 54, 97, 52, 56, 34, 44, 34, 119, 101, 105, 103, 104, 116, 34, 58, 49, 48, 48, 125, 93, 125
					],
					"logs": [],
					"block_height": 39225942,
					"block_hash": "BEZdFjq3G9x5TC6J6NYsfKFTTGBP6Hb5i8MCCKtBFXoA"
				},
				"id": "dontcare"
			}
			"#.to_vec()),
		sent: true,
		..Default::default()
	});
}

#[test]
fn parse_validator_set_works() {
	let test_data = vec![
		(r#"
			{
				"jsonrpc": "2.0",
				"result": {
					"result": [
						123, 34, 97, 112, 112, 99, 104, 97, 105, 110, 95, 105, 100, 34, 58, 49, 48, 48, 44, 34, 118, 97, 108, 105, 100, 97, 116, 111, 114, 95, 115, 101, 116, 95, 105, 110, 100, 101, 120, 34, 58, 48, 44, 34, 118, 97, 108, 105, 100, 97, 116, 111, 114, 115, 34, 58, 91, 123, 34, 111, 99, 119, 95, 105, 100, 34, 58, 34, 48, 120, 51, 48, 54, 55, 50, 49, 50, 49, 49, 100, 53, 52, 48, 52, 98, 100, 57, 100, 97, 56, 56, 101, 48, 50, 48, 52, 51, 54, 48, 97, 49, 97, 57, 97, 98, 56, 98, 56, 55, 99, 54, 54, 99, 49, 98, 99, 50, 102, 99, 100, 100, 51, 55, 102, 51, 99, 50, 50, 50, 50, 99, 99, 50, 48, 34, 44, 34, 105, 100, 34, 58, 34, 48, 120, 100, 52, 51, 53, 57, 51, 99, 55, 49, 53, 102, 100, 100, 51, 49, 99, 54, 49, 49, 52, 49, 97, 98, 100, 48, 52, 97, 57, 57, 102, 100, 54, 56, 50, 50, 99, 56, 53, 53, 56, 56, 53, 52, 99, 99, 100, 101, 51, 57, 97, 53, 54, 56, 52, 101, 55, 97, 53, 54, 100, 97, 50, 55, 100, 34, 44, 34, 119, 101, 105, 103, 104, 116, 34, 58, 49, 48, 48, 125, 44, 123, 34, 111, 99, 119, 95, 105, 100, 34, 58, 34, 48, 120, 101, 54, 53, 57, 97, 55, 97, 49, 54, 50, 56, 99, 100, 100, 57, 51, 102, 101, 98, 99, 48, 52, 97, 52, 101, 48, 54, 52, 54, 101, 97, 50, 48, 101, 57, 102, 53, 102, 48, 99, 101, 48, 57, 55, 100, 57, 97, 48, 53, 50, 57, 48, 100, 52, 97, 57, 101, 48, 53, 52, 100, 102, 52, 101, 34, 44, 34, 105, 100, 34, 58, 34, 48, 120, 56, 101, 97, 102, 48, 52, 49, 53, 49, 54, 56, 55, 55, 51, 54, 51, 50, 54, 99, 57, 102, 101, 97, 49, 55, 101, 50, 53, 102, 99, 53, 50, 56, 55, 54, 49, 51, 54, 57, 51, 99, 57, 49, 50, 57, 48, 57, 99, 98, 50, 50, 54, 97, 97, 52, 55, 57, 52, 102, 50, 54, 97, 52, 56, 34, 44, 34, 119, 101, 105, 103, 104, 116, 34, 58, 49, 48, 48, 125, 93, 125
					],
					"logs": [],
					"block_height": 39225942,
					"block_hash": "BEZdFjq3G9x5TC6J6NYsfKFTTGBP6Hb5i8MCCKtBFXoA"
				},
				"id": "dontcare"
			}
			"#, expected_set()),
	];

	for (json, expected) in test_data {
		assert_eq!(expected, Example::parse_validator_set(json));
	}
}

#[test]
fn extract_result_works() {
	let test_data = vec![
		(r#"
			{
				"jsonrpc": "2.0",
				"result": {
					"result": [
						111, 99, 116, 111, 112, 117, 115
					],
					"logs": [],
					"block_height": 39225942,
					"block_hash": "BEZdFjq3G9x5TC6J6NYsfKFTTGBP6Hb5i8MCCKtBFXoA"
				},
				"id": "dontcare"
			}
			"#, Some(vec![111, 99, 116, 111, 112, 117, 115])),
	];

	for (json, expected) in test_data {
		assert_eq!(expected, Example::extract_result(json));
	}
}

#[test]
fn encode_args_works() {
	let test_data = vec![
		(0u32, Some(vec![101, 121, 74, 112, 98, 109, 82, 108, 101, 67, 73, 54, 77, 72, 48, 61])), // eyJpbmRleCI6MH0=
		(4294967295u32, Some(vec![101, 121, 74, 112, 98, 109, 82, 108, 101, 67, 73, 54, 78, 68, 73, 53, 78, 68, 107, 50, 78, 122, 73, 53, 78, 88, 48, 61])), // eyJpbmRleCI6NDI5NDk2NzI5NX0=
	];

	for (index, expected) in test_data {
		assert_eq!(expected, Example::encode_args(index));
	}
}

#[test]
fn should_submit_unsigned_transaction_on_chain() {
	const PHRASE: &str = "news slush supreme milk chapter athlete soap sausage put clutch what kitten";
	let (offchain, offchain_state) = testing::TestOffchainExt::new();
	let (pool, pool_state) = testing::TestTransactionPoolExt::new();

	let keystore = KeyStore::new();

	SyncCryptoStore::sr25519_generate_new(
		&keystore,
		crate::crypto::Public::ID,
		Some(&format!("{}/hunter1", PHRASE))
	).unwrap();

	let public_key = SyncCryptoStore::sr25519_public_keys(&keystore, crate::crypto::Public::ID)
		.get(0)
		.unwrap()
		.clone();

	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainExt::new(offchain));
	t.register_extension(TransactionPoolExt::new(pool));
	t.register_extension(KeystoreExt(Arc::new(keystore)));

	validator_set_response(&mut offchain_state.write());

	let payload = ValidatorSetPayload {
		public: <Test as SigningTypes>::Public::from(public_key),
		block_number: 1,
		set: expected_set().unwrap(),
	};

	// let signature = price_payload.sign::<crypto::TestAuthId>().unwrap();
	t.execute_with(|| {
		// when
		Example::fetch_and_update_validator_set(1, 0).unwrap();
		// then
		let tx = pool_state.write().transactions.pop().unwrap();
		let tx = Extrinsic::decode(&mut &*tx).unwrap();
		assert_eq!(tx.signature, None);
		if let Call::Example(crate::Call::submit_validator_set(body, signature)) = tx.call {
			assert_eq!(body, payload);

			let signature_valid = <ValidatorSetPayload<
				<Test as SigningTypes>::Public,
				<Test as frame_system::Config>::BlockNumber,
				<Test as frame_system::Config>::AccountId
					> as SignedPayload<Test>>::verify::<crypto::TestAuthId>(&payload, signature);

			assert!(signature_valid);
		}
	});
}
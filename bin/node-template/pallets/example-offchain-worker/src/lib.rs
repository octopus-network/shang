#![cfg_attr(not(feature = "std"), no_std)]

use frame_system::{
	self as system,
	ensure_none,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendUnsignedTransaction,
		SignedPayload, SigningTypes, Signer,
	}
};
use frame_support::{
	debug,
	dispatch::DispatchResult, decl_module, decl_storage, decl_error, decl_event,
	traits::Get,
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	RuntimeDebug,
	offchain::{http, Duration, storage::StorageValueRef},
	transaction_validity::{
		InvalidTransaction, ValidTransaction, TransactionValidity, TransactionSource,
		TransactionPriority,
	},
};
use codec::{Encode, Decode};
use sp_std::vec::Vec;
use lite_json::json::JsonValue;
use sp_std::prelude::*;
use sp_runtime::traits::IdentifyAccount;

#[cfg(test)]
mod tests;

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"oct!");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		MultiSignature, MultiSigner,
	};
	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

/// This pallet's configuration trait
pub trait Config: CreateSignedTransaction<Call<Self>> {
	/// The identifier type for an offchain worker.
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;

	// Configuration parameters

	/// A grace period after we send transaction.
	///
	/// To avoid sending too many transactions, we only attempt to send one
	/// every `GRACE_PERIOD` blocks. We use Local Storage to coordinate
	/// sending between distinct runs of this offchain worker.
	type GracePeriod: Get<Self::BlockNumber>;

	/// Number of blocks of cooldown after unsigned transaction is included.
	///
	/// This ensures that we only accept unsigned transactions once, every `UnsignedInterval` blocks.
	type UnsignedInterval: Get<Self::BlockNumber>;

	/// A configuration for base priority of unsigned transactions.
	///
	/// This is exposed so that it can be tuned for particular runtime, when
	/// multiple pallets send unsigned transactions.
	type UnsignedPriority: Get<TransactionPriority>;
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct Validator<AccountId> {
	ocw_id: AccountId,
	id: AccountId,
	weight: u64,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct ValidatorSet<AccountId> {
	appchain_id: u32,
	validator_set_index: u32,
	validators: Vec<Validator<AccountId>>,
}

/// Payload used by this crate to hold validator set
/// data required to submit a transaction.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct ValidatorSetPayload<Public, BlockNumber, AccountId> {
	public: Public,
	block_number: BlockNumber,
	set: ValidatorSet<AccountId>,
}

impl<T: SigningTypes> SignedPayload<T> for ValidatorSetPayload<T::Public, T::BlockNumber, <T as frame_system::Config>::AccountId> {
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

decl_storage! {
	trait Store for Module<T: Config> as ExampleOffchainWorker {
		///
		CurrentValidatorSet get(fn current_validator_set): Option<ValidatorSet<<T as frame_system::Config>::AccountId>>;
		///
		CandidateValidatorSets get(fn candidate_validator_sets): Vec<ValidatorSet<<T as frame_system::Config>::AccountId>>;
		///
		Voters get(fn voters):
		map hasher(twox_64_concat) u32
		=> Vec<Validator<<T as frame_system::Config>::AccountId>>;
		/// Defines the block when next unsigned transaction will be accepted.
		///
		/// To prevent spam of unsigned (and unpayed!) transactions on the network,
		/// we only allow one transaction every `T::UnsignedInterval` blocks.
		/// This storage entry defines when new transaction is going to be accepted.
		NextUnsignedAt get(fn next_unsigned_at): T::BlockNumber;
	}
	add_extra_genesis {
		config(vals): Vec<(<T as frame_system::Config>::AccountId, <T as frame_system::Config>::AccountId, u64)>;
		build(|config| Module::<T>::initialize_validator_set(&config.vals))
	}
}

decl_error! {
	/// Error for the offchain worker module.
	pub enum Error for Module<T: Config> {
		/// Invalid.
		Invalid,
	}
}

decl_event!(
	/// Events generated by the module.
	pub enum Event<T> where AccountId = <T as frame_system::Config>::AccountId {
		/// Event generated when new price is accepted to contribute to the average.
		/// \[price, who\]
		NewPrice(u32, AccountId),
	}
);

decl_module! {
	/// A public part of the pallet.
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		#[weight = 0]
		pub fn submit_validator_set(
			origin,
			payload: ValidatorSetPayload<T::Public, T::BlockNumber, <T as frame_system::Config>::AccountId>,
			_signature: T::Signature,
		) -> DispatchResult {
			// This ensures that the function can only be called via unsigned transaction.
			ensure_none(origin)?;

			if let Some(set) = <CurrentValidatorSet<T>>::get() {
				if payload.set.validator_set_index != set.validator_set_index + 1 {
					debug::native::error!("Wrong validator set index: {}", payload.set.validator_set_index);
					return Err(Error::<T>::Invalid.into());
				}
				let val = set.validators
					.iter()
					.find(|v| {
						v.ocw_id == payload.public.clone().into_account()
					});
				if val.is_none() {
					debug::native::error!("Not a validator in current set: {:?}", payload.public.clone().into_account());
					return Err(Error::<T>::Invalid.into());
				}
				Self::add_validator_set(val.unwrap().clone(), payload.set);

				// now increment the block number at which we expect next unsigned transaction.
				let current_block = <system::Module<T>>::block_number();
				<NextUnsignedAt<T>>::put(current_block + T::UnsignedInterval::get());
				Ok(())
			} else {
				// TODO
				Err(Error::<T>::Invalid.into())
			}
		}

		/// Offchain Worker entry point.
		///
		/// By implementing `fn offchain_worker` within `decl_module!` you declare a new offchain
		/// worker.
		/// This function will be called when the node is fully synced and a new best block is
		/// succesfuly imported.
		/// Note that it's not guaranteed for offchain workers to run on EVERY block, there might
		/// be cases where some blocks are skipped, or for some the worker runs twice (re-orgs),
		/// so the code should be able to handle that.
		/// You can use `Local Storage` API to coordinate runs of the worker.
		fn offchain_worker(block_number: T::BlockNumber) {
			debug::native::info!("Hello World from offchain workers!");

			let parent_hash = <system::Module<T>>::block_hash(block_number - 1u32.into());
			debug::native::info!("Current block: {:?} (parent hash: {:?})", block_number, parent_hash);

			if !Self::should_send(block_number) {
				return;
			}

			let next_index;
			if let Some(set) = <CurrentValidatorSet<T>>::get() {
				next_index = set.validator_set_index + 1;
			} else {
				debug::native::error!("CurrentValidatorSet must be initialized.");
				return;
			}
			debug::native::info!("Next validator set index: {}", next_index);

			if let Err(e) = Self::fetch_and_update_validator_set(block_number, next_index) {
				debug::native::error!("Error: {}", e);
			}
		}
	}
}

/// Most of the functions are moved outside of the `decl_module!` macro.
///
/// This greatly helps with error messages, as the ones inside the macro
/// can sometimes be hard to debug.
impl<T: Config> Module<T> {
	fn initialize_validator_set(vals: &Vec<(<T as frame_system::Config>::AccountId, <T as frame_system::Config>::AccountId, u64)>) {
		if vals.len() != 0 {
			assert!(<CurrentValidatorSet<T>>::get().is_none(), "CurrentValidatorSet are already initialized!");
			<CurrentValidatorSet<T>>::put(
				// ValidatorSet<<T as frame_system::Config>::AccountId>
				ValidatorSet{
					appchain_id: 100,
					validator_set_index: 0,
					validators: vals.iter().map(|x| Validator{
						ocw_id: x.0.clone(),
						id: x.1.clone(),
						weight: x.2,
					}).collect::<Vec<_>>(),
				}
			);
		}
	}

	fn should_send(block_number: T::BlockNumber) -> bool {
		/// A friendlier name for the error that is going to be returned in case we are in the grace
		/// period.
		const RECENTLY_SENT: () = ();

		// Start off by creating a reference to Local Storage value.
		// Since the local storage is common for all offchain workers, it's a good practice
		// to prepend your entry with the module name.
		let val = StorageValueRef::persistent(b"example_ocw::last_send");
		// The Local Storage is persisted and shared between runs of the offchain workers,
		// and offchain workers may run concurrently. We can use the `mutate` function, to
		// write a storage entry in an atomic fashion. Under the hood it uses `compare_and_set`
		// low-level method of local storage API, which means that only one worker
		// will be able to "acquire a lock" and send a transaction if multiple workers
		// happen to be executed concurrently.
		let res = val.mutate(|last_send: Option<Option<T::BlockNumber>>| {
			// We match on the value decoded from the storage. The first `Option`
			// indicates if the value was present in the storage at all,
			// the second (inner) `Option` indicates if the value was succesfuly
			// decoded to expected type (`T::BlockNumber` in our case).
			match last_send {
				// If we already have a value in storage and the block number is recent enough
				// we avoid sending another transaction at this time.
				Some(Some(block)) if block_number < block + T::GracePeriod::get() => {
					Err(RECENTLY_SENT)
				},
				// In every other case we attempt to acquire the lock and send a transaction.
				_ => Ok(block_number)
			}
		});

		// The result of `mutate` call will give us a nested `Result` type.
		// The first one matches the return of the closure passed to `mutate`, i.e.
		// if we return `Err` from the closure, we get an `Err` here.
		// In case we return `Ok`, here we will have another (inner) `Result` that indicates
		// if the value has been set to the storage correctly - i.e. if it wasn't
		// written to in the meantime.
		match res {
			// The value has been set correctly, which means we can safely send a transaction now.
			Ok(Ok(_block_number)) => {
				true
			},
			// We are in the grace period, we should not send a transaction this time.
			Err(RECENTLY_SENT) => false,
			// We wanted to send a transaction, but failed to write the block number (acquire a
			// lock). This indicates that another offchain worker that was running concurrently
			// most likely executed the same logic and succeeded at writing to storage.
			// Thus we don't really want to send the transaction, knowing that the other run
			// already did.
			Ok(Err(_)) => false,
		}
	}

	fn fetch_and_update_validator_set(block_number: T::BlockNumber, next_index: u32) -> Result<(), &'static str> {
		debug::native::info!("ys-debug: in fetch_and_update_validator_set");
		// Make sure we don't fetch if unsigned transaction is going to be rejected anyway.
		let next_unsigned_at = <NextUnsignedAt<T>>::get();
		if next_unsigned_at > block_number {
			return Err("Too early to send unsigned transaction")
		}

		// Make an external HTTP request to fetch the current validator set.
		// Note this call will block until response is received.
		let set = Self::fetch_validator_set(next_index).map_err(|_| "Failed to fetch validator set")?;

		// -- Sign using any account
		let (_, result) = Signer::<T, T::AuthorityId>::any_account().send_unsigned_transaction(
			|account| ValidatorSetPayload {
				public: account.public.clone(),
				block_number,
				set: set.clone()
			},
			|payload, signature| {
				Call::submit_validator_set(payload, signature)
			}
		).ok_or("No local accounts accounts available.")?;
		result.map_err(|()| "Unable to submit transaction")?;

		Ok(())
	}

	/// Fetch current price and return the result in cents.
	fn fetch_validator_set(_index: u32) -> Result<ValidatorSet<<T as frame_system::Config>::AccountId>, http::Error> {
		// We want to keep the offchain worker execution time reasonable, so we set a hard-coded
		// deadline to 2s to complete the external call.
		// You can also wait idefinitely for the response, however you may still get a timeout
		// coming from the host machine.
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		// Initiate an external HTTP GET request.
		// This is using high-level wrappers from `sp_runtime`, for the low-level calls that
		// you can find in `sp_io`. The API is trying to be similar to `reqwest`, but
		// since we are running in a custom WASM execution environment we can't simply
		// import the library here.
		let request = http::Request::get(
			"https://www.baidu.com"
		);
		// We set the deadline for sending of the request, note that awaiting response can
		// have a separate deadline. Next we send the request, before that it's also possible
		// to alter request headers or stream body content in case of non-GET requests.
		let pending = request
			.deadline(deadline)
			.send()
			.map_err(|_| http::Error::IoError)?;

		// The request is already being processed by the host, we are free to do anything
		// else in the worker (we can send multiple concurrent requests too).
		// At some point however we probably want to check the response though,
		// so we can block current thread and wait for it to finish.
		// Note that since the request is being driven by the host, we don't have to wait
		// for the request to have it complete, we will just not read the response.
		let response = pending.try_wait(deadline)
			.map_err(|_| http::Error::DeadlineReached)??;
		// Let's check the status code before we proceed to reading the response.
		if response.code != 200 {
			debug::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown);
		}

		// Next we want to fully read the response body and collect it to a vector of bytes.
		// Note that the return object allows you to read the body in chunks as well
		// with a way to control the deadline.
		let body = response.body().collect::<Vec<u8>>();

		// Create a str slice from the body.
		let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
			debug::warn!("No UTF8 body");
			http::Error::Unknown
		})?;
		// debug::native::info!("Got response: {:?}", body_str);

		let body_str = "{
			\"appchain_id\":100,
			\"validator_set_index\":1,
			\"validators\":[
				{
					\"ocw_id\":\"0x306721211d5404bd9da88e0204360a1a9ab8b87c66c1bc2fcdd37f3c2222cc20\",
					\"id\":\"0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d\",
					\"weight\":100
				},
				{
					\"ocw_id\":\"0xe659a7a1628cdd93febc04a4e0646ea20e9f5f0ce097d9a05290d4a9e054df4e\",
					\"id\":\"0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48\",
					\"weight\":200
				}
			]
		}";

		let set = match Self::parse_validator_set(body_str) {
			Some(set) => Ok(set),
			None => {
				debug::warn!("Unable to extract price from the response: {:?}", body_str);
				Err(http::Error::Unknown)
			}
		}?;

		debug::warn!("Got validator set: {:?}", set);

		Ok(set)
	}

	fn parse_validator_set(price_str: &str) -> Option<ValidatorSet<<T as frame_system::Config>::AccountId>> {
		let val = lite_json::parse_json(price_str);
		let mut set: ValidatorSet<<T as frame_system::Config>::AccountId> = ValidatorSet {
			appchain_id: 0,
			validator_set_index: 0,
			validators: vec![],
		};
		val.ok().and_then(|v| match v {
			JsonValue::Object(obj) => {
				set.appchain_id = obj
					.clone()
					.into_iter()
					.find(|(k, _)| {
						let mut appchain_id = "appchain_id".chars();
						k.iter().all(|k| Some(*k) == appchain_id.next())
					})
					.and_then(|v| match v.1 {
						JsonValue::Number(number) => Some(number),
						_ => None,
					})?
					.integer as u32;
				set.validator_set_index = obj
					.clone()
					.into_iter()
					.find(|(k, _)| {
						let mut validator_set_index = "validator_set_index".chars();
						k.iter().all(|k| Some(*k) == validator_set_index.next())
					})
					.and_then(|v| match v.1 {
						JsonValue::Number(number) => Some(number),
						_ => None,
					})?
					.integer as u32;
				obj.into_iter()
					.find(|(k, _)| {
						let mut validators = "validators".chars();
						k.iter().all(|k| Some(*k) == validators.next())
					})
					.and_then(|(_, v)| match v {
						JsonValue::Array(vs) => {
							vs.iter().for_each(|v| match v {
								JsonValue::Object(obj) => {
									let ocw_id = obj
										.clone()
										.into_iter()
										.find(|(k, _)| {
											let mut ocw_id = "ocw_id".chars();
											k.iter().all(|k| Some(*k) == ocw_id.next())
										})
										.and_then(|v| match v.1 {
											JsonValue::String(s) => {
												let data: Vec<u8> = s
													.iter()
													.skip(2)
													.map(|c| *c as u8)
													.collect::<Vec<_>>();
												let b = hex::decode(data).unwrap();
												<<T as SigningTypes>::Public as IdentifyAccount>::AccountId::decode(
													&mut &b[..],
												)
												.ok()
											}
											_ => None,
										});
									let id = obj
										.clone()
										.into_iter()
										.find(|(k, _)| {
											let mut id = "id".chars();
											k.iter().all(|k| Some(*k) == id.next())
										})
										.and_then(|v| match v.1 {
											JsonValue::String(s) => {
												let data: Vec<u8> = s
													.iter()
													.skip(2)
													.map(|c| *c as u8)
													.collect::<Vec<_>>();
												let b = hex::decode(data).unwrap();
												<T as frame_system::Config>::AccountId::decode(
													&mut &b[..],
												)
												.ok()
											}
											_ => None,
										});
									let weight = obj
										.clone()
										.into_iter()
										.find(|(k, _)| {
											let mut weight = "weight".chars();
											k.iter().all(|k| Some(*k) == weight.next())
										})
										.and_then(|v| match v.1 {
											JsonValue::Number(number) => Some(number),
											_ => None,
										});
									if id.is_some() && weight.is_some() {
										set.validators.push(Validator {
											ocw_id: ocw_id.unwrap(),
											id: id.unwrap(),
											weight: weight.unwrap().integer as u64,
										});
									}
								}
								_ => (),
							});
							Some(0)
						}
						_ => None,
					});
				Some(set)
			}
			_ => None,
		})
	}

	/// Add new validator set to the list.
	fn add_validator_set(
		val: Validator<<T as frame_system::Config>::AccountId>,
		new_set: ValidatorSet<<T as frame_system::Config>::AccountId>,
	) {
		debug::native::info!("Adding to the voters: {:?}", new_set);
		let index = 0;
		<CandidateValidatorSets<T>>::mutate(|sets| {
			// TODO
			if sets.len() == 0 {
				sets.push(new_set);
			}
		});

		<Voters<T>>::mutate(index, |vals| {
			let exist = vals
				.iter()
				.find(|v| {
					v.ocw_id == val.ocw_id
				});
			if exist.is_none() {
				vals.push(val)
			}
		});
		// // here we are raising the NewPrice event
		// Self::deposit_event(RawEvent::NewPrice(price, who));
	}

	fn validate_transaction_parameters(
		block_number: &T::BlockNumber,
		set: &ValidatorSet<<T as frame_system::Config>::AccountId>,
	) -> TransactionValidity {
		// Now let's check if the transaction has any chance to succeed.
		let next_unsigned_at = <NextUnsignedAt<T>>::get();
		if &next_unsigned_at > block_number {
			return InvalidTransaction::Stale.into();
		}
		// Let's make sure to reject transactions from the future.
		let current_block = <system::Module<T>>::block_number();
		if &current_block < block_number {
			return InvalidTransaction::Future.into();
		}

		ValidTransaction::with_tag_prefix("ExampleOffchainWorker")
			// We set base priority to 2**20 and hope it's included before any other
			// transactions in the pool. Next we tweak the priority depending on how much
			// it differs from the current average. (the more it differs the more priority it
			// has).
			.priority(T::UnsignedPriority::get().saturating_add(set.validator_set_index as _))
			// This transaction does not require anything else to go before into the pool.
			// In theory we could require `previous_unsigned_at` transaction to go first,
			// but it's not necessary in our case.
			//.and_requires()
			// We set the `provides` tag to be the same as `next_unsigned_at`. This makes
			// sure only one transaction produced after `next_unsigned_at` will ever
			// get to the transaction pool and will end up in the block.
			// We can still have multiple transactions compete for the same "spot",
			// and the one with higher priority will replace other one in the pool.
			.and_provides(next_unsigned_at)
			// The transaction is only valid for next 5 blocks. After that it's
			// going to be revalidated by the pool.
			.longevity(5)
			// It's fine to propagate that transaction to other peers, which means it can be
			// created even by nodes that don't produce blocks.
			// Note that sometimes it's better to keep it for yourself (if you are the block
			// producer), since for instance in some schemes others may copy your solution and
			// claim a reward.
			.propagate(true)
			.build()
	}
}

#[allow(deprecated)] // ValidateUnsigned
impl<T: Config> frame_support::unsigned::ValidateUnsigned for Module<T> {
	type Call = Call<T>;

	/// Validate unsigned call to this module.
	///
	/// By default unsigned transactions are disallowed, but implementing the validator
	/// here we make sure that some particular calls (the ones produced by offchain worker)
	/// are being whitelisted and marked as valid.
	fn validate_unsigned(
		_source: TransactionSource,
		call: &Self::Call,
	) -> TransactionValidity {
		// Firstly let's check that we call the right function.
		if let Call::submit_validator_set(
			ref payload, ref signature
		) = call {
			let signature_valid = SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone());
			if !signature_valid {
				return InvalidTransaction::BadProof.into();
			}
			Self::validate_transaction_parameters(&payload.block_number, &payload.set)
		} else {
			InvalidTransaction::Call.into()
		}
	}
}

pub(crate) const LOG_TARGET: &'static str = "cdot";
pub type SessionIndex = u32;

impl<T: Config> pallet_session::SessionManager<T::AccountId> for Module<T> {
	fn new_session(new_index: SessionIndex) -> Option<Vec<T::AccountId>> {
			frame_support::debug::native::trace!(
				target: LOG_TARGET,
				"[{}] planning new_session({})",
				<frame_system::Module<T>>::block_number(),
				new_index
			);
			let alice = vec![
				212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44,
				133, 88, 133, 76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
				];
			let bob = vec![
				142, 175, 4, 21, 22, 135, 115, 99, 38, 201, 254, 161, 126, 37, 252, 82, 135, 97,
				54, 147, 201, 18, 144, 156, 178, 38, 170, 71, 148, 242, 106, 72,
				];
			let charlie = vec![
				144, 181, 171, 32, 92, 105, 116, 201, 234, 132, 27, 230, 136, 134, 70, 51, 220,
				156, 168, 163, 87, 132, 62, 234, 207, 35, 20, 100, 153, 101, 254, 34,
				];
			if new_index % 2 == 0 {
				Some(vec![
					<T as frame_system::Config>::AccountId::decode(&mut &alice[..]).unwrap_or_default(),
					<T as frame_system::Config>::AccountId::decode(&mut &bob[..]).unwrap_or_default(),
					])
			} else if new_index % 3 == 0 {
				Some(vec![
					<T as frame_system::Config>::AccountId::decode(&mut &alice[..]).unwrap_or_default(),
					<T as frame_system::Config>::AccountId::decode(&mut &charlie[..]).unwrap_or_default(),
					])
			} else {
				Some(vec![
					<T as frame_system::Config>::AccountId::decode(&mut &bob[..]).unwrap_or_default(),
					<T as frame_system::Config>::AccountId::decode(&mut &charlie[..]).unwrap_or_default(),
					])
				}
	}

	fn start_session(start_index: SessionIndex) {
		frame_support::debug::native::trace!(
			target: LOG_TARGET,
			"[{}] starting start_session({})",
			<frame_system::Module<T>>::block_number(),
			start_index
		);
	}

	fn end_session(end_index: SessionIndex) {
		frame_support::debug::native::trace!(
			target: LOG_TARGET,
			"[{}] ending end_session({})",
			<frame_system::Module<T>>::block_number(),
			end_index
		);
	}
}

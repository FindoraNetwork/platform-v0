// Interface for issuing transactions that can be compiled to Wasm.
// Allows web clients to issue transactions from a browser contexts.
// For now, forwards transactions to a ledger hosted locally.
// To compile wasm package, run wasm-pack build in the wasm directory;
//#![deny(warnings)]
use bulletproofs::PedersenGens;
use core::fmt::Display;
use credentials::{
  credential_commit, credential_issuer_key_gen, credential_reveal, credential_sign,
  credential_user_key_gen, credential_verify, CredCommitment, CredIssuerPublicKey,
  CredIssuerSecretKey, CredPoK, CredRevealSig, CredSignature, CredUserPublicKey, CredUserSecretKey,
  Credential as PlatformCredential,
};
use cryptohash::sha256;
use cryptohash::sha256::Digest as BitDigest;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use js_sys::Promise;
use ledger::data_model::{
  b64enc, AssetTypeCode, AuthenticatedTransaction, Operation, Serialized, TransferType, TxOutput,
  TxoRef, TxoSID,
};
use ledger::policies::{DebtMemo, Fraction};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use std::str;
use txn_builder::{BuildsTransactions, TransactionBuilder, TransferOperationBuilder};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode};
use zei::api::anon_creds::ac_confidential_gen_encryption_keys;
use zei::basic_crypto::elgamal::{elgamal_key_gen, ElGamalEncKey};
use zei::serialization::ZeiFromToBytes;
use zei::setup::PublicParams;
use zei::xfr::asset_record::{
  build_blind_asset_record, open_blind_asset_record as open_bar, AssetRecordType,
};
use zei::xfr::sig::{XfrKeyPair, XfrPublicKey};
use zei::xfr::structs::{
  AssetRecordTemplate, AssetTracerEncKeys, BlindAssetRecord, OpenAssetRecord, OwnerMemo,
};

/////////// TRANSACTION BUILDING ////////////////

//Random Helpers

#[wasm_bindgen]
/// Creates a relative txo reference as a JSON string. Relative txo references are offset
/// backwards from the operation they appear in -- 0 is the most recent, (n-1) is the first output
/// of the transaction.
///
/// Use relative txo indexing when referring to outputs of intermediate operations (e.g. a
/// transaction containing both an issuance and a transfer).
///
/// # Arguments
/// @param {BigInt} idx -  Relative Txo (transaction output) SID.
pub fn create_relative_txo_ref(idx: u64) -> String {
  serde_json::to_string(&TxoRef::Relative(idx)).unwrap()
}

#[wasm_bindgen]
/// Creates an absolute transaction reference as a JSON string.
///
/// Use absolute txo indexing when referring to an output that has been assigned a utxo index (i.e.
/// when the utxo has been committed to the ledger in an earlier transaction).
///
/// # Arguments
/// @param {BigInt} idx -  Txo (transaction output) SID.
pub fn create_absolute_txo_ref(idx: u64) -> String {
  serde_json::to_string(&TxoRef::Absolute(TxoSID(idx))).unwrap()
}

#[wasm_bindgen]
/// Standard TransferType variant for txn builder.
/// Returns a token as a string signifying that the Standard policy should be used when evaluating the transaction.
pub fn standard_transfer_type() -> String {
  serde_json::to_string(&TransferType::Standard).unwrap()
}

#[wasm_bindgen]
/// Debt swap TransferType variant for txn builder.
/// Returns a token as a string signifying that the DebtSwap policy should be used when evaluating the transaction.
pub fn debt_transfer_type() -> String {
  serde_json::to_string(&TransferType::DebtSwap).unwrap()
}

#[wasm_bindgen]
/// Generates random base64 encoded asset type string. Used in asset definitions.
/// @see {@link WasmTransactionBuilder#add_operation_create_asset} for instructions on how to define an asset with a new
/// asset type
pub fn random_asset_type() -> String {
  AssetTypeCode::gen_random().to_base64()
}

#[wasm_bindgen]
/// Given a serialized state commitment and transaction, returns true if the transaction correctly
/// hashes up to the state commitment and false otherwise.
/// @param {string} state_commitment - string representating the state commitment.
/// @param {string} authenticated_txn - string representating the transaction.
/// @see {@link get_transaction} for instructions on fetching a transaction from the ledger.
/// @see {@link get_state_commitment} for instructions on fetching a ledger state commitment.
/// @throws Will throw an error if the state commitment or the transaction fail to deserialize.
pub fn verify_authenticated_txn(state_commitment: String,
                                authenticated_txn: String)
                                -> Result<bool, JsValue> {
  let authenticated_txn = serde_json::from_str::<AuthenticatedTransaction>(&authenticated_txn)
        .map_err(|_e| JsValue::from_str("Could not deserialize transaction"))?;
  let state_commitment = serde_json::from_str::<BitDigest>(&state_commitment).map_err(|_e| {
                           JsValue::from_str("Could not deserialize state commitment")
                         })?;
  Ok(authenticated_txn.is_valid(state_commitment))
}

#[wasm_bindgen]
/// Performs a simple loan repayment fee calculation.
///
/// The returned fee is a fraction of the `outstanding_balance`
/// where the interest rate is expressed as a fraction `ir_numerator` / `ir_denominator`.
/// Used in the Lending Demo.
/// @param {BigInt} ir_numerator - interest rate numerator.
/// @param {BigInt} ir_denominator - interest rate denominator.
/// @param {BigInt] outstanding_balance -  amount of outstanding debt.
pub fn calculate_fee(ir_numerator: u64, ir_denominator: u64, outstanding_balance: u64) -> u64 {
  ledger::policies::calculate_fee(outstanding_balance,
                                  Fraction::new(ir_numerator, ir_denominator))
}

#[wasm_bindgen]
/// Returns an address to use for cancelling debt tokens in a debt swap.
pub fn get_null_pk() -> XfrPublicKey {
  XfrPublicKey::zei_from_bytes(&[0; 32])
}
#[wasm_bindgen]
/// Creates memo needed for debt token asset types. The memo will be parsed by the policy evaluator to ensure
/// that all payment and fee amounts are correct.
/// @param {BigInt} ir_numerator  - interest rate numerator.
/// @param {BigInt} ir_denominator - interest rate denominator.
/// @param {string} fiat_code - base64 string representing asset type used to pay off the loan.
/// @param {BigInt} loan_amount - loan amount.
/// @throws Will throw an error if `fiat_code` fails to deserialize.
pub fn create_debt_memo(ir_numerator: u64,
                        ir_denominator: u64,
                        fiat_code: String,
                        loan_amount: u64)
                        -> Result<String, JsValue> {
  let fiat_code = AssetTypeCode::new_from_base64(&fiat_code)
        .map_err(|_e| JsValue::from_str("Could not deserialize asset token code"))?;
  let memo = DebtMemo { interest_rate: Fraction::new(ir_numerator, ir_denominator),
                        fiat_code,
                        loan_amount };
  Ok(serde_json::to_string(&memo).unwrap())
}

#[wasm_bindgen]
/// Creates a blind asset record.
///
/// Blind asset records are records of asset ownership. Each blind asset record has a unique record
/// owner, an asset type, and an amount. Asset types and amounts can be confidential.
///
/// Transaction outputs (TXOs) of issuance and transfer operations contain blind asset records.
/// Transfer operation inputs also contain blind asset records.
///
/// For simple operations, it is not necessary to construct blind asset records manually -  `WasmTransactionBuilder` will handle most of the heavy lifting.
///
/// @param {BigInt} amount - asset amount to store in the record.
/// @param {string} code -  base64 string representing the token code of the asset to be stored in the record.
/// @param {XfrPublicKey} pk -  XfrPublicKey representing the record owner.
/// @param {bool} conf_amount - boolean indicating whether the asset amount should be private.
/// @param {bool} conf_type - boolean indicating whether the asset type should be private.
/// @see {@link WasmTransactionBuilder#add_operation_issue_asset} for instructions on how to use
/// blind asset records to issue assets on the ledger.
pub fn create_blind_asset_record(amount: u64,
                                 code: String,
                                 pk: &XfrPublicKey,
                                 conf_amount: bool,
                                 conf_type: bool)
                                 -> Result<String, JsValue> {
  let params = PublicParams::new();
  let code = AssetTypeCode::new_from_base64(&code)
        .map_err(|_e| JsValue::from_str("Could not deserialize asset token code"))?;
  let mut small_rng = ChaChaRng::from_entropy();
  let ar_type = AssetRecordType::from_booleans(conf_amount, conf_type);
  let template = AssetRecordTemplate::with_no_asset_tracking(amount, code.val, ar_type, *pk);
  Ok(serde_json::to_string(&build_blind_asset_record(&mut small_rng,
                                                     &params.pc_gens,
                                                     &template,
                                                     None)).unwrap())
}

#[wasm_bindgen]
/// Decodes (opens) a blind asset record expressed as a JSON string using the given key pair.
/// If successful returns a JSON encoding of the serialized open asset record.
/// @param {string} blind_asset_record - String representing the blind asset record.
/// @param {string} memo - String representing the blind asset record's owner's memo
/// @param {XfrKeyPair} key - Key pair of the asset record owner.
///
/// TODO Add advice for resolving the errors to the error messages when possible
/// @throws Could not deserialize blind asset record.
/// @throws Could not open asset record.
/// @see {@link WasmTransferOperationBuilder#add_input) for instructions on how to construct transfers with opened asset
/// records.
pub fn open_blind_asset_record(blind_asset_record: String,
                               memo: String,
                               key: &XfrKeyPair)
                               -> Result<String, JsValue> {
  let blind_asset_record = serde_json::from_str::<BlindAssetRecord>(&blind_asset_record).map_err(|_e| {
                             JsValue::from_str("Could not deserialize blind asset record")
                           })?;
  let memo = serde_json::from_str::<Option<OwnerMemo>>(&memo).map_err(|_e| {
    JsValue::from_str("Could not deserialize blind asset record")
  })?;
  let open_asset_record = open_bar(&blind_asset_record, &memo, key.get_sk_ref()).map_err(|_e| JsValue::from_str("Could not open asset record"))?;
  Ok(serde_json::to_string(&open_asset_record).unwrap())
}

#[wasm_bindgen]
/// Structure that allows users to construct arbitrary transactions.
#[derive(Default)]
pub struct WasmTransactionBuilder {
  transaction_builder: Serialized<TransactionBuilder>,
}

#[wasm_bindgen]
impl WasmTransactionBuilder {
  /// Create a new transaction builder.
  pub fn new() -> Self {
    Self::default()
  }

  /// Wraps around TransactionBuilder to add an asset definition operation to a transaction builder instance.
  ///
  /// @param {XfrKeyPair} key_pair -  Issuer XfrKeyPair.
  /// @param {string} memo - Text field for asset definition.
  /// @param {string} token_code - Optional Base64 string representing the token code of the asset to be issued
  /// If empty, a token code will be chosen at random.
  pub fn add_operation_create_asset(&self,
                                    key_pair: &XfrKeyPair,
                                    memo: String,
                                    token_code: String)
                                    -> Result<WasmTransactionBuilder, JsValue> {
    let asset_token = if token_code.is_empty() {
      AssetTypeCode::gen_random()
    } else {
      AssetTypeCode::new_from_base64(&token_code).unwrap()
    };

    Ok(WasmTransactionBuilder {
            transaction_builder: Serialized::new(
                &*self
                    .transaction_builder
                    .deserialize()
                    .add_operation_create_asset(&key_pair, Some(asset_token), false, false, &memo)
                    .map_err(|_e| JsValue::from_str("Could not build transaction"))?,
            ),
        })
  }

  /// Wraps around TransactionBuilder to add an asset issuance to a transaction builder instance.
  ///
  /// Use this function for simple one-shot issuances.
  ///
  /// @param {XfrKeyPair} key_pair  - Issuer XfrKeyPair.
  /// @param {string} elgamal_pub_key  - Optional tracking public key. Pass in serialized tracking key or "".
  /// @param {string} code - Base64 string representing the token code of the asset to be issued.
  /// @param {BigInt} seq_num - Issuance sequence number. Every subsequent issuance of a given asset type must have a higher sequence number than before.
  /// @param {BigInt} amount - Amount to be issued.
  #[allow(clippy::too_many_arguments)]
  pub fn add_basic_issue_asset(&self,
                               key_pair: &XfrKeyPair,
                               elgamal_pub_key: String,
                               code: String,
                               seq_num: u64,
                               amount: u64,
                               conf_amount: bool,
                               conf_asset_type: bool)
                               -> Result<WasmTransactionBuilder, JsValue> {
    let asset_token = AssetTypeCode::new_from_base64(&code)
            .map_err(|_e| JsValue::from_str("Could not deserialize asset token code"))?;

    let mut txn_builder = self.transaction_builder.deserialize();
    // construct asset tracking keys
    let issuer_keys;
    if elgamal_pub_key.is_empty() {
      issuer_keys = None
    } else {
      let pk = serde_json::from_str::<ElGamalEncKey<RistrettoPoint>>(&elgamal_pub_key).map_err(|_e| JsValue::from_str("could not deserialize elgamal key"))?;
      let mut small_rng = ChaChaRng::from_entropy();
      let (_, id_reveal_pub_key) = ac_confidential_gen_encryption_keys(&mut small_rng);
      issuer_keys = Some(AssetTracerEncKeys { record_data_enc_key: pk,
                                              attrs_enc_key: id_reveal_pub_key });
    }

    let confidentiality_flags = AssetRecordType::from_booleans(conf_amount, conf_asset_type);
    Ok(WasmTransactionBuilder { transaction_builder: Serialized::new(&*txn_builder.add_basic_issue_asset(&key_pair,
                                            &issuer_keys,
                                            &asset_token,
                                            seq_num,
                                            amount, confidentiality_flags
    ).map_err(|_e| JsValue::from_str("could not build transaction"))?)})
  }

  /// Wraps around TransactionBuilder to add an asset issuance operation to a transaction builder instance.
  ///
  /// While add_basic_issue_asset constructs the blind asset record internally, this function
  /// allows an issuer to pass in an externally constructed blind asset record. For complicated
  /// transactions (e.g. issue and
  /// transfers) the client must have a handle on the issuance record for subsequent operations.
  ///
  /// @param {XfrKeyPair} key_pair - Issuer XfrKeyPair.
  /// @param {string} code - Base64 string representing the token code of the asset to be issued.
  /// @param {BigInt} seq_num - Issuance sequence number. Every subsequent issuance of a given asset type must have a higher sequence number than before.
  /// @param {string} record - Issuance output (serialized blind asset record).
  /// @see {@link create_blind_asset_record} for details on constructing blind asset records.
  /// @see {@link random_asset_type} for details on generating new asset types.
  /// @throws Will throw an error if `record` or `code` fail to deserialize.
  pub fn add_operation_issue_asset(&self,
                                   key_pair: &XfrKeyPair,
                                   code: String,
                                   seq_num: u64,
                                   record: String,
                                   owner_memo: String)
                                   -> Result<WasmTransactionBuilder, JsValue> {
    let asset_token = AssetTypeCode::new_from_base64(&code)
            .map_err(|_e| JsValue::from_str("Could not deserialize asset token code"))?;
    let blind_asset_record = serde_json::from_str::<BlindAssetRecord>(&record).map_err(|_e| {
                               JsValue::from_str("could not deserialize blind asset record")
                             })?;
    let memo;
    if owner_memo.is_empty() {
      memo = None
    } else {
      memo =
        Some(serde_json::from_str::<OwnerMemo>(&owner_memo).map_err(|_e| {
                                           JsValue::from_str("could not deserialize owner memo")
                                         })?);
    }

    let mut txn_builder = self.transaction_builder.deserialize();
    Ok(WasmTransactionBuilder {
            transaction_builder: Serialized::new(
                &*txn_builder
                    .add_operation_issue_asset(
                        &key_pair,
                        &asset_token,
                        seq_num,
                        &[(TxOutput(blind_asset_record), memo)],
                    )
                    .map_err(|_e| JsValue::from_str("could not build transaction"))?,
            ),
        })
  }

  /// Adds a serialized operation to a WasmTransactionBuilder instance
  /// @param {string} op -  a JSON-serialized operation (i.e. a transfer operation).
  /// @see {@link WasmTransferOperationBuilder} for details on constructing a transfer operation.
  /// @throws Will throw an error if `op` fails to deserialize.
  pub fn add_operation(&mut self, op: String) -> Result<WasmTransactionBuilder, JsValue> {
    let op =
      serde_json::from_str::<Operation>(&op).map_err(|_e| {
                                              JsValue::from_str("Could not deserialize operation")
                                            })?;
    Ok(WasmTransactionBuilder { transaction_builder: Serialized::new(&*self.transaction_builder
                                                                           .deserialize()
                                                                           .add_operation(op)) })
  }

  /// Extracts the serialized form of a transaction.
  ///
  /// TODO Develop standard terminology for Javascript functions that may throw errors.
  pub fn transaction(&mut self) -> Result<String, JsValue> {
    Ok(self.transaction_builder
           .deserialize()
           .serialize_str()
           .map_err(|_e| JsValue::from_str("Could not serialize transaction"))?)
  }
}

#[wasm_bindgen]
#[derive(Default)]
/// Structure that enables clients to construct complex transfers.
pub struct WasmTransferOperationBuilder {
  op_builder: Serialized<TransferOperationBuilder>,
}
#[wasm_bindgen]
impl WasmTransferOperationBuilder {
  /// Create a new transfer operation builder.
  pub fn new() -> Self {
    Self::default()
  }

  /// Wraps around TransferOperationBuilder to add an input to a transfer operation builder.
  /// @param {string} txo_ref - Serialized Absolute or relative utxo reference
  /// @param {string} oar - Serializez opened asset record to serve as transfer input. This record must exist on the
  /// ledger for the transfer to be valid
  /// @param {BigInt} amount - Amount of input record to transfer
  /// @see {@link create_absolute_txo_ref} or {@link create_relative_txo_ref} for details on txo
  /// references.
  /// @see {@link open_blind_asset_record} for details on opening blind asset records.
  /// @see {@link get_txo} for details on fetching blind asset records.
  /// @throws Will throw an error if `oar` or `txo_ref` fail to deserialize.
  pub fn add_input(&mut self,
                   txo_ref: String,
                   oar: String,
                   amount: u64)
                   -> Result<WasmTransferOperationBuilder, JsValue> {
    let txo_sid =
      serde_json::from_str::<TxoRef>(&txo_ref).map_err(|_e| {
                                                JsValue::from_str("Could not deserialize txo sid")
                                              })?;
    let oar = serde_json::from_str::<OpenAssetRecord>(&oar)
            .map_err(|_e| JsValue::from_str("Could not deserialize open asset record"))?;
    Ok(WasmTransferOperationBuilder { op_builder:
                                        Serialized::new(&*self.op_builder
                                                              .deserialize()
                                                              .add_input(txo_sid, oar, amount)
                                                              .map_err(|e| {
                                                                JsValue::from_str(&format!("{}", e))
                                                              })?) })
  }

  /// Wraps around TransferOperationBuilder to add an output to a transfer operation builder.
  ///
  /// @param {BigInt} amount - amount to transfer to the recipient
  /// @param {XfrPublicKey} recipient - public key of the recipient
  /// @param code {string} - String representaiton of the asset token code
  /// @param conf_amount {bool} - Indicates whether output's amount is confidential
  /// @param conf_type {bool} - Indicates whether output's asset type is confidential
  /// @throws Will throw an error if `code` fails to deserialize.
  pub fn add_output(&mut self,
                    amount: u64,
                    recipient: &XfrPublicKey,
                    code: String,
                    conf_amount: bool,
                    conf_type: bool)
                    -> Result<WasmTransferOperationBuilder, JsValue> {
    let code = AssetTypeCode::new_from_base64(&code)
            .map_err(|_e| JsValue::from_str("Could not deserialize asset token code"))?;

    let asset_record_type = AssetRecordType::from_booleans(conf_amount, conf_type);
    let template =
      AssetRecordTemplate::with_no_asset_tracking(amount, code.val, asset_record_type, *recipient);
    let new_builder = Serialized::new(&*self.op_builder
                                            .deserialize()
                                            .add_output(&template)
                                            .map_err(|e| JsValue::from_str(&format!("{}", e)))?);
    Ok(WasmTransferOperationBuilder { op_builder: new_builder })
  }

  /// Wraps around TransferOperationBuilder to ensure the transfer inputs and outputs are balanced.
  /// This function will add change outputs for all unspent portions of input records.
  /// @throws Will throw an error if the transaction cannot be balanced.
  pub fn balance(&mut self) -> Result<WasmTransferOperationBuilder, JsValue> {
    Ok(WasmTransferOperationBuilder {
            op_builder: Serialized::new(
                &*self
                    .op_builder
                    .deserialize()
                    .balance()
                    .map_err(|_e| JsValue::from_str("Error balancing txn"))?,
            ),
        })
  }

  /// Wraps around TransferOperationBuilder to finalize the transaction.
  ///
  /// @param {string} transfer_type - string representing the transfer type
  /// @see {@link standard_transfer_type} or {@link debt_transfer_types} for details on transfer
  /// types.
  /// @throws Will throw an error if `transfer_type` fails to deserialize.
  /// @throws Will throw an error if input and output amounts do not add up.
  /// @throws Will throw an error if not all record owners have signed the transaction.
  pub fn create(&mut self, transfer_type: String) -> Result<WasmTransferOperationBuilder, JsValue> {
    let transfer_type = serde_json::from_str::<TransferType>(&transfer_type)
            .map_err(|_e| JsValue::from_str("Could not deserialize transfer type"))?;
    let new_builder = Serialized::new(&*self.op_builder
                                            .deserialize()
                                            .create(transfer_type)
                                            .map_err(|e| JsValue::from_str(&format!("{}", e)))?);

    Ok(WasmTransferOperationBuilder { op_builder: new_builder })
  }

  /// Wraps around TransferOperationBuilder to add a signature to the transaction.
  ///
  /// All input owners must sign.
  ///
  /// @param {XfrKeyPair} kp - key pair of one of the input owners.
  pub fn sign(&mut self, kp: &XfrKeyPair) -> Result<WasmTransferOperationBuilder, JsValue> {
    let new_builder = Serialized::new(&*self.op_builder
                                            .deserialize()
                                            .sign(&kp)
                                            .map_err(|e| JsValue::from_str(&format!("{}", e)))?);

    Ok(WasmTransferOperationBuilder { op_builder: new_builder })
  }

  /// Wraps around TransferOperationBuilder to extract an operation expression as JSON.
  pub fn transaction(&self) -> Result<String, JsValue> {
    let transaction = self.op_builder
                          .deserialize()
                          .transaction()
                          .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

    Ok(serde_json::to_string(&transaction).unwrap())
  }
}

///////////// CRYPTO //////////////////////

#[wasm_bindgen]
/// Extracts the public key as a string from a transfer key pair.
pub fn get_pub_key_str(key_pair: &XfrKeyPair) -> String {
  serde_json::to_string(key_pair.get_pk_ref()).unwrap()
}

#[wasm_bindgen]
/// Extracts the private key as a string from a transfer key pair.
pub fn get_priv_key_str(key_pair: &XfrKeyPair) -> String {
  serde_json::to_string(key_pair.get_sk_ref()).unwrap()
}

#[wasm_bindgen]
/// Creates a new transfer key pair.
pub fn new_keypair() -> XfrKeyPair {
  let mut small_rng = rand::thread_rng();
  XfrKeyPair::generate(&mut small_rng)
}

#[wasm_bindgen]
/// Returns base64 encoded representation of an XfrPublicKey.
pub fn public_key_to_base64(key: &XfrPublicKey) -> String {
  b64enc(&XfrPublicKey::zei_to_bytes(&key))
}

#[wasm_bindgen]
/// Expresses a transfer key pair as a hex-encoded string.
/// To decode the string, use `keypair_from_str` function.
pub fn keypair_to_str(key_pair: &XfrKeyPair) -> String {
  hex::encode(key_pair.zei_to_bytes())
}

#[wasm_bindgen]
/// Constructs a transfer key pair from a hex-encoded string.
/// The encode a key pair, use `keypair_to_str`
pub fn keypair_from_str(str: String) -> XfrKeyPair {
  XfrKeyPair::zei_from_bytes(&hex::decode(str).unwrap())
}

#[wasm_bindgen]
pub fn generate_elgamal_keys() -> String {
  let mut small_rng = rand::thread_rng();
  let pc_gens = PedersenGens::default();
  serde_json::to_string(&elgamal_key_gen::<_, Scalar, RistrettoPoint>(&mut small_rng, &pc_gens.B)).unwrap()
}

#[wasm_bindgen]
/// Returns the SHA256 signature of the given string as a hex-encoded
/// string.
pub fn sha256str(str: &str) -> String {
  let digest = sha256::hash(&str.as_bytes());
  hex::encode(digest)
}

#[wasm_bindgen]
/// Signs the given message using the given transfer key pair.
pub fn sign(key_pair: &XfrKeyPair, message: String) -> Result<JsValue, JsValue> {
  let signature = key_pair.get_sk_ref()
                          .sign(&message.as_bytes(), key_pair.get_pk_ref());
  let mut smaller_signature: [u8; 32] = Default::default();
  smaller_signature.copy_from_slice(&signature.0.to_bytes()[0..32]);
  Ok(JsValue::from_serde(&smaller_signature).unwrap())
}
/*
fn u8_littleendian_slice_to_u32(array: &[u8]) -> u32 {
  u32::from(array[0])
  | u32::from(array[1]) << 8
  | u32::from(array[2]) << 16
  | u32::from(array[3]) << 24
}

fn u32_pair_to_u64(x: (u32, u32)) -> u64 {
  (x.1 as u64) << 32 ^ (x.0 as u64)
}
*/
/*
#[wasm_bindgen]
pub fn get_tracked_amount(blind_asset_record: String,
                          issuer_private_key_point: String)
                          -> Result<String, JsValue> {
  let pc_gens = PedersenGens::default();
  let blind_asset_record = serde_json::from_str::<BlindAssetRecord>(&blind_asset_record).map_err(|_e| {
                             JsValue::from_str("Could not deserialize blind asset record")
                           })?;
  let issuer_private_key = serde_json::from_str(&issuer_private_key_point).map_err(|_e| {
                             JsValue::from_str("Could not deserialize issuer private key")
                           })?;
  if let Some(lock_amount) = blind_asset_record.issuer_lock_amount {
    match (elgamal_decrypt(&RistrettoPoint(pc_gens.B), &(lock_amount.0), &issuer_private_key),
           elgamal_decrypt(&RistrettoPoint(pc_gens.B), &(lock_amount.1), &issuer_private_key))
    {
      (Ok(s1), Ok(s2)) => {
        let amount = u32_pair_to_u64((u8_littleendian_slice_to_u32(s1.0.as_bytes()),
                                      u8_littleendian_slice_to_u32(s2.0.as_bytes())));
        Ok(amount.to_string())
      }
      (_, _) => Err(JsValue::from_str("Unable to decrypt amount")),
    }
  } else {
    Err(JsValue::from_str("Asset record does not contain decrypted lock amount"))
  }
}
*/

// Ensures that the transaction serialization is valid URI text
#[wasm_bindgen]
/// Submit a transaction to the ledger and return a promise for the
/// ledger's eventual response. The transaction will be enqueued for
/// validation. If it is valid, it will eventually be committed to the
/// ledger.
///
/// To determine whether or not the transaction has been committed to the ledger,
/// query the ledger by transaction handle.
///
/// Contained in the response of `submit_transaction` is a `TransactionHandle` that can be used to
/// query the status of the transaction.
/// @param {string} path - Submission server path (e.g. `https://localhost:8669`)
/// @param {transaction_str} - JSON-encoded transaction string.
///
/// @see {@link get_txn_status} for information about transaction statuses.
/// TODO Design and implement a notification mechanism.
pub fn submit_transaction(path: String, transaction_str: String) -> Result<Promise, JsValue> {
  let mut opts = RequestInit::new();
  opts.method("POST");
  opts.mode(RequestMode::Cors);
  opts.body(Some(&JsValue::from_str(&transaction_str)));

  let req_string = format!("{}/submit_transaction", path);

  create_query_promise(&opts, &req_string, true)
}

#[wasm_bindgen]
/// Given a transaction ID, returns a promise for the transaction status.
pub fn get_txn_status(path: String, handle: String) -> Result<Promise, JsValue> {
  let mut opts = RequestInit::new();
  opts.method("GET");
  opts.mode(RequestMode::Cors);

  let req_string = format!("{}/txn_status/{}", path, handle);

  create_query_promise(&opts, &req_string, false)
}

#[wasm_bindgen]
/// If successful, returns a promise that will eventually provide a
/// JsValue describing an unspent transaction output (UTXO).
/// Otherwise, returns 'not found'. The request fails if the txo uid
/// has been spent or the transaction index does not correspond to a
/// transaction.
/// @param {string} path - Address of ledger server
/// @param {BigInt} index - UTXO index
///
/// TODO Provide an example (test case) that demonstrates how to
/// handle the error in the case of an invalid transaction index.
/// TODO Rename this function get_utxo
pub fn get_txo(path: String, index: u64) -> Result<Promise, JsValue> {
  let mut opts = RequestInit::new();
  opts.method("GET");
  opts.mode(RequestMode::Cors);

  let req_string = format!("{}/utxo_sid/{}", path, format!("{}", index));

  create_query_promise(&opts, &req_string, false)
}

#[wasm_bindgen]
/// If successful, returns a promise that will eventually provide a
/// JsValue describing a transaction.
/// Otherwise, returns 'not found'. The request fails if the transaction index does not correspond
/// to a transaction.
///
/// @param {String} path - Ledger server path
/// @param {BigInt} index - transaction index.
///
/// TODO Provide an example (test case) that demonstrates how to
/// handle the error in the case of an invalid transaction index.
pub fn get_transaction(path: String, index: u64) -> Result<Promise, JsValue> {
  let mut opts = RequestInit::new();
  opts.method("GET");
  opts.mode(RequestMode::Cors);

  let req_string = format!("{}/txn_sid/{}", path, format!("{}", index));

  create_query_promise(&opts, &req_string, false)
}

#[wasm_bindgen]
/// Returns a JSON-encoded version of the state commitment of a running ledger. This is used to
/// check the authenticity of transactions and blocks.
pub fn get_state_commitment(path: String) -> Result<Promise, JsValue> {
  let mut opts = RequestInit::new();
  opts.method("GET");
  opts.mode(RequestMode::Cors);

  let req_string = format!("{}/state_commitment", path);

  create_query_promise(&opts, &req_string, false)
}

#[wasm_bindgen]
/// If successful, returns a promise that will eventually provide a
/// JsValue describing an asset token. Otherwise, returns 'not found'.
/// The request fails if the given asset name does not correspond to
/// an asset.
/// @param {string} path: Address of ledger server
/// @param {string} name: base64-encoded asset token string
///
/// TODO Provide an example (test case) that demonstrates how to
/// handle the error in the case of an undefined asset.
pub fn get_asset_token(path: String, name: String) -> Result<Promise, JsValue> {
  let mut opts = RequestInit::new();
  opts.method("GET");
  opts.mode(RequestMode::Cors);

  let req_string = format!("{}/asset_token/{}", path, name);

  create_query_promise(&opts, &req_string, false)
}

// Given a request string and a request init object, constructs
// the JS promise to be returned to the client.
fn create_query_promise(opts: &RequestInit,
                        req_string: &str,
                        is_json: bool)
                        -> Result<Promise, JsValue> {
  let request = Request::new_with_str_and_init(&req_string, &opts)?;
  if is_json {
    request.headers().set("content-type", "application/json")?;
  }
  let window = web_sys::window().unwrap();
  let request_promise = window.fetch_with_request(&request);
  Ok(future_to_promise(JsFuture::from(request_promise)))
}

#[derive(Serialize, Deserialize)]
struct AttributeDefinition {
  pub name: String,
  pub size: usize,
}

#[derive(Serialize, Deserialize)]
struct AttributeAssignment {
  pub name: String,
  pub val: String,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct CredentialUserKeyPair {
  pk: CredUserPublicKey,
  sk: CredUserSecretKey,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct CredentialIssuerKeyPair {
  pk: CredIssuerPublicKey,
  sk: CredIssuerSecretKey,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct CredentialSignature {
  sig: CredSignature,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct CredentialRevealSig {
  sig: CredRevealSig,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct CredentialCommitment {
  commitment: CredCommitment,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Credential {
  credential: PlatformCredential,
}

impl CredentialSignature {
  pub fn get_sig_ref(&self) -> &CredSignature {
    &self.sig
  }
}

impl Credential {
  pub fn get_cred_ref(&self) -> &PlatformCredential {
    &self.credential
  }
}

impl CredentialRevealSig {
  pub fn get_sig_ref(&self) -> &CredRevealSig {
    &self.sig
  }
}

#[wasm_bindgen]
impl CredentialIssuerKeyPair {
  pub fn get_pk(&self) -> CredIssuerPublicKey {
    self.pk.clone()
  }
  pub fn get_sk(&self) -> CredIssuerSecretKey {
    self.sk.clone()
  }
  pub fn serialize(&self) -> String {
    serde_json::to_string(&self).unwrap()
  }
}

#[wasm_bindgen]
impl CredentialUserKeyPair {
  pub fn get_pk(&self) -> CredUserPublicKey {
    self.pk.clone()
  }
  pub fn get_sk(&self) -> CredUserSecretKey {
    self.sk.clone()
  }
  pub fn serialize(&self) -> String {
    serde_json::to_string(&self).unwrap()
  }
}

#[wasm_bindgen]
pub fn wasm_credential_issuer_key_gen(attributes: JsValue) -> CredentialIssuerKeyPair {
  let mut prng = ChaChaRng::from_entropy();
  let mut attributes: Vec<AttributeDefinition> = attributes.into_serde().unwrap();
  let attributes: Vec<(String, usize)> = attributes.drain(..)
                                                   .map(|attr| (attr.name, attr.size))
                                                   .collect();

  let (pk, sk) = credential_issuer_key_gen(&mut prng, &attributes[..]);
  CredentialIssuerKeyPair { pk, sk }
}

#[wasm_bindgen]
pub fn wasm_credential_user_key_gen(issuer_pub_key: &CredIssuerPublicKey) -> CredentialUserKeyPair {
  let mut prng = ChaChaRng::from_entropy();
  let (pk, sk) = credential_user_key_gen(&mut prng, issuer_pub_key);
  CredentialUserKeyPair { pk, sk }
}

fn error_to_jsvalue<T: Display>(e: T) -> JsValue {
  JsValue::from_str(&String::from(format!("{}", e)))
}

#[wasm_bindgen]
pub fn wasm_credential_sign(issuer_secret_key: &CredIssuerSecretKey,
                            user_public_key: &CredUserPublicKey,
                            attributes: JsValue)
                            -> Result<CredentialSignature, JsValue> {
  let mut prng = ChaChaRng::from_entropy();
  let attributes: Vec<AttributeAssignment> = attributes.into_serde().unwrap();
  let attributes: Vec<(String, &[u8])> =
    attributes.iter()
              .map(|attr| (attr.name.clone(), attr.val.as_bytes()))
              .collect();
  let sig = credential_sign(&mut prng, &issuer_secret_key, &user_public_key, &attributes)
    .map_err(|e| error_to_jsvalue(e))?;
  Ok(CredentialSignature { sig })
}

#[wasm_bindgen]
pub fn create_credential(issuer_public_key: &CredIssuerPublicKey,
                         signature: &CredentialSignature,
                         attributes: &JsValue)
                         -> Credential {
  let attributes: Vec<AttributeAssignment> = attributes.into_serde().unwrap();
  let attributes: Vec<(String, Vec<u8>)> =
    attributes.iter()
              .map(|attr| (attr.name.clone(), attr.val.as_bytes().to_vec()))
              .collect();
  Credential { credential: PlatformCredential { attributes,
                                                issuer_pub_key: issuer_public_key.clone(),
                                                signature: signature.get_sig_ref().clone() } }
}

#[wasm_bindgen]
pub fn wasm_credential_commit(user_secret_key: &CredUserSecretKey,
                              user_public_key: &XfrPublicKey,
                              credential: &Credential)
                              -> Result<CredentialCommitment, JsValue> {
  let mut prng = ChaChaRng::from_entropy();
  let (commitment, _pok, _key) =
    credential_commit(&mut prng,
                      &user_secret_key,
                      credential.get_cred_ref(),
                      &user_public_key.as_bytes()).map_err(|e| error_to_jsvalue(e))?;
  Ok(CredentialCommitment { commitment })
}

#[wasm_bindgen]
pub fn wasm_credential_reveal(user_sk: &CredUserSecretKey,
                              credential: &Credential,
                              reveal_fields: JsValue)
                              -> Result<CredentialRevealSig, JsValue> {
  let mut prng = ChaChaRng::from_entropy();
  let reveal_fields: Vec<String> = reveal_fields.into_serde().unwrap();
  Ok(CredentialRevealSig { sig: credential_reveal(&mut prng,
                                                  &user_sk,
                                                  credential.get_cred_ref(),
                                                  &reveal_fields[..]).map_err(|e| {
                                                                       error_to_jsvalue(e)
                                                                     })? })
}

#[wasm_bindgen]
pub fn wasm_credential_verify(issuer_pub_key: &CredIssuerPublicKey,
                              attributes: JsValue,
                              reveal_sig: &CredentialRevealSig)
                              -> Result<(), JsValue> {
  let attributes: Vec<AttributeAssignment> = attributes.into_serde().unwrap();
  let attributes: Vec<(String, &[u8])> =
    attributes.iter()
              .map(|attr| (attr.name.clone(), attr.val.as_bytes()))
              .collect();
  credential_verify(issuer_pub_key,
                    &attributes,
                    &reveal_sig.get_sig_ref().sig_commitment,
                    &reveal_sig.get_sig_ref().pok).map_err(|e| error_to_jsvalue(e))?;
  Ok(())
}

/*
 * Copyright 2024 Fondazione LINKS
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.	
 *
 */

use std::{str::FromStr, fs::File, io::Write};
use anyhow::anyhow;
use anyhow::Context;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::{iota::{NetworkName, IotaDID}, prelude::IotaDocument, storage::JwsSignatureOptions, verification::MethodRelationship, document::verifiable::JwsVerificationOptions, credential::{Jwt, Subject, CredentialBuilder, Credential, JwtCredentialValidator, JwtCredentialValidationOptions, FailFast, JwtCredentialValidatorUtils}, did::DID, core::{FromJson, ToJson, json, Object, OneOrMany}};
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::Storage;
use identity_iota::verification::MethodScope;
use identity_iota::iota::IotaClientExt;
use identity_iota::iota::IotaIdentityClientExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_stronghold::StrongholdStorage;
use iota_sdk::{client::{api::GetAddressesOptions, stronghold::StrongholdAdapter}, types::block::output::AliasOutput, Url};
use iota_sdk::client::node_api::indexer::query_parameters::QueryParameter;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::crypto::keys::bip39;
use iota_sdk::types::block::address::Address;
use iota_sdk::types::block::address::Bech32Address;
use iota_sdk::types::block::address::Hrp;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;


// --------------------------------------------------

pub const DID_OID: &str = "1.2.840.20000.1.1";
pub const VC_OID: &str = "1.2.840.30000.1.1";

pub struct Wallet {
  client: Client,
  stronghold_storage: StrongholdStorage,
  address: Address,
  network: NetworkName,
  storage: Storage<StrongholdStorage, StrongholdStorage>
}

impl Wallet {

  pub const API_ENDPOINT: &str = "https://api.testnet.shimmer.network";
  pub const FAUCET_ENDPOINT: &str = "https://faucet.testnet.shimmer.network/api/enqueue";

  pub async fn setup(stronghold_path: &str, password: &str) -> anyhow::Result<Self> {
    let client = Client::builder().with_primary_node(Self::API_ENDPOINT, None)?.finish().await?;

    let stronghold = Self::setup_secret_manager(stronghold_path, password).await?;
    let stronghold_storage = StrongholdStorage::new(stronghold);
    

    let address = Self::request_funds_for_address(None, &client, stronghold_storage.as_secret_manager(), Self::FAUCET_ENDPOINT).await?;

    let network: NetworkName = client.network_name().await?;
    
    let storage: Storage<StrongholdStorage, StrongholdStorage> = Storage::new(stronghold_storage.clone(), stronghold_storage.clone());
    
    Ok(Self { client, stronghold_storage, address, network, storage/* , vc: None, did_document: None, fragment: None, peer_did_document: None */ })
  }


  async fn setup_secret_manager(stronghold_path: &str, password: &str) -> anyhow::Result<StrongholdAdapter> {
    // let path_exists = Path::new(&std::env::var("STRONGHOLD_SNAPSHOT_PATH").unwrap()).exists();

    // Setup Stronghold secret_manager
  let secret_manager = StrongholdSecretManager::builder()
        .password(password.to_owned())
        .build(stronghold_path)?;

    // if !path_exists {
    //     // Only required the first time, can also be generated with `manager.generate_mnemonic()?`
    //     let mnemonic = Mnemonic::from(std::env::var("MNEMONIC").unwrap());
    //     // The mnemonic only needs to be stored the first time
    //     secret_manager.store_mnemonic(mnemonic).await?;
    // }

    Ok(secret_manager)
  }


  // Generates an address from the given [`SecretManager`] and adds funds from the faucet.
  async fn request_funds_for_address(
    address: Option<&Bech32Address>,
    client: &Client,
    stronghold: &SecretManager,
    faucet_endpoint: &str,
  ) -> anyhow::Result<Address> {
    
    let address: Bech32Address = if address.is_none() {
        Self::get_address(client, stronghold).await?.clone()
    } else {
        address.unwrap().clone()
    };
    

    Self::request_faucet_funds(client, address, faucet_endpoint)
      .await
      .context("failed to request faucet funds")?;

    Ok(*address)
  }

  /// Initializes the [`SecretManager`] with a new mnemonic, if necessary,
  /// and generates an address from the given [`SecretManager`].
  async fn get_address(client: &Client, secret_manager: &SecretManager) -> anyhow::Result<Bech32Address> {
    let random: [u8; 32] = rand::random();
    let mnemonic = bip39::wordlist::encode(random.as_ref(), &bip39::wordlist::ENGLISH)
      .map_err(|err| anyhow::anyhow!(format!("{err:?}")))?;

    if let SecretManager::Stronghold(ref stronghold) = secret_manager {
      match stronghold.store_mnemonic(mnemonic).await {
        Ok(()) => (),
        Err(iota_sdk::client::stronghold::Error::MnemonicAlreadyStored) => (),
        Err(err) => anyhow::bail!(err),
      }
    } else {
      anyhow::bail!("expected a `StrongholdSecretManager`");
    }

    let bech32_hrp: Hrp = client.get_bech32_hrp().await?;
    let address: Bech32Address = secret_manager
      .generate_ed25519_addresses(
        GetAddressesOptions::default()
          .with_range(0..1)
          .with_bech32_hrp(bech32_hrp),
      )
      .await?[0];

    Ok(address)
  }

  /// Requests funds from the faucet for the given `address`.
  async fn request_faucet_funds(client: &Client, address: Bech32Address, faucet_endpoint: &str) -> anyhow::Result<()> {
    iota_sdk::client::request_funds_from_faucet(faucet_endpoint, &address).await?;

    tokio::time::timeout(std::time::Duration::from_secs(45), async {
      loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let balance = Self::get_address_balance(client, &address)
          .await
          .context("failed to get address balance")?;
        if balance > 0 {
          break;
        }
      }
      Ok::<(), anyhow::Error>(())
    })
    .await
    .context("maximum timeout exceeded")??;

    Ok(())
  }

  /// Returns the balance of the given Bech32-encoded `address`.
  async fn get_address_balance(client: &Client, address: &Bech32Address) -> anyhow::Result<u64> {
    let output_ids = client
      .basic_output_ids(vec![
        QueryParameter::Address(address.to_owned()),
        QueryParameter::HasExpiration(false),
        QueryParameter::HasTimelock(false),
        QueryParameter::HasStorageDepositReturn(false),
      ])
      .await?;

    let outputs = client.get_outputs(&output_ids).await?;

    let mut total_amount = 0;
    for output_response in outputs {
      total_amount += output_response.output().amount();
    }

    Ok(total_amount)
  }

}

pub struct Did {
  did_document: IotaDocument,
  fragment: String
}

impl Did {
  
  pub async fn did_create(wallet: &Wallet) -> anyhow::Result<Self>{

    // Create a new DID document with a placeholder DID.
    // The DID will be derived from the Alias Id of the Alias Output after publishing.
    //let mut document: IotaDocument = IotaDocument::new(&wallet.network);
    let mut document = IotaDocument::new(&wallet.network);

    // Insert a new Ed25519 verification method in the DID document.
    //let fragment = document
    let fragment = document
    .generate_method(
      &wallet.storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      None,
      MethodScope::VerificationMethod,
    )
    .await?;

    // Attach a new method relationship to the inserted method.
    document.attach_method_relationship(
      document.id().to_url().join(format!("#{fragment}"))?,
      MethodRelationship::Authentication,
    )?;

    // Construct an Alias Output containing the DID document, with the wallet address
    // set as both the state controller and governor.
    let alias_output: AliasOutput = wallet.client.new_did_output(wallet.address, document, None).await?;

    // Publish the Alias Output and get the published DID document.
    let did_document = wallet.client.publish_did_output(wallet.stronghold_storage.as_secret_manager(), alias_output).await?;
    let doc_json = did_document.to_json()?;

    println!{"creating did document {}", doc_json};
    
    Self::write_on_file(DID_OID, &fragment.as_str(), &doc_json, "did_document.json")?;

    Ok(Self { did_document, fragment })

  }

  pub async fn did_resolve(wallet: &mut Wallet, did: &str) -> anyhow::Result<Self>{
    let iota_did = IotaDID::from_str(did)?;
    let did_document: IotaDocument = wallet.client.resolve_did(&iota_did).await?;

    if did_document.metadata.deactivated.is_some_and(|v| v == true) {
      return Err(anyhow!("Deactivated DID Document"));
    }

    let fragment = String::from("Hello");
    Ok(Self { did_document, fragment} )
  }

//   pub async fn update(&mut self) -> anyhow::Result<()> {
    
//     let (did_document, fragment) = Self::read_did_document_from_file("did_document.json", "fragment")?;

//     let mut did_document = IotaDocument::from_json(&did_document)?;

//     // Insert a new Ed25519 verification method in the DID document.
//     let new_fragment: String = did_document
//       .generate_method(
//         &self.storage,
//         JwkMemStore::ED25519_KEY_TYPE,
//         JwsAlgorithm::EdDSA,
//         None,
//         MethodScope::VerificationMethod,
//       )
//       .await?;

//     // Attach a new method relationship to the inserted method.
//     did_document.attach_method_relationship(
//       &did_document.id().to_url().join(format!("#{new_fragment}"))?,
//       MethodRelationship::Authentication,
//     )?;

//     did_document.metadata.updated = Some(Timestamp::now_utc());

//     // Remove a verification method.
//     let original_method: DIDUrl = did_document.resolve_method(&fragment, None).unwrap().id().clone();
//     did_document.purge_method(&self.storage, &original_method).await.unwrap();

//     // Resolve the latest output and update it with the given document.
//     let alias_output: AliasOutput = self.client.update_did_output(did_document.clone()).await?;

//     // Because the size of the DID document increased, we have to increase the allocated storage deposit.
//     // This increases the deposit amount to the new minimum.
//     let rent_structure: RentStructure = self.client.get_rent_structure().await?;
//     let alias_output: AliasOutput = AliasOutputBuilder::from(&alias_output)
//       .with_minimum_storage_deposit(rent_structure)
//       .finish()?;

//     // Publish the updated Alias Output.
//     let updated_document: IotaDocument = self.client.publish_did_output(self.stronghold_storage.as_secret_manager(), alias_output).await?;
    
//     let doc_json = updated_document.to_json()?;
//     Self::write_on_file(&doc_json, "did_document.json")?;
//     Self::write_on_file(&fragment, "fragment")?;

//     Ok(())
//   }

//   pub async fn deactivate(&self) -> anyhow::Result<()> {
//     let iota_did = match &self.did_document {
//       Some(document) => document.id().clone(),
//       None => return Err(anyhow!("Did Document NOT found!".to_owned())),
//     };

//     let deactivated_output: AliasOutput = self.client.deactivate_did_output(&iota_did).await?;

//     // Optional: reduce and reclaim the storage deposit, sending the tokens to the state controller.
//     let rent_structure = self.client.get_rent_structure().await?;
//     let deactivated_output = AliasOutputBuilder::from(&deactivated_output)
//       .with_minimum_storage_deposit(rent_structure)
//       .finish()?;

//     // Publish the deactivated DID document.
//     let _ = self.client.publish_did_output(self.stronghold_storage.as_secret_manager(), deactivated_output).await?;

//     Ok(())
    
//   }

  pub async fn get_did(&self) -> anyhow::Result<String> {

      println!("Ayo: {} {}", self.fragment.to_owned(), &self.did_document.to_json()?);
      Ok(self.fragment.to_owned() + " " + &self.did_document.to_json()?)
  }

  pub fn set_did(did_document: &str, fragment: &str) -> anyhow::Result<Self> {
     let did_document = IotaDocument::from_json(did_document)?;
     let fragment = fragment.to_owned();

     //println!("setting DID Document: {}", did_document.to_json()?);
     //println!("Setitng fragment: {}", fragment);

     Ok(Self {did_document, fragment})
  }

  fn write_on_file(oid: &str, fragment: &str, did_document: &str, file_path: &str) -> anyhow::Result<()> {

    // Create a new file, or truncate the existing file
    let mut file = File::create(file_path)?;

    // Write the data to the file
    file.write_all(oid.as_bytes())?;
    file.write_all(" ".as_bytes())?;
    file.write_all(fragment.as_bytes())?;
    file.write_all(" ".as_bytes())?;
    file.write_all(did_document.as_bytes())?;

    // Flush the buffer to ensure the data is written immediately
    file.flush()?;

    Ok(())
  }

  pub async fn did_sign(&self, wallet: &Wallet, message: &[u8]) -> anyhow::Result<String>{     
    let jws = self.did_document.as_ref().create_jws(&wallet.storage, &self.fragment, message, &JwsSignatureOptions::default()).await?;
    println!("Signature length: {}", jws.as_str().to_string().len());
    println!("JWT: {}", jws.as_str().to_string());
    Ok(jws.as_str().to_string())
  }

  pub async fn did_verify(&self, jws: &str) -> anyhow::Result<()> {
      //let jws = Jws::new(jws.to_owned());
      println!("qui c'è {}", &self.did_document.to_json()?);
      println!("{}", jws);
      let result = self.did_document.as_ref()
      .verify_jws(&jws, None, &EdDSAJwsVerifier::default(), &JwsVerificationOptions::default());
    
      match result {
          Ok(_) => { println!("Success!\n");
            Ok(())}, // Verification successful, return Ok
          Err(err) => { println!("Error\n");
            Err(anyhow::Error::msg(format!("JWS verification failed: {}", err)))},
      }     
  }

}

pub struct Vc {
  vc: Jwt
}

impl Vc {

  pub async fn vc_create(wallet: &mut Wallet, did: &Did, name: &str) -> anyhow::Result<Self>{
        
    // Create Issuer document
    // Create a new DID document with a placeholder DID.
    // The DID will be derived from the Alias Id of the Alias Output after publishing.
    let mut issuer_document: IotaDocument = IotaDocument::new(&wallet.network);
 
    // Insert a new Ed25519 verification method in the DID document.
    let fragment_issuer = issuer_document
    .generate_method(
      &wallet.storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      None,
      MethodScope::VerificationMethod,
    )
    .await?;

    // Attach a new method relationship to the inserted method.
    issuer_document.attach_method_relationship(
      &issuer_document.id().to_url().join(format!("#{fragment_issuer}"))?,
      MethodRelationship::AssertionMethod,
    )?;

    // Construct an Alias Output containing the DID document, with the wallet address
    // set as both the state controller and governor.
    let alias_output: AliasOutput = wallet.client.new_did_output(wallet.address, issuer_document, None).await?;

    // Publish the Alias Output and get the published DID document.
    let issuer_document: IotaDocument = wallet.client.publish_did_output(wallet.stronghold_storage.as_secret_manager(), alias_output).await?;

    let subject: Subject = Subject::from_json_value(json!({
      "id": did.did_document.as_ref().id().to_string(),
      "name": name
    }))?;
  
    // Build credential using subject above and issuer.
    let credential: Credential = CredentialBuilder::default()
      .id(Url::parse("https://example.edu/credentials/3732")?.into())
      .issuer(Url::parse(&issuer_document.id().to_string())?)
      .type_("WebCredential")
      .subject(subject)
      .build()?;
  
    let credential_jwt: Jwt = issuer_document
      .create_credential_jwt(
        &credential,
        &wallet.storage,
        &fragment_issuer,
        &JwsSignatureOptions::default(),
        None,
      )
      .await?;
  
    let vc = credential_jwt.clone();
    Self::write_on_file(VC_OID,credential_jwt.as_str(), "credential.jwt")?;

    Ok(Self {vc})
  }

  pub async fn vc_verify(wallet: &Wallet, peer_vc: &str) -> anyhow::Result<Did> {

    let vc = Jwt::from(peer_vc.to_owned());

    let issuer: IotaDID = JwtCredentialValidatorUtils::extract_issuer_from_jwt(&vc)?;

    let issuer_document: IotaDocument = wallet.client.resolve_did(&issuer).await?;

    if issuer_document.metadata.deactivated.is_some_and(|v| v == true) {
      return Err(anyhow!("Deactivated DID Document"));
    }

    let decoded_vc = JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
    .validate::<_, Object>(
      &vc,
      &issuer_document,
      &JwtCredentialValidationOptions::default(),
      FailFast::FirstError,
    )
    .unwrap();

    let peer_did = match &decoded_vc.credential.credential_subject {
      OneOrMany::One(ref credential_subject) => credential_subject.id.as_ref().and_then(|i| Some(i.as_str())),
      OneOrMany::Many(subjects) => {
        // need to check the case where the Many variant holds a vector of exactly one subject
        if let [credential_subject] = subjects.as_slice() {
          credential_subject.id.as_ref().and_then(|i| Some(i.as_str()))
        } else {
          // zero or > 1 subjects is interpreted to mean that the holder is not the subject
          None
        }
      }
    };

    let peer_did = match peer_did {
        Some(h) => IotaDID::from_str(h)?,
        None => return Err(anyhow!("holder DID not found!".to_owned())),
    };

    let peer_did_doc: IotaDocument = wallet.client.resolve_did(&peer_did).await?;
    if peer_did_doc.metadata.deactivated.is_some_and(|v| v == true) {
      return Err(anyhow!("Deactivated DID Document"));
    }

    let fragment = String::from("Hello");
    let peer_did = Did {did_document : peer_did_doc, fragment : fragment};

    Ok(peer_did)
  }

  pub fn get_vc(&self) -> anyhow::Result<String> {
    Ok(self.vc.as_str().to_string())
  }

  pub fn set_vc(vc: &str) -> anyhow::Result<Self>{
    let vc = Jwt::from(vc.to_owned());
    Ok(Self {vc})
  }

  fn write_on_file(oid: &str, vc: &str, file_path: &str) -> anyhow::Result<()> {

    // Create a new file, or truncate the existing file
    let mut file = File::create(file_path)?;

    // Write the data to the file
    file.write_all(oid.as_bytes())?;
    file.write_all(" ".as_bytes())?;
    file.write_all(vc.as_bytes())?;

    // Flush the buffer to ensure the data is written immediately
    file.flush()?;

    Ok(())
  }

}


  


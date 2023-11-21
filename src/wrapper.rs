use std::{env, path::{PathBuf, Path}, str::FromStr};
use anyhow::anyhow;
use anyhow::Context;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::{iota::{NetworkName, IotaDID}, prelude::IotaDocument, storage::{JwkStorage, KeyId, JwsSignatureOptions}, verification::{jwk::Jwk, jws::Decoder, MethodRelationship}, document::{self, verifiable::JwsVerificationOptions}, credential::Jws, did::{DID, DIDUrl}, core::Timestamp};
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::Storage;
use identity_iota::verification::MethodScope;
use identity_iota::iota::IotaClientExt;
use identity_iota::iota::IotaIdentityClientExt;

use identity_iota::storage::JwkMemStore;
use identity_iota::storage::KeyIdMemstore;


use identity_iota::verification::jws::JwsAlgorithm;
use iota_sdk::{client::api::GetAddressesOptions, crypto::keys::bip39::Mnemonic, types::block::output::{AliasOutput, RentStructure, AliasOutputBuilder}};
use iota_sdk::client::node_api::indexer::query_parameters::QueryParameter;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::crypto::keys::bip39;
use iota_sdk::types::block::address::Address;
use iota_sdk::types::block::address::Bech32Address;
use iota_sdk::types::block::address::Hrp;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;



pub async fn setup_secret_manager() -> anyhow::Result<SecretManager> {
    // let path_exists = Path::new(&std::env::var("STRONGHOLD_SNAPSHOT_PATH").unwrap()).exists();

    // Setup Stronghold secret_manager
    let secret_manager = StrongholdSecretManager::builder()
        .password(std::env::var("STRONGHOLD_PASSWORD").unwrap())
        .build(std::env::var("STRONGHOLD_SNAPSHOT_PATH").unwrap())?;

    // if !path_exists {
    //     // Only required the first time, can also be generated with `manager.generate_mnemonic()?`
    //     let mnemonic = Mnemonic::from(std::env::var("MNEMONIC").unwrap());
    //     // The mnemonic only needs to be stored the first time
    //     secret_manager.store_mnemonic(mnemonic).await?;
    // }

    Ok(SecretManager::Stronghold(secret_manager))
}


/// Generates an address from the given [`SecretManager`] and adds funds from the faucet.
pub async fn request_funds_for_address(
    address: Option<&Bech32Address>,
    client: &Client,
    stronghold: &SecretManager,
    faucet_endpoint: &str,
  ) -> anyhow::Result<Address> {
    
    let address: Bech32Address = if address.is_none() {
        get_address(client, stronghold).await?.clone()
    } else {
        address.unwrap().clone()
    };
    
  
    request_faucet_funds(client, address, faucet_endpoint)
      .await
      .context("failed to request faucet funds")?;
  
    Ok(*address)
  }
  
  /// Initializes the [`SecretManager`] with a new mnemonic, if necessary,
  /// and generates an address from the given [`SecretManager`].
  pub async fn get_address(client: &Client, secret_manager: &SecretManager) -> anyhow::Result<Bech32Address> {
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
  
        let balance = get_address_balance(client, &address)
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






//--------------------------------------------------

pub struct DidOperations {
  client: Client,
  secret_manager: SecretManager,
  address: Address,
  network: NetworkName,
  storage: Storage<JwkMemStore, KeyIdMemstore>
}


impl DidOperations {

  pub const API_ENDPOINT: &str = "https://api.testnet.shimmer.network";
  pub const FAUCET_ENDPOINT: &str = "https://faucet.testnet.shimmer.network/api/enqueue";


  pub async fn setup() -> anyhow::Result<Self> {
    dotenv::dotenv().ok();
    env_logger::init();
    

    let client = Client::builder().with_primary_node(Self::API_ENDPOINT, None)?.finish().await?;

    let secret_manager = setup_secret_manager().await?;

    let address = request_funds_for_address(None, &client, &secret_manager, Self::FAUCET_ENDPOINT).await?;

    let network: NetworkName = client.network_name().await?;
    // let network: NetworkName = NetworkName::try_from(client.get_network_name().await?)?;

    let storage: Storage<JwkMemStore, KeyIdMemstore> = Storage::<JwkMemStore, KeyIdMemstore>::new(JwkMemStore::new(), KeyIdMemstore::new());

    Ok(Self { client, secret_manager, address, network, storage })
  }


  pub async fn sign(&self, message: &[u8], did_document: &IotaDocument, fragment: &str) -> anyhow::Result<Jws>{
    let jws = did_document.create_jws(&self.storage, fragment, message, &JwsSignatureOptions::default()).await?;
    Ok(jws)
  }

  pub async fn verify(&self, jws: &Jws, did_document: &IotaDocument) -> anyhow::Result<()> {
    let result = did_document.verify_jws(jws, None, &EdDSAJwsVerifier::default(), &JwsVerificationOptions::default());

    match result {
        Ok(_) => Ok(()), // Verification successful, return Ok
        Err(err) => Err(anyhow::Error::msg(format!("JWS verification failed: {}", err))),
    }
  }


  
  pub async fn create(&self, relationship: MethodRelationship) -> anyhow::Result<(IotaDocument, String)>{

    // Create a new DID document with a placeholder DID.
    // The DID will be derived from the Alias Id of the Alias Output after publishing.
    let mut document: IotaDocument = IotaDocument::new(&self.network);

    
    // Insert a new Ed25519 verification method in the DID document.
    let fragment = document
    .generate_method(
      &self.storage,
      JwkMemStore::ED25519_KEY_TYPE,
      JwsAlgorithm::EdDSA,
      None,
      MethodScope::VerificationMethod,
    )
    .await?;


    // Attach a new method relationship to the inserted method.
    document.attach_method_relationship(
      &document.id().to_url().join(format!("#{fragment}"))?,
      relationship,
    )?;


      // Construct an Alias Output containing the DID document, with the wallet address
    // set as both the state controller and governor.
    let alias_output: AliasOutput = self.client.new_did_output(self.address, document, None).await?;

    // Publish the Alias Output and get the published DID document.
    let document: IotaDocument = self.client.publish_did_output(&self.secret_manager, alias_output).await?;

    Ok((document, fragment))
  }


  pub async fn resolve(&self, did: &str) -> anyhow::Result<IotaDocument>{
    let iota_did = IotaDID::from_str(did)?;
    let document: IotaDocument = self.client.resolve_did(&iota_did).await?;

    match document.metadata.deactivated {
      Some(true) => Err(anyhow!("Deactivated DID Document")),
      Some(false) | None => Ok(document)
    }
    
  }


  pub async fn update(&self, did: &str, fragment: &str, relationship: MethodRelationship) -> anyhow::Result<(IotaDocument, String)> {
    
    let mut did_document = self.resolve(did).await?; 
    
    // Insert a new Ed25519 verification method in the DID document.
    let new_fragment: String = did_document
      .generate_method(
        &self.storage,
        JwkMemStore::ED25519_KEY_TYPE,
        JwsAlgorithm::EdDSA,
        None,
        MethodScope::VerificationMethod,
      )
      .await?;

    // Attach a new method relationship to the inserted method.
    did_document.attach_method_relationship(
      &did_document.id().to_url().join(format!("#{new_fragment}"))?,
      relationship,
    )?;

    did_document.metadata.updated = Some(Timestamp::now_utc());

    // Remove a verification method.
    let original_method: DIDUrl = did_document.resolve_method(fragment, None).unwrap().id().clone();
    did_document.purge_method(&self.storage, &original_method).await.unwrap();

    // Resolve the latest output and update it with the given document.
    let alias_output: AliasOutput = self.client.update_did_output(did_document.clone()).await?;

    // Because the size of the DID document increased, we have to increase the allocated storage deposit.
    // This increases the deposit amount to the new minimum.
    let rent_structure: RentStructure = self.client.get_rent_structure().await?;
    let alias_output: AliasOutput = AliasOutputBuilder::from(&alias_output)
      .with_minimum_storage_deposit(rent_structure)
      .finish()?;

    // Publish the updated Alias Output.
    let updated_document: IotaDocument = self.client.publish_did_output(&self.secret_manager, alias_output).await?;
  
    Ok((updated_document, new_fragment))
  }

  
  pub async fn deactivate(&self, did: &str) -> anyhow::Result<()> {
    let iota_did = IotaDID::from_str(did)?;
    let deactivated_output: AliasOutput = self.client.deactivate_did_output(&iota_did).await?;

    // Optional: reduce and reclaim the storage deposit, sending the tokens to the state controller.
    let rent_structure = self.client.get_rent_structure().await?;
    let deactivated_output = AliasOutputBuilder::from(&deactivated_output)
      .with_minimum_storage_deposit(rent_structure)
      .finish()?;

    // Publish the deactivated DID document.
    let _ = self.client.publish_did_output(&self.secret_manager, deactivated_output).await?;

    Ok(())
    
  }

}
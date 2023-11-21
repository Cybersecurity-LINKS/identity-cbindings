use identity_iota::{verification::MethodRelationship, did::DID};
use wrapper::DidOperations;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let operations = DidOperations::setup().await?;

    let (document, fragment) = operations.create(MethodRelationship::Authentication).await?;
    println!("DID document: {document:#}");

    let (updated_document, fragment_2) = operations.update(document.id().as_str(), &fragment, MethodRelationship::Authentication).await?;
    println!("Updated DID document: {updated_document:#}");

    let resolved_document = operations.resolve(updated_document.id().as_str()).await?;
    println!("Resolved DID document: {resolved_document:#}");


    let message = b"Message to be signed";

    //TEST: This should fail, because the fragment is incorrect
    operations.sign(message, &resolved_document, &fragment).await.expect_err("This should fail, wrong fragment!");

    let jws = operations.sign(message, &resolved_document, &fragment_2).await?;
    println!("JWS: {}", jws.as_str());

    operations.verify(&jws, &resolved_document).await?;


    //Deactivate DID
    operations.deactivate(resolved_document.id().as_str()).await?;
    println!("DID Deactivated");
    Ok(())
}

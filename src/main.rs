use identity_iota::verification::MethodRelationship;
use wrapper::DidOperations;

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    //Server
    let mut operations_server = DidOperations::setup("./server.stronghold", "server").await?;

    operations_server.create(MethodRelationship::Authentication).await?;

    // operations_server.update(MethodRelationship::Authentication).await?;

    //Should be done by OpenSSL
    let (document, fragment) = DidOperations::read_did_document_from_file("did_document.json", "fragment")?;
    
    operations_server.set_did_document(&document, &fragment)?;


    operations_server.vc_create("www.server.com").await?;

    //read from file

    let vc = DidOperations::read_vc_from_file("credential.jwt")?;

    //send to client by OpenSSL


    let message = b"CertificateVerify";

    let jws = operations_server.sign(message).await?;


    //Client
    let mut operations_client = DidOperations::setup("./client.stronghold", "client").await?;

    operations_client.vc_verify(&vc).await?;

    operations_client.verify(&jws).await?;



    //Deactivate server DID
    operations_server.deactivate().await?;
    println!("DID Deactivated");

    Ok(())
}

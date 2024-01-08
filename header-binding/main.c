#include <stdio.h>
#include "identity.h"
#include <string.h>


char* read_file(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error wening file");
        return NULL;
    }

    // Seek to the end of the file to determine its size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the entire file content plus null terminator
    char* file_content = (char*)malloc(file_size + 1);
    if (!file_content) {
        perror("Error allocating memory");
        fclose(file);
        return NULL;
    }

    // Read the entire file into memory
    size_t bytes_read = fread(file_content, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        perror("Error reading file");
        free(file_content);
        fclose(file);
        return NULL;
    }

    // Null-terminate the string
    file_content[file_size] = '\0';

    fclose(file);
    return file_content;
}

int main() {
    
    /* WALLET SETUP */
    Wallet *w = setup("./server.stronghold", "server");
    printf("Done setting up the wallet \n");
    
    /* CREATE A DID DOCUMENT */
    Did *did = did_create(w);
    const char *did_document = did_get(did);
    printf("\nDID Document: %s\n", did_document);

    /* SIGN AN ARBITRARY MESSAGE WITH THE DID KEY */
    /* char s[] = "Hello";
    const char *sign = did_sign(w, did, (unsigned char*)s, strlen(s));
    printf("Signature: %s\n", sign); */

    /* RESOLVE THE DID */
    //TODO 
    // I should read the DID Document id from the file
    /* did = did_resolve(w, "did:iota:rms:0xf66b6e320a8b794c473003cebb6534970e63d953029d0bbf48f29168aef2e079"); */
    
    /* VERIFY THE SIGNATURE */
    //TODO
    /* rvalue_t ret = did_verify(did, signature);
    printf("return code: %d\n", ret.code); */

    /* READ A DID DOCUMENT FROM FILE AND SET IT */
    /* char* document = read_file("did_document.json");
    char* fragment = read_file("fragment");
    Did *did2 = did_set(did_document, fragment);
    const char *did_document2 = did_get(did2);
    printf("The content of the set DID Document: %s\n", did_document2); */

    /* CREATE A VC */
    VC *vc = vc_create(w, did, "www.server.com");

    /* GET THE VC AS A JWT */
    const char* vc_jwt = vc_get(vc);
    printf("\nVC as JWT:\n %s", vc_jwt);

    /* READ VC FROM FILE AND SET IT */
    /* char* vc_jwt2 = read_file("credential.jwt");
    VC *vc2 = vc_set(vc_jwt2); */

    /* VERIFY THE VC */
    Did *peer_did = vc_verify(w, vc_jwt);
    const char *peer_did_document = did_get(peer_did);
    printf("\nThe content of the peer DID document: %s\n", peer_did_document);

    return 0;
}


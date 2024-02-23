/*
 * Copyright 2024 Fondazione LINKS.
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
    if(w == NULL) {
        fprintf(stderr, "Error setting up the wallet\n");
        return -1;
    }
    printf("Done setting up the wallet \n");
    
    /* CREATE A DID DOCUMENT */
    Did *did = did_create(w);
    const char *did_document = get_did(did);
    printf("\nDID Document: %s\n", did_document);

    /* SIGN AN ARBITRARY MESSAGE WITH THE DID KEY */
    char s[] = "Hello";
    const char *sign = did_sign(w, did, (unsigned char*)s, strlen(s));
    printf("Signature: %s\n", sign);

    /* RESOLVE THE DID */
    //TODO 
    // I should read the DID Document id from the file
    did = did_resolve(w, "did:iota:rms:0xf66b6e320a8b794c473003cebb6534970e63d953029d0bbf48f29168aef2e079");
    
    /* VERIFY THE SIGNATURE */
    //TODO

    /* READ A DID DOCUMENT FROM FILE AND SET IT */
    char* document = read_file("did_document.json");
    char* fragment = read_file("fragment");
    Did *did2 = set_did(did_document, fragment);
    const char *did_document2 = get_did(did2);
    printf("The content of the set DID Document: %s\n", did_document2);

    /* CREATE A VC */
    Vc *vc = vc_create(w, did, "www.server.com");

    /* GET THE VC AS A JWT */
    const char* vc_jwt = get_vc(vc);
    printf("\nVC as JWT:\n %s", vc_jwt);

    /* READ VC FROM FILE AND SET IT */
    char* vc_jwt2 = read_file("credential.jwt");
    Vc *vc2 = set_vc(vc_jwt2);

    /* VERIFY THE VC */
    Did *peer_did = vc_verify(w, vc_jwt);
    const char *peer_did_document = get_did(peer_did);
    printf("\nThe content of the peer DID document: %s\n", peer_did_document);

    return 0;
}


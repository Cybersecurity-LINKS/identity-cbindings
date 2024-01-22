#ifndef IDENTITY_H
# define IDENTITY_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Did Did;

typedef struct Vc Vc;

typedef struct Wallet Wallet;

typedef struct rvalue_t {
  uint32_t code;
} rvalue_t;

struct Wallet *setup(const char *stronghold_path, const char *password);

struct Did *did_create(const struct Wallet *wallet);

struct Did *did_resolve(struct Wallet *wallet, const char *did);

const char *get_did(const struct Did *did);

/**
 * # Safety
 * The ptr should be a valid pointer to the string allocated by rust
 */
struct Did *set_did(const char *document, const char *fragment);

char *did_sign(const struct Wallet *wallet,
               const struct Did *did,
               uint8_t *message,
               uintptr_t message_len);

struct rvalue_t did_verify(const struct Did *did, const char *jws);

struct Vc *vc_create(struct Wallet *wallet, const struct Did *did, const char *name);

struct Did *vc_verify(const struct Wallet *wallet, const char *peer_vc);

const char *get_vc(const struct Vc *vc);

struct Vc *set_vc(const char *vc_jwt);

#endif
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Did Did;

typedef struct VC VC;

typedef struct Wallet Wallet;

typedef struct rvalue_t {
  uint32_t code;
} rvalue_t;

struct Wallet *setup(const char *stronghold_path, const char *password);

struct Did *did_create(const struct Wallet *wallet);

struct Did *did_resolve(struct Wallet *wallet, const char *did);

const char *did_get(const struct Did *did);

/**
 * # Safety
 * The ptr should be a valid pointer to the string allocated by rust
 */
struct Did *did_set(const char *document, const char *fragment);

const char *did_sign(const struct Wallet *wallet,
                     const struct Did *did,
                     uint8_t *message,
                     uintptr_t message_len);

struct rvalue_t did_verify(const struct Did *did, const char *jws);

struct VC *vc_create(struct Wallet *wallet, const struct Did *did, const char *name);

struct Did *vc_verify(const struct Wallet *wallet, const char *peer_vc);

const char *vc_get(const struct VC *vc);

struct VC *vc_set(const char *vc_jwt);

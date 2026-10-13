/* See LICENSE for licensing information */

/**
 * \file darknames.h
 * \brief Header for darknames.c
 **/

#ifndef TOR_DARKNAMES_H
#define TOR_DARKNAMES_H

#include "lib/cc/torint.h"
#include "lib/testsupport/testsupport.h"

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/** The shortest and the longest that a name can be. A service address is
 * longer than the longest name, so the two are never mistaken. */
#define DARKNAME_MIN_LEN 3
#define DARKNAME_MAX_LEN 32

/** What became of looking a name up. */
typedef enum darkname_result_t {
  /** The name is registered, and here is the address it points to. */
  DARKNAME_FOUND,
  /** There is a snapshot to trust, and it does not list this name. */
  DARKNAME_NOT_FOUND,
  /** There is no snapshot to trust right now: none was fetched, or the one
   * that was is out of date. Whether the name exists is not known. */
  DARKNAME_UNAVAILABLE,
} darkname_result_t;

bool darknames_name_is_valid(const char *name);
bool darknames_root_key_is_valid(const char *base64);
darkname_result_t darknames_lookup(const char *name, char *address_out);

const char *darknames_get_pin(const char *name);
void darknames_note_connected(const char *name, const char *address);
bool darknames_forget_pin(const char *name);

void darknames_free_all(void);

#ifdef DARKNAMES_PRIVATE

struct ed25519_public_key_t;

/** What we remember of the last snapshot that we accepted, so as not to
 * take an older one after it. */
typedef struct darknames_freshness_t {
  uint64_t head_index;
  uint64_t created;
} darknames_freshness_t;

typedef struct darknames_snapshot_t darknames_snapshot_t;

STATIC darknames_snapshot_t *darknames_snapshot_parse(
                                const char *text, size_t len,
                                const struct ed25519_public_key_t *root_key,
                                time_t now,
                                const darknames_freshness_t *accepted,
                                const char **problem_out);
STATIC darkname_result_t darknames_snapshot_lookup(
                                const darknames_snapshot_t *snapshot,
                                const char *name, time_t now,
                                char *address_out);
STATIC int darknames_snapshot_n_names(const darknames_snapshot_t *snapshot);
STATIC void darknames_snapshot_free_(darknames_snapshot_t *snapshot);
#define darknames_snapshot_free(snapshot) \
  FREE_AND_NULL(darknames_snapshot_t, darknames_snapshot_free_, (snapshot))

#endif /* defined(DARKNAMES_PRIVATE) */

#endif /* !defined(TOR_DARKNAMES_H) */

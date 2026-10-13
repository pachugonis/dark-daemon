/* See LICENSE for licensing information */

/**
 * \file test_dark.c
 * \brief Tests for what makes this a Dark build: things that tor does not do
 *   upstream, or that must never happen on this network.
 */

#define CIRCUITLIST_PRIVATE
#define CONFIG_PRIVATE
#define CONNECTION_PRIVATE
#define DARKNAMES_PRIVATE
#define PROCESS_DESCS_PRIVATE

#include "core/or/or.h"
#include "test/test.h"
#include "test/log_test_helpers.h"

#include "app/config/config.h"
#include "app/config/or_options_st.h"
#include "core/mainloop/connection.h"
#include "core/or/circuitlist.h"
#include "core/or/connection_edge.h"
#include "core/or/entry_connection_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/policies.h"
#include "core/or/protover.h"
#include "core/or/relay.h"
#include "core/or/relay_msg_st.h"
#include "core/or/socks_request_st.h"
#include "feature/client/addressmap.h"
#include "feature/darknames/darknames.h"
#include "feature/hs/hs_cache.h"
#include "feature/hs/hs_common.h"
#include "feature/dirauth/process_descs.h"
#include "feature/nodelist/routerinfo.h"
#include "feature/nodelist/routerinfo_st.h"
#include "feature/relay/routermode.h"
#include "lib/crypt_ops/crypto_curve25519.h"
#include "lib/crypt_ops/crypto_ed25519.h"
#include "lib/crypt_ops/crypto_format.h"
#include "lib/crypt_ops/crypto_rsa.h"
#include "lib/encoding/confline.h"
#include "lib/fs/dir.h"
#include "lib/fs/files.h"
#include "lib/wallclock/approx_time.h"

#include "test/dark_names_vectors.inc"

/* What the last cell sent from the edge of a circuit was. */
static int n_cells_sent;
static streamid_t sent_stream_id;
static uint8_t sent_command;
static uint8_t sent_end_reason;

static int
mock_relay_send_command_from_edge(streamid_t stream_id, circuit_t *circ,
                                  uint8_t relay_command, const char *payload,
                                  size_t payload_len,
                                  crypt_path_t *cpath_layer,
                                  const char *filename, int lineno)
{
  (void)circ;
  (void)cpath_layer;
  (void)filename;
  (void)lineno;

  ++n_cells_sent;
  sent_stream_id = stream_id;
  sent_command = relay_command;
  sent_end_reason = (payload && payload_len) ? (uint8_t)payload[0] : 0;
  return 0;
}

/** Set up <b>msg</b> as a relay message of type <b>command</b> on stream
 * <b>stream_id</b>, carrying the NUL-terminated string <b>body</b>. */
static void
make_relay_msg(relay_msg_t *msg, uint8_t command, streamid_t stream_id,
               const char *body)
{
  memset(msg, 0, sizeof(*msg));
  msg->command = command;
  msg->stream_id = stream_id;
  msg->body = (const uint8_t *)body;
  msg->length = (uint16_t)(strlen(body) + 1);
}

/** The exit policy of a relay is reject-all, whatever the options say. */
static void
test_dark_exit_policy_ignores_options(void *arg)
{
  (void)arg;
  or_options_t *options = options_new();
  smartlist_t *policy = NULL;

  /* Everything that makes an upstream relay into an exit. */
  options->ExitRelay = 1;
  options->IPv6Exit = 1;
  options->ReducedExitPolicy = 1;
  config_line_append(&options->ExitPolicy, "ExitPolicy", "accept *:*");

  tt_int_op(policies_parse_exit_policy_from_options(options, NULL, NULL,
                                                    &policy),
            OP_EQ, 0);
  tt_assert(policy);
  tt_assert(policy_is_reject_star(policy, AF_INET, 1));
  tt_assert(policy_is_reject_star(policy, AF_INET6, 1));

 done:
  addr_policy_list_free(policy);
  or_options_free(options);
}

/** A relay refuses a BEGIN cell on an OR circuit, before looking at the
 * address in it. */
static void
test_dark_relay_refuses_begin(void *arg)
{
  (void)arg;
  or_circuit_t *or_circ = NULL;
  relay_msg_t msg;

  MOCK(relay_send_command_from_edge_, mock_relay_send_command_from_edge);

  /* Be a relay: a client refuses BEGIN cells already, on another branch. */
  get_options_mutable()->ORPort_set = 1;
  tt_assert(server_mode(get_options()));

  or_circ = or_circuit_new(0, NULL);
  TO_CIRCUIT(or_circ)->purpose = CIRCUIT_PURPOSE_OR;
  make_relay_msg(&msg, RELAY_COMMAND_BEGIN, 7, "example.com:80");

  tt_int_op(connection_exit_begin_conn(&msg, TO_CIRCUIT(or_circ)), OP_EQ, 0);

  tt_int_op(n_cells_sent, OP_EQ, 1);
  tt_int_op(sent_stream_id, OP_EQ, 7);
  tt_int_op(sent_command, OP_EQ, RELAY_COMMAND_END);
  tt_int_op(sent_end_reason, OP_EQ, END_STREAM_REASON_EXITPOLICY);
  /* No stream was opened, and nothing is waiting on a DNS answer. */
  tt_ptr_op(or_circ->n_streams, OP_EQ, NULL);
  tt_ptr_op(or_circ->resolving_streams, OP_EQ, NULL);

 done:
  UNMOCK(relay_send_command_from_edge_);
  if (or_circ)
    circuit_free_(TO_CIRCUIT(or_circ));
}

/** A relay refuses a RESOLVE cell, and looks nothing up. */
static void
test_dark_relay_refuses_resolve(void *arg)
{
  (void)arg;
  or_circuit_t *or_circ = NULL;
  relay_msg_t msg;

  MOCK(relay_send_command_from_edge_, mock_relay_send_command_from_edge);

  get_options_mutable()->ORPort_set = 1;

  or_circ = or_circuit_new(0, NULL);
  TO_CIRCUIT(or_circ)->purpose = CIRCUIT_PURPOSE_OR;
  make_relay_msg(&msg, RELAY_COMMAND_RESOLVE, 9, "example.com");

  tt_int_op(connection_exit_begin_resolve(&msg, or_circ), OP_EQ, 0);

  tt_int_op(n_cells_sent, OP_EQ, 1);
  tt_int_op(sent_stream_id, OP_EQ, 9);
  tt_int_op(sent_command, OP_EQ, RELAY_COMMAND_END);
  tt_int_op(sent_end_reason, OP_EQ, END_STREAM_REASON_EXITPOLICY);
  tt_ptr_op(or_circ->n_streams, OP_EQ, NULL);
  tt_ptr_op(or_circ->resolving_streams, OP_EQ, NULL);

 done:
  UNMOCK(relay_send_command_from_edge_);
  if (or_circ)
    circuit_free_(TO_CIRCUIT(or_circ));
}

/** An authority takes a descriptor only if its exit policy rejects
 * everything. */
static void
test_dark_dirauth_rejects_exit_descriptor(void *arg)
{
  (void)arg;
  routerinfo_t *ri = NULL;
  crypto_pk_t *pk = pk_generate(0);
  curve25519_keypair_t onion_keypair;
  const char *msg = NULL;
  char digest[DIGEST_LEN];
  char fp[HEX_DIGEST_LEN+1];

  authdir_init_fingerprint_list();

  ri = tor_malloc_zero(sizeof(routerinfo_t));
  tor_addr_from_ipv4h(&ri->ipv4_addr, 0xc0a80001u);
  ri->ipv4_orport = 9001;
  ri->platform = tor_strdup("Tor 0.4.9.14 on Linux");
  ri->nickname = tor_strdup("Relay");
  ri->identity_pkey = crypto_pk_dup_key(pk);
  ri->protocol_list = tor_strdup(protover_get_supported_protocols());
  curve25519_keypair_generate(&onion_keypair, 0);
  ri->onion_curve25519_pkey = tor_memdup(&onion_keypair.pubkey,
                                         sizeof(curve25519_public_key_t));

  /* A relay that refuses every exit stream is accepted. */
  ri->policy_is_reject_star = 1;
  tt_int_op(dirserv_router_get_status(ri, &msg, LOG_INFO), OP_EQ, 0);

  /* One that would carry any is not... */
  ri->policy_is_reject_star = 0;
  tt_int_op(dirserv_router_get_status(ri, &msg, LOG_INFO), OP_EQ, RTR_REJECT);
  tt_str_op(msg, OP_EQ, "This network has no exit relays: "
                        "the exit policy must be reject *:*.");

  /* ...even when a status is listed for its fingerprint, which makes the
   * later checks return that status early. */
  tt_int_op(crypto_pk_get_digest(ri->identity_pkey, digest), OP_EQ, 0);
  base16_encode(fp, sizeof(fp), digest, DIGEST_LEN);
  add_rsa_fingerprint_to_dir(fp, authdir_return_fingerprint_list(),
                             RTR_INVALID);
  tt_int_op(dirserv_router_get_status(ri, &msg, LOG_INFO), OP_EQ, RTR_REJECT);

 done:
  dirserv_free_fingerprint_list();
  routerinfo_free(ri);
  crypto_pk_free(pk);
}

/* How the last entry connection that was given up on ended, and what the
 * last resolve request was answered with. */
static int n_marked_unattached;
static int marked_end_reason;
static int n_resolved;
static int resolved_answer_type;

static void
mock_connection_mark_unattached_ap_(entry_connection_t *conn, int endreason,
                                    int line, const char *file)
{
  (void)conn;
  (void)line;
  (void)file;

  ++n_marked_unattached;
  marked_end_reason = endreason;
}

static void
mock_connection_ap_handshake_socks_resolved(entry_connection_t *conn,
                                            int answer_type,
                                            size_t answer_len,
                                            const uint8_t *answer,
                                            int ttl, time_t expires)
{
  (void)conn;
  (void)answer_len;
  (void)answer;
  (void)ttl;
  (void)expires;

  ++n_resolved;
  resolved_answer_type = answer_type;
}

/** Make the SOCKS request <b>command</b> for <b>address</b> on a new entry
 * connection, and return what connection_ap_handshake_rewrite_and_attach()
 * said about it. If <b>all_traffic</b>, the connection has every kind of
 * traffic enabled that a port can enable; otherwise none but onion. */
static int
request_destination(uint8_t command, const char *address, bool all_traffic)
{
  entry_connection_t *conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  int r;

  n_marked_unattached = marked_end_reason = n_resolved = 0;
  resolved_answer_type = -1;

  conn->socks_request->command = command;
  conn->socks_request->port = 80;
  strlcpy(conn->socks_request->address, address,
          sizeof(conn->socks_request->address));
  conn->entry_cfg.onion_traffic = 1;
  conn->entry_cfg.dns_request = all_traffic;
  conn->entry_cfg.ipv4_traffic = all_traffic;
  conn->entry_cfg.ipv6_traffic = all_traffic;
  ENTRY_TO_CONN(conn)->state = AP_CONN_STATE_SOCKS_WAIT;

  r = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  connection_free_minimal(ENTRY_TO_CONN(conn));
  return r;
}

/** A client refuses every destination that is not a .dark address, and no
 * setting of a port changes that. */
static void
test_dark_client_refuses_non_dark(void *arg)
{
  (void)arg;
  static const struct {
    uint8_t command;
    const char *address;
  } refused[] = {
    { SOCKS_COMMAND_CONNECT, "example.com" },
    { SOCKS_COMMAND_CONNECT, "1.2.3.4" },
    { SOCKS_COMMAND_CONNECT, "2001:db8::1" },
    { SOCKS_COMMAND_RESOLVE, "example.com" },
    { SOCKS_COMMAND_RESOLVE_PTR, "1.2.3.4" },
  };

  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_);
  MOCK(connection_ap_handshake_socks_resolved,
       mock_connection_ap_handshake_socks_resolved);
  addressmap_init();

  for (int all_traffic = 0; all_traffic <= 1; ++all_traffic) {
    for (unsigned i = 0; i < ARRAY_LENGTH(refused); ++i) {
      tt_int_op(request_destination(refused[i].command, refused[i].address,
                                    all_traffic),
                OP_EQ, -1);
      tt_int_op(n_marked_unattached, OP_EQ, 1);
      tt_int_op(marked_end_reason & END_STREAM_REASON_MASK, OP_EQ,
                END_STREAM_REASON_ENTRYPOLICY);
      if (SOCKS_COMMAND_IS_RESOLVE(refused[i].command)) {
        /* "No such name", which a DNSPort turns into NXDOMAIN. */
        tt_int_op(n_resolved, OP_EQ, 1);
        tt_int_op(resolved_answer_type, OP_EQ, RESOLVED_TYPE_ERROR);
      } else {
        tt_int_op(n_resolved, OP_EQ, 0);
      }
    }
  }

 done:
  UNMOCK(connection_mark_unattached_ap_);
  UNMOCK(connection_ap_handshake_socks_resolved);
  addressmap_free_all();
}

/** Resolving a literal IP address needs no network, and is how an automapped
 * .dark name gets its answer: it is the one request that is not refused. */
static void
test_dark_client_resolves_literal_address(void *arg)
{
  (void)arg;

  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_);
  MOCK(connection_ap_handshake_socks_resolved,
       mock_connection_ap_handshake_socks_resolved);
  addressmap_init();

  tt_int_op(request_destination(SOCKS_COMMAND_RESOLVE, "1.2.3.4", false),
            OP_EQ, 0);
  tt_int_op(n_resolved, OP_EQ, 1);
  tt_int_op(resolved_answer_type, OP_EQ, RESOLVED_TYPE_IPV4);
  tt_int_op(n_marked_unattached, OP_EQ, 1);
  tt_int_op(marked_end_reason & END_STREAM_REASON_MASK, OP_EQ,
            END_STREAM_REASON_DONE);

 done:
  UNMOCK(connection_mark_unattached_ap_);
  UNMOCK(connection_ap_handshake_socks_resolved);
  addressmap_free_all();
}

/** The root key that the vectors were made with. */
static const ed25519_public_key_t *
vector_root_key(void)
{
  static ed25519_public_key_t key;
  tor_assert(ed25519_public_from_base64(&key, DARK_VECTOR_ROOT_KEY) == 0);
  return &key;
}

/** Parse the snapshot <b>text</b> as of the time <b>now</b>. */
static darknames_snapshot_t *
parse_vector(const char *text, time_t now,
             const darknames_freshness_t *accepted, const char **problem)
{
  return darknames_snapshot_parse(text, strlen(text), vector_root_key(), now,
                                  accepted, problem);
}

/** Which names may be registered. The registry in Python has the same list
 * in its tests: the two must agree on every one. */
static void
test_dark_names_validity(void *arg)
{
  (void)arg;
  static const char *valid[] = {
    "abc", "site", "a-b", "a1b2", "3com", "ab-c-d", "a--b", "abc--d",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  };
  static const char *invalid[] = {
    "", "a", "ab", "Site", "-ab", "ab-", "a_b", "a.b", "a b", "ab--cd",
    "xn--80ak6aa92e", "abc\n", "\xd1\x81\xd0\xb0\xd0\xb9\xd1\x82",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  };

  for (unsigned i = 0; i < ARRAY_LENGTH(valid); ++i)
    tt_assert(darknames_name_is_valid(valid[i]));
  for (unsigned i = 0; i < ARRAY_LENGTH(invalid); ++i)
    tt_assert(!darknames_name_is_valid(invalid[i]));

  tt_assert(darknames_root_key_is_valid(DARK_VECTOR_ROOT_KEY));
  tt_assert(!darknames_root_key_is_valid(""));
  tt_assert(!darknames_root_key_is_valid(DARK_VECTOR_ROOT_KEY "="));
  tt_assert(!darknames_root_key_is_valid(DARK_VECTOR_ROOT_KEY "A"));
  /* One character short, and stray bits in the last character. */
  tt_assert(!darknames_root_key_is_valid(
                          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  tt_assert(!darknames_root_key_is_valid(
                          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"));

 done:
  ;
}

/** A snapshot that the registry signed is accepted, and names resolve from
 * it for as long as it and they are in force. */
static void
test_dark_names_snapshot(void *arg)
{
  (void)arg;
  const time_t created = DARK_VECTOR_CREATED;
  const char *problem = "unset";
  char address[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  darknames_snapshot_t *snapshot = NULL;
  static const char *keywords[] = { "signature", "names", "head" };

  snapshot = parse_vector(DARK_VECTOR_VALID, created, NULL, &problem);
  tt_assert(snapshot);
  tt_ptr_op(problem, OP_EQ, NULL);
  tt_int_op(darknames_snapshot_n_names(snapshot), OP_EQ, 6);

#define LOOKUP(name, now) \
  darknames_snapshot_lookup(snapshot, (name), (now), address)

  tt_int_op(LOOKUP("site", created), OP_EQ, DARKNAME_FOUND);
  tt_str_op(address, OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  tt_int_op(LOOKUP("nosuch", created), OP_EQ, DARKNAME_NOT_FOUND);
  /* A name is found whole, and not by how it begins. */
  tt_int_op(LOOKUP("sit", created), OP_EQ, DARKNAME_NOT_FOUND);
  tt_int_op(LOOKUP("sites", created), OP_EQ, DARKNAME_NOT_FOUND);

  /* Names that are spelled like keywords of the format are plain names. */
  for (unsigned i = 0; i < ARRAY_LENGTH(keywords); ++i) {
    tt_int_op(LOOKUP(keywords[i], created), OP_EQ, DARKNAME_FOUND);
    tt_str_op(address, OP_EQ, DARK_VECTOR_ADDRESS_SITE);
  }

  /* A name can expire while the snapshot that lists it is still good. */
  tt_int_op(LOOKUP("soon", created + DARK_VECTOR_DAY - 1), OP_EQ,
            DARKNAME_FOUND);
  tt_int_op(LOOKUP("soon", created + DARK_VECTOR_DAY), OP_EQ,
            DARKNAME_NOT_FOUND);

  /* And the snapshot goes out of date while we hold it: after that we do
   * not know which names there are. */
  tt_int_op(LOOKUP("site", DARK_VECTOR_VALID_UNTIL), OP_EQ, DARKNAME_FOUND);
  tt_int_op(LOOKUP("site", DARK_VECTOR_VALID_UNTIL + 1), OP_EQ,
            DARKNAME_UNAVAILABLE);
  tt_int_op(LOOKUP("nosuch", DARK_VECTOR_VALID_UNTIL + 1), OP_EQ,
            DARKNAME_UNAVAILABLE);
  darknames_snapshot_free(snapshot);

  /* Fields that a later revision of the format adds to a name are ignored. */
  snapshot = parse_vector(DARK_VECTOR_EXTRA_FIELDS, created, NULL, &problem);
  tt_assert(snapshot);
  tt_int_op(LOOKUP("shop", created), OP_EQ, DARKNAME_FOUND);
  tt_str_op(address, OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  darknames_snapshot_free(snapshot);

  /* A certificate may run out before the snapshot does. */
  snapshot = parse_vector(DARK_VECTOR_SHORT_CERTIFICATE,
                          created + DARK_VECTOR_DAY, NULL, &problem);
  tt_assert(snapshot);
  tt_int_op(LOOKUP("site", created + DARK_VECTOR_DAY), OP_EQ, DARKNAME_FOUND);
  tt_int_op(LOOKUP("site", created + DARK_VECTOR_DAY + 1), OP_EQ,
            DARKNAME_UNAVAILABLE);
#undef LOOKUP

 done:
  darknames_snapshot_free(snapshot);
}

/** What must not be accepted, and why it is not. */
static void
test_dark_names_snapshot_rejected(void *arg)
{
  (void)arg;
  const time_t created = DARK_VECTOR_CREATED;
  const size_t valid_len = strlen(DARK_VECTOR_VALID);
  char *copy = NULL;
  const char *problem;
  static const struct {
    const char *text;
    time_t now;
    const char *problem;
  } cases[] = {
    /* Not what the registry signed. */
    { DARK_VECTOR_TAMPERED, DARK_VECTOR_CREATED,
      "it is not signed by the signing key" },
    { DARK_VECTOR_WRONG_ROOT, DARK_VECTOR_CREATED,
      "its signing key is not certified by the root key" },
    /* Signed, and out of date. */
    { DARK_VECTOR_VALID, DARK_VECTOR_VALID_UNTIL + 1,
      "it is no longer valid" },
    { DARK_VECTOR_SHORT_CERTIFICATE, DARK_VECTOR_CREATED + DARK_VECTOR_DAY + 1,
      "the certificate of its signing key has expired" },
    /* Signed, and not made the way the format says. */
    { DARK_VECTOR_UNSORTED, DARK_VECTOR_CREATED, "it is malformed" },
    { DARK_VECTOR_DUPLICATE, DARK_VECTOR_CREATED, "it is malformed" },
    { DARK_VECTOR_COUNT_LOW, DARK_VECTOR_CREATED, "it is malformed" },
    { DARK_VECTOR_COUNT_HIGH, DARK_VECTOR_CREATED, "it is malformed" },
    { DARK_VECTOR_UNKNOWN_LINE, DARK_VECTOR_CREATED, "it is malformed" },
    { DARK_VECTOR_LEADING_ZERO, DARK_VECTOR_CREATED, "it is malformed" },
    /* Not a snapshot at all. */
    { "", DARK_VECTOR_CREATED, "it is malformed" },
    { "\n", DARK_VECTOR_CREATED, "it is malformed" },
    { "dark-names-snapshot 1\n", DARK_VECTOR_CREATED, "it is malformed" },
    { "dark-names-snapshot 2\n\n\n", DARK_VECTOR_CREATED, "it is malformed" },
  };

  for (unsigned i = 0; i < ARRAY_LENGTH(cases); ++i) {
    problem = NULL;
    tt_ptr_op(parse_vector(cases[i].text, cases[i].now, NULL, &problem),
              OP_EQ, NULL);
    tt_str_op(problem, OP_EQ, cases[i].problem);
  }

  /* The good snapshot, cut short of its last newline, or with one more. */
  tt_ptr_op(darknames_snapshot_parse(DARK_VECTOR_VALID, valid_len - 1,
                                     vector_root_key(), created, NULL,
                                     &problem), OP_EQ, NULL);
  tor_asprintf(&copy, "%s\n", DARK_VECTOR_VALID);
  tt_ptr_op(parse_vector(copy, created, NULL, &problem), OP_EQ, NULL);
  tor_free(copy);

  /* A NUL anywhere in it. */
  copy = tor_memdup(DARK_VECTOR_VALID, valid_len + 1);
  copy[valid_len / 2] = '\0';
  tt_ptr_op(darknames_snapshot_parse(copy, valid_len, vector_root_key(),
                                     created, NULL, &problem), OP_EQ, NULL);
  tt_str_op(problem, OP_EQ, "it is malformed");

 done:
  tor_free(copy);
}

/** A snapshot is not accepted after a newer one was. */
static void
test_dark_names_rollback(void *arg)
{
  (void)arg;
  const time_t created = DARK_VECTOR_CREATED;
  const char *problem;
  darknames_snapshot_t *snapshot = NULL;
  darknames_freshness_t accepted;

  /* The very snapshot that was accepted last, or anything after one that
   * was older by both measures. */
  static const darknames_freshness_t not_newer[] = {
    { DARK_VECTOR_HEAD_INDEX, DARK_VECTOR_CREATED },
    { DARK_VECTOR_HEAD_INDEX - 1, DARK_VECTOR_CREATED - 1 },
    { 0, 0 },
  };
  /* Newer by either measure is enough to make this one a step back. */
  static const darknames_freshness_t newer[] = {
    { DARK_VECTOR_HEAD_INDEX + 1, DARK_VECTOR_CREATED },
    { DARK_VECTOR_HEAD_INDEX, DARK_VECTOR_CREATED + 1 },
  };

  for (unsigned i = 0; i < ARRAY_LENGTH(not_newer); ++i) {
    accepted = not_newer[i];
    snapshot = parse_vector(DARK_VECTOR_VALID, created, &accepted, &problem);
    tt_assert(snapshot);
    darknames_snapshot_free(snapshot);
  }
  for (unsigned i = 0; i < ARRAY_LENGTH(newer); ++i) {
    accepted = newer[i];
    tt_ptr_op(parse_vector(DARK_VECTOR_VALID, created, &accepted, &problem),
              OP_EQ, NULL);
    tt_str_op(problem, OP_EQ,
              "it is older than one that was accepted before");
  }

 done:
  darknames_snapshot_free(snapshot);
}

/** Thousands of ways to spoil the good snapshot: none of them is accepted,
 * and none of them breaks the parser. The sequence is the same on every
 * run. */
static void
test_dark_names_mutations(void *arg)
{
  (void)arg;
  const char *valid = DARK_VECTOR_VALID;
  const size_t len = strlen(valid);
  const char *problem;
  char *mutated = NULL;
  uint32_t rng = 0x6461726b;

#define NEXT_RANDOM() \
  (rng ^= rng << 13, rng ^= rng >> 17, rng ^= rng << 5, rng)

  for (int i = 0; i < 4000; ++i) {
    size_t mutated_len = len;
    const size_t at = NEXT_RANDOM() % len;
    /* The line that `at` is in, with its newline. */
    const char *line = valid + at, *line_end;
    while (line > valid && line[-1] != '\n')
      --line;
    line_end = (const char *)memchr(line, '\n', valid + len - line) + 1;

    mutated = tor_malloc(2 * len + 1);
    memcpy(mutated, valid, len);
    switch (NEXT_RANDOM() % 4) {
      case 0: /* One byte becomes another. */
        mutated[at] = (char)(valid[at] ^ (1 + NEXT_RANDOM() % 255));
        break;
      case 1: /* Cut short. */
        mutated_len = at;
        break;
      case 2: /* A line twice. */
        memcpy(mutated + (line_end - valid), line, line_end - line);
        memcpy(mutated + (line_end - valid) + (line_end - line), line_end,
               valid + len - line_end);
        mutated_len = len + (size_t)(line_end - line);
        break;
      default: /* A line gone. */
        memmove(mutated + (line - valid), line_end, valid + len - line_end);
        mutated_len = len - (size_t)(line_end - line);
        break;
    }

    tt_ptr_op(darknames_snapshot_parse(mutated, mutated_len,
                                       vector_root_key(),
                                       DARK_VECTOR_CREATED, NULL, &problem),
              OP_EQ, NULL);
    tt_assert(problem);
    tor_free(mutated);
  }
#undef NEXT_RANDOM

 done:
  tor_free(mutated);
}

/** Write <b>text</b> where the helper leaves the snapshot for us. */
static void
write_snapshot_file(const char *text)
{
  char *fname = get_datadir_fname2("dark_names", "snapshot");
  tor_assert(write_str_to_file(fname, text, 1) == 0);
  tor_free(fname);
}

/** Give this test a data directory of its own, called <b>name</b>, with the
 * place for the snapshot in it; and the time at which the vectors are good. */
static void
use_names_directory(const char *name)
{
  or_options_t *options = get_options_mutable();
  char *directory;

  tor_free(options->DataDirectory);
  options->DataDirectory = tor_strdup(get_fname(name));
  directory = get_datadir_fname("dark_names");
  tor_assert(check_private_dir(options->DataDirectory, CPD_CREATE, NULL) == 0);
  tor_assert(check_private_dir(directory, CPD_CREATE, NULL) == 0);
  tor_free(directory);
  /* Look at the file on every lookup, as in a testing network. */
  options->TestingTorNetwork = 1;
  update_approx_time(DARK_VECTOR_CREATED);
}

/** Names resolve from the file in the data directory, and a bad file there
 * does not cost us the snapshot we already have. */
static void
test_dark_names_lookup(void *arg)
{
  (void)arg;
  or_options_t *options = get_options_mutable();
  char address[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  char *accepted = NULL, *fname = NULL;

  use_names_directory("dark_names_lookup");

  /* No root key: nothing resolves, whatever is on the disk. */
  write_snapshot_file(DARK_VECTOR_VALID);
  tt_int_op(darknames_lookup("site", address), OP_EQ, DARKNAME_UNAVAILABLE);

  options->DarkNamesRootKey = tor_strdup(DARK_VECTOR_ROOT_KEY);
  tt_int_op(darknames_lookup("site", address), OP_EQ, DARKNAME_FOUND);
  tt_str_op(address, OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  tt_int_op(darknames_lookup("nosuch", address), OP_EQ, DARKNAME_NOT_FOUND);

  /* We wrote down what we accepted. */
  fname = get_datadir_fname2("dark_names", "accepted");
  accepted = read_file_to_str(fname, RFTS_BIN, NULL);
  tt_assert(accepted);
  tt_str_op(accepted, OP_EQ, "13 1800000000\n");

  /* Files that are not what the registry signed, or not a snapshot at all,
   * leave us with what we had. */
  setup_full_capture_of_logs(LOG_WARN);
  write_snapshot_file(DARK_VECTOR_WRONG_ROOT);
  tt_int_op(darknames_lookup("shop", address), OP_EQ, DARKNAME_FOUND);
  tt_str_op(address, OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  expect_single_log_msg_containing(
                          "its signing key is not certified by the root key");
  mock_clean_saved_logs();
  write_snapshot_file("garbage\n");
  tt_int_op(darknames_lookup("site", address), OP_EQ, DARKNAME_FOUND);
  /* This one ends with the signature of the snapshot we hold, so it is taken
   * for that snapshot and not read at all: its changed address is not
   * what "shop" resolves to. */
  write_snapshot_file(DARK_VECTOR_VALID);
  tt_int_op(darknames_lookup("site", address), OP_EQ, DARKNAME_FOUND);
  write_snapshot_file(DARK_VECTOR_TAMPERED);
  tt_int_op(darknames_lookup("shop", address), OP_EQ, DARKNAME_FOUND);
  tt_str_op(address, OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  teardown_capture_of_logs();

  /* A good file takes its place. */
  write_snapshot_file(DARK_VECTOR_EXTRA_FIELDS);
  tt_int_op(darknames_lookup("site", address), OP_EQ, DARKNAME_FOUND);

  /* The snapshot we hold goes out of date like any other. */
  update_approx_time(DARK_VECTOR_VALID_UNTIL + 1);
  tt_int_op(darknames_lookup("site", address), OP_EQ, DARKNAME_UNAVAILABLE);
  update_approx_time(DARK_VECTOR_CREATED);

  /* Under another root key it was never vouched for. */
  tor_free(options->DarkNamesRootKey);
  options->DarkNamesRootKey =
    tor_strdup("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  setup_full_capture_of_logs(LOG_WARN);
  tt_int_op(darknames_lookup("site", address), OP_EQ, DARKNAME_UNAVAILABLE);
  teardown_capture_of_logs();

  /* And once we have accepted a newer snapshot, this one is a step back. */
  tor_free(options->DarkNamesRootKey);
  options->DarkNamesRootKey = tor_strdup(DARK_VECTOR_ROOT_KEY);
  tt_int_op(write_str_to_file(fname, "14 1800000000\n", 1), OP_EQ, 0);
  setup_full_capture_of_logs(LOG_WARN);
  tt_int_op(darknames_lookup("site", address), OP_EQ, DARKNAME_UNAVAILABLE);
  teardown_capture_of_logs();

 done:
  teardown_capture_of_logs();
  darknames_free_all();
  tor_free(accepted);
  tor_free(fname);
}

/** A name never reaches a log, whatever SafeLogging says. An address is
 * the user's to log or not. */
static void
test_dark_names_are_not_logged(void *arg)
{
  (void)arg;
  or_options_t *options = get_options_mutable();
  static const char *names[] = {
    "site.dark", "www.site.dark", "SITE.DARK", "a.b.c.site.dark",
    /* Not names that can be registered, and as much the user's business. */
    "ab.dark", "a_b.dark",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.dark",
  };
  static const char *not_names[] = {
    DARK_VECTOR_ADDRESS_SITE ".dark",
    "www." DARK_VECTOR_ADDRESS_SITE ".dark",
    DARK_VECTOR_ADDRESS_SITE,
    "example.com", "site.onion", "dark", ".dark", "site.darker", "1.2.3.4",
  };

  options->SafeLogging_ = SAFELOG_SCRUB_NONE;
  for (unsigned i = 0; i < ARRAY_LENGTH(names); ++i) {
    tt_str_op(safe_str_client(names[i]), OP_EQ, "[scrubbed]");
    tt_str_op(safe_str(names[i]), OP_EQ, "[scrubbed]");
    tt_str_op(escaped_safe_str_client(names[i]), OP_EQ, "[scrubbed]");
    tt_str_op(escaped_safe_str(names[i]), OP_EQ, "[scrubbed]");
  }
  for (unsigned i = 0; i < ARRAY_LENGTH(not_names); ++i) {
    tt_str_op(safe_str_client(not_names[i]), OP_EQ, not_names[i]);
    tt_str_op(safe_str(not_names[i]), OP_EQ, not_names[i]);
  }

  /* With SafeLogging on, nothing changes: all of it is scrubbed. */
  options->SafeLogging_ = SAFELOG_SCRUB_ALL;
  tt_str_op(safe_str_client(not_names[0]), OP_EQ, "[scrubbed]");
  tt_str_op(safe_str_client(names[0]), OP_EQ, "[scrubbed]");

 done:
  ;
}

/** A request for a registered name becomes a request for the address that
 * the registry gives it; a request for any other name is refused. */
static void
test_dark_client_resolves_names(void *arg)
{
  (void)arg;
  or_options_t *options = get_options_mutable();
  entry_connection_t *conn = NULL;

  use_names_directory("dark_client_resolves_names");
  options->DarkNamesRootKey = tor_strdup(DARK_VECTOR_ROOT_KEY);
  write_snapshot_file(DARK_VECTOR_VALID);
  addressmap_init();
  hs_cache_init();

  /* A name, with a sub-domain that is dropped as one of an address is. */
  conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  conn->socks_request->port = 80;
  strlcpy(conn->socks_request->address, "www.site.dark",
          sizeof(conn->socks_request->address));
  conn->entry_cfg.onion_traffic = 1;
  ENTRY_TO_CONN(conn)->state = AP_CONN_STATE_SOCKS_WAIT;

  tt_int_op(connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL),
            OP_EQ, 0);
  /* It goes on as a request for the service: here, to wait for the
   * service's descriptor. */
  tt_str_op(conn->socks_request->address, OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  tt_int_op(ENTRY_TO_CONN(conn)->state, OP_EQ, AP_CONN_STATE_RENDDESC_WAIT);
  tt_assert(ENTRY_TO_EDGE_CONN(conn)->hs_ident);

  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_);
  MOCK(connection_ap_handshake_socks_resolved,
       mock_connection_ap_handshake_socks_resolved);

  /* A name that is not registered. */
  tt_int_op(request_destination(SOCKS_COMMAND_CONNECT, "nosuch.dark", false),
            OP_EQ, -1);
  tt_int_op(n_marked_unattached, OP_EQ, 1);
  tt_int_op(marked_end_reason & END_STREAM_REASON_MASK, OP_EQ,
            END_STREAM_REASON_RESOLVEFAILED);
  tt_int_op(n_resolved, OP_EQ, 0);

  /* One that is registered and has expired. */
  update_approx_time(DARK_VECTOR_CREATED + DARK_VECTOR_DAY);
  tt_int_op(request_destination(SOCKS_COMMAND_CONNECT, "soon.dark", false),
            OP_EQ, -1);
  tt_int_op(marked_end_reason & END_STREAM_REASON_MASK, OP_EQ,
            END_STREAM_REASON_RESOLVEFAILED);
  update_approx_time(DARK_VECTOR_CREATED);

  /* A resolve gets "no such name" for an answer. */
  tt_int_op(request_destination(SOCKS_COMMAND_RESOLVE, "nosuch.dark", false),
            OP_EQ, -1);
  tt_int_op(n_resolved, OP_EQ, 1);
  tt_int_op(resolved_answer_type, OP_EQ, RESOLVED_TYPE_ERROR);

  /* With no snapshot to trust, whether there is such a name is not known,
   * and the refusal says so by being another one. */
  tor_free(options->DarkNamesRootKey);
  tt_int_op(request_destination(SOCKS_COMMAND_CONNECT, "site.dark", false),
            OP_EQ, -1);
  tt_int_op(marked_end_reason & END_STREAM_REASON_MASK, OP_EQ,
            END_STREAM_REASON_INTERNAL);
  /* Even then a resolve is not answered with a failure. */
  tt_int_op(request_destination(SOCKS_COMMAND_RESOLVE, "site.dark", false),
            OP_EQ, -1);
  tt_int_op(resolved_answer_type, OP_EQ, RESOLVED_TYPE_ERROR);

 done:
  UNMOCK(connection_mark_unattached_ap_);
  UNMOCK(connection_ap_handshake_socks_resolved);
  if (conn)
    connection_free_minimal(ENTRY_TO_CONN(conn));
  addressmap_free_all();
  hs_free_all();
  darknames_free_all();
}

/** A name is pinned to the address of the first connection made by it, and
 * the pins are kept the way DarkNamesPinsOnDisk says. */
static void
test_dark_names_pins(void *arg)
{
  (void)arg;
  or_options_t *options = get_options_mutable();
  char *fname = NULL, *text = NULL;

  use_names_directory("dark_names_pins");
  options->DarkNamesPinsOnDisk = 1;
  fname = get_datadir_fname2("dark_names", "pins");

  tt_ptr_op(darknames_get_pin("site"), OP_EQ, NULL);
  tt_assert(!darknames_forget_pin("site"));

  /* The first connection pins the name, and a later one does not move it. */
  darknames_note_connected("site", DARK_VECTOR_ADDRESS_SHOP);
  tt_str_op(darknames_get_pin("site"), OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  darknames_note_connected("site", DARK_VECTOR_ADDRESS_SITE);
  tt_str_op(darknames_get_pin("site"), OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  darknames_note_connected("shop", DARK_VECTOR_ADDRESS_SHOP);

  text = read_file_to_str(fname, RFTS_BIN, NULL);
  tt_str_op(text, OP_EQ, "shop " DARK_VECTOR_ADDRESS_SHOP "\n"
                         "site " DARK_VECTOR_ADDRESS_SHOP "\n");
  tor_free(text);

  /* Pins outlast the process that made them. */
  darknames_free_all();
  tt_str_op(darknames_get_pin("site"), OP_EQ, DARK_VECTOR_ADDRESS_SHOP);

  /* A pin that is forgotten is gone from the file too. */
  tt_assert(darknames_forget_pin("site"));
  tt_ptr_op(darknames_get_pin("site"), OP_EQ, NULL);
  darknames_free_all();
  tt_ptr_op(darknames_get_pin("site"), OP_EQ, NULL);
  tt_str_op(darknames_get_pin("shop"), OP_EQ, DARK_VECTOR_ADDRESS_SHOP);

  /* Kept in memory alone, the pins go on, and the file that listed the
   * names does not stay behind. */
  options->DarkNamesPinsOnDisk = 0;
  tt_str_op(darknames_get_pin("shop"), OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  tt_int_op(file_status(fname), OP_EQ, FN_NOENT);
  darknames_note_connected("site", DARK_VECTOR_ADDRESS_SITE);
  tt_str_op(darknames_get_pin("site"), OP_EQ, DARK_VECTOR_ADDRESS_SITE);
  tt_int_op(file_status(fname), OP_EQ, FN_NOENT);
  /* They end with the process. */
  darknames_free_all();
  tt_ptr_op(darknames_get_pin("site"), OP_EQ, NULL);
  tt_ptr_op(darknames_get_pin("shop"), OP_EQ, NULL);

  /* A file left over from before is removed when the process starts so. */
  tt_int_op(write_str_to_file(fname, "site " DARK_VECTOR_ADDRESS_SHOP "\n", 1),
            OP_EQ, 0);
  darknames_free_all();
  tt_ptr_op(darknames_get_pin("site"), OP_EQ, NULL);
  tt_int_op(file_status(fname), OP_EQ, FN_NOENT);

  /* A damaged file gives what pins it still has. Of two for one name the
   * first stands. */
  options->DarkNamesPinsOnDisk = 1;
  darknames_free_all();
  tt_int_op(write_str_to_file(fname,
                              "site " DARK_VECTOR_ADDRESS_SHOP "\n"
                              "not a pin at all\n"
                              "shop tooshort\n"
                              "blog " DARK_VECTOR_ADDRESS_SITE "\n"
                              "site " DARK_VECTOR_ADDRESS_SITE "\n"
                              "cut short", 1), OP_EQ, 0);
  setup_full_capture_of_logs(LOG_WARN);
  tt_str_op(darknames_get_pin("site"), OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  tt_str_op(darknames_get_pin("blog"), OP_EQ, DARK_VECTOR_ADDRESS_SITE);
  tt_ptr_op(darknames_get_pin("shop"), OP_EQ, NULL);
  expect_single_log_msg_containing("Passed over 4 lines");
  teardown_capture_of_logs();

 done:
  teardown_capture_of_logs();
  darknames_free_all();
  tor_free(fname);
  tor_free(text);
}

/** Make the request for <b>host</b> on a new connection, which is expected
 * to go on as a request for a service. Return the connection. */
static entry_connection_t *
request_by_name(const char *host)
{
  entry_connection_t *conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  conn->socks_request->port = 80;
  strlcpy(conn->socks_request->address, host,
          sizeof(conn->socks_request->address));
  conn->entry_cfg.onion_traffic = 1;
  ENTRY_TO_CONN(conn)->state = AP_CONN_STATE_SOCKS_WAIT;
  int r = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);
  tor_assert(r == 0);
  return conn;
}

/** The registry may say that a name leads elsewhere; a client that has been
 * to the name does not follow until the user says so. */
static void
test_dark_client_holds_names_to_pins(void *arg)
{
  (void)arg;
  or_options_t *options = get_options_mutable();
  entry_connection_t *conn = NULL;

  use_names_directory("dark_client_holds_names_to_pins");
  options->DarkNamesPinsOnDisk = 1;
  options->DarkNamesRootKey = tor_strdup(DARK_VECTOR_ROOT_KEY);
  write_snapshot_file(DARK_VECTOR_VALID);
  addressmap_init();
  hs_cache_init();

  /* Resolving a name pins nothing: no connection has been made yet. */
  conn = request_by_name("www.site.dark");
  tt_str_op(conn->socks_request->address, OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  tt_str_op(conn->dark_name, OP_EQ, "site");
  tt_ptr_op(darknames_get_pin("site"), OP_EQ, NULL);
  /* Then it is made, which the relay code tells us like this. */
  darknames_note_connected(conn->dark_name, conn->socks_request->address);
  tt_str_op(darknames_get_pin("site"), OP_EQ, DARK_VECTOR_ADDRESS_SHOP);
  connection_free_minimal(ENTRY_TO_CONN(conn));
  conn = NULL;

  /* A request by address is not one by name. */
  conn = request_by_name(DARK_VECTOR_ADDRESS_SHOP ".dark");
  tt_ptr_op(conn->dark_name, OP_EQ, NULL);
  connection_free_minimal(ENTRY_TO_CONN(conn));
  conn = NULL;

  /* The registry moves the name. */
  update_approx_time(DARK_VECTOR_CREATED + 60);
  write_snapshot_file(DARK_VECTOR_MOVED);

  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_);
  setup_full_capture_of_logs(LOG_INFO);
  tt_int_op(request_destination(SOCKS_COMMAND_CONNECT, "site.dark", false),
            OP_EQ, -1);
  tt_int_op(n_marked_unattached, OP_EQ, 1);
  tt_int_op(marked_end_reason & END_STREAM_REASON_MASK, OP_EQ,
            END_STREAM_REASON_ENTRYPOLICY);
  /* The log says that it happened, and not to which name. */
  expect_log_msg_containing("the registry now gives it another address");
  expect_no_log_msg_containing("site.dark");
  teardown_capture_of_logs();
  UNMOCK(connection_mark_unattached_ap_);
  /* Other names resolve as before. */
  conn = request_by_name("shop.dark");
  connection_free_minimal(ENTRY_TO_CONN(conn));
  conn = NULL;

  /* The user accepts the change: the next connection pins the name anew. */
  tt_assert(darknames_forget_pin("site"));
  conn = request_by_name("site.dark");
  tt_str_op(conn->socks_request->address, OP_EQ, DARK_VECTOR_ADDRESS_SITE);
  darknames_note_connected(conn->dark_name, conn->socks_request->address);
  tt_str_op(darknames_get_pin("site"), OP_EQ, DARK_VECTOR_ADDRESS_SITE);

 done:
  teardown_capture_of_logs();
  UNMOCK(connection_mark_unattached_ap_);
  if (conn)
    connection_free_minimal(ENTRY_TO_CONN(conn));
  addressmap_free_all();
  hs_free_all();
  darknames_free_all();
}

#define DARK_TEST(name, flags)                          \
  { #name, test_dark_ ##name, (flags), NULL, NULL }

struct testcase_t dark_tests[] = {
  DARK_TEST(exit_policy_ignores_options, 0),
  DARK_TEST(relay_refuses_begin, TT_FORK),
  DARK_TEST(relay_refuses_resolve, TT_FORK),
  DARK_TEST(dirauth_rejects_exit_descriptor, TT_FORK),
  DARK_TEST(client_refuses_non_dark, TT_FORK),
  DARK_TEST(client_resolves_literal_address, TT_FORK),
  DARK_TEST(names_validity, 0),
  DARK_TEST(names_snapshot, 0),
  DARK_TEST(names_snapshot_rejected, 0),
  DARK_TEST(names_rollback, 0),
  DARK_TEST(names_mutations, 0),
  DARK_TEST(names_lookup, TT_FORK),
  DARK_TEST(names_are_not_logged, TT_FORK),
  DARK_TEST(client_resolves_names, TT_FORK),
  DARK_TEST(names_pins, TT_FORK),
  DARK_TEST(client_holds_names_to_pins, TT_FORK),
  END_OF_TESTCASES
};

/* See LICENSE for licensing information */

/**
 * \file test_dark.c
 * \brief Tests for what makes this a Dark build: things that tor does not do
 *   upstream, or that must never happen on this network.
 */

#define CIRCUITLIST_PRIVATE
#define CONFIG_PRIVATE

#include "core/or/or.h"
#include "test/test.h"

#include "app/config/config.h"
#include "app/config/or_options_st.h"
#include "core/or/circuitlist.h"
#include "core/or/connection_edge.h"
#include "core/or/or_circuit_st.h"
#include "core/or/policies.h"
#include "core/or/relay.h"
#include "core/or/relay_msg_st.h"
#include "feature/relay/routermode.h"
#include "lib/encoding/confline.h"

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

#define DARK_TEST(name, flags)                          \
  { #name, test_dark_ ##name, (flags), NULL, NULL }

struct testcase_t dark_tests[] = {
  DARK_TEST(exit_policy_ignores_options, 0),
  DARK_TEST(relay_refuses_begin, TT_FORK),
  DARK_TEST(relay_refuses_resolve, TT_FORK),
  END_OF_TESTCASES
};

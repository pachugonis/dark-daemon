/* See LICENSE for licensing information */

/**
 * \file darknames.c
 * \brief Resolve registered names from the registry's signed snapshot.
 *
 * A helper program fetches the snapshot of the name registry and leaves it
 * in our data directory. We do not trust the helper: everything that lets a
 * name resolve is checked here again, starting from the registry's root key.
 *
 * The format is in docs/registry-spec.md of the Dark repository, section 7.
 * Its other implementation is in Python, and both are tested against the
 * same vectors.
 *
 * Nothing in this file may log a name. The addresses and counts that it does
 * log say nothing about what the user asked for.
 **/

#define DARKNAMES_PRIVATE

#include "core/or/or.h"
#include "feature/darknames/darknames.h"

#include "app/config/config.h"
#include "feature/hs/hs_common.h"
#include "lib/container/map.h"
#include "lib/crypt_ops/crypto_ed25519.h"
#include "lib/crypt_ops/crypto_format.h"
#include "lib/fs/files.h"
#include "lib/log/ratelim.h"
#include "lib/wallclock/approx_time.h"

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/** The root key of the registry that this build trusts, in base64, or NULL
 * if it has none. It is set once the registry's keys have been made; until
 * then names resolve only where DarkNamesRootKey is configured. */
#define DARKNAMES_BUILTIN_ROOT_KEY NULL

/** How often, in seconds, we look whether the snapshot file has changed. */
#define DARKNAMES_CHECK_INTERVAL 60

#define SNAPSHOT_VERSION_LINE "dark-names-snapshot 1"
#define SIGNING_KEY_DOMAIN "dark names signing key v1"
#define SNAPSHOT_DOMAIN "dark names snapshot v1"

/** A decimal integer of the format has at most this many digits, which keeps
 * it below 2^63. */
#define MAX_UINT_DIGITS 18

/** The most fields of a line that we look at. A name line may have more,
 * which belong to a later revision of the format. */
#define MAX_FIELDS 5

/** No name line is shorter than this: the shortest name, an address, a
 * one-digit time, a key, a one-digit number, four spaces and a newline. */
#define MIN_NAME_LINE_LEN \
  (DARKNAME_MIN_LEN + HS_SERVICE_ADDR_LEN_BASE32 + ED25519_BASE64_LEN + 7)

/** What a snapshot says about one name. */
typedef struct darkname_entry_t {
  char address[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  uint64_t expires;
} darkname_entry_t;

/** A snapshot that has been verified. */
struct darknames_snapshot_t {
  uint64_t head_index;
  uint64_t created;
  uint64_t valid_until;
  uint64_t certificate_expires;
  /** Map from name to darkname_entry_t. */
  strmap_t *names;
};

/** A field of a line: it is not NUL-terminated. */
typedef struct field_t {
  const char *s;
  size_t len;
} field_t;

/** Return true iff <b>name</b> may be registered: see section 2 of the
 * specification. */
bool
darknames_name_is_valid(const char *name)
{
  const size_t len = strlen(name);
  if (len < DARKNAME_MIN_LEN || len > DARKNAME_MAX_LEN)
    return false;
  if (name[0] == '-' || name[len - 1] == '-')
    return false;
  /* "--" in the third and fourth places would make an ACE prefix, such as
   * "xn--": there are no punycode names. */
  if (name[2] == '-' && len > 3 && name[3] == '-')
    return false;
  return strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789-") == len;
}

/** Set <b>key_out</b> to the key that <b>base64</b> spells, and return true.
 * Return false if it does not spell a key, or does not spell it in the one
 * way that the format allows. */
static bool
parse_public_key(const char *base64, ed25519_public_key_t *key_out)
{
  char canonical[ED25519_BASE64_LEN + 1];
  if (strlen(base64) != ED25519_BASE64_LEN ||
      ed25519_public_from_base64(key_out, base64) < 0)
    return false;
  ed25519_public_to_base64(canonical, key_out);
  return !strcmp(canonical, base64);
}

/** As parse_public_key(), for a signature. */
static bool
parse_signature(const char *base64, ed25519_signature_t *sig_out)
{
  char canonical[ED25519_SIG_BASE64_LEN + 1];
  if (ed25519_signature_from_base64(sig_out, base64) < 0)
    return false;
  ed25519_signature_to_base64(canonical, sig_out);
  return !strcmp(canonical, base64);
}

/** Return true iff <b>base64</b> can be a value of DarkNamesRootKey. */
bool
darknames_root_key_is_valid(const char *base64)
{
  ed25519_public_key_t key;
  return parse_public_key(base64, &key);
}

/** Copy the field <b>f</b> into <b>buf</b> as a string, and return true; or
 * return false if it does not fit, or is not as long as <b>len</b>. */
static bool
field_to_str(const field_t *f, size_t len, char *buf, size_t buflen)
{
  if (f->len != len || len + 1 > buflen)
    return false;
  memcpy(buf, f->s, len);
  buf[len] = '\0';
  return true;
}

static bool
field_is(const field_t *f, const char *keyword)
{
  return f->len == strlen(keyword) && fast_memeq(f->s, keyword, f->len);
}

/** Set <b>out</b> to the integer that <b>f</b> spells, and return true.
 * There is one way to spell an integer: in decimal digits and nothing else,
 * with no zero before another digit. */
static bool
field_to_uint(const field_t *f, uint64_t *out)
{
  uint64_t value = 0;
  if (f->len == 0 || f->len > MAX_UINT_DIGITS)
    return false;
  if (f->s[0] == '0' && f->len > 1)
    return false;
  for (size_t i = 0; i < f->len; ++i) {
    if (f->s[i] < '0' || f->s[i] > '9')
      return false;
    value = value * 10 + (uint64_t)(f->s[i] - '0');
  }
  *out = value;
  return true;
}

static bool
field_to_public_key(const field_t *f, ed25519_public_key_t *key_out)
{
  char buf[ED25519_BASE64_LEN + 1];
  return field_to_str(f, ED25519_BASE64_LEN, buf, sizeof(buf)) &&
    parse_public_key(buf, key_out);
}

static bool
field_to_signature(const field_t *f, ed25519_signature_t *sig_out)
{
  char buf[ED25519_SIG_BASE64_LEN + 1];
  return field_to_str(f, ED25519_SIG_BASE64_LEN, buf, sizeof(buf)) &&
    parse_signature(buf, sig_out);
}

/** Return true iff <b>f</b> is <b>len</b> characters, all of them from
 * <b>alphabet</b>. */
static bool
field_is_spelled_in(const field_t *f, size_t len, const char *alphabet)
{
  if (f->len != len)
    return false;
  for (size_t i = 0; i < len; ++i) {
    if (!strchr(alphabet, f->s[i]))
      return false;
  }
  return true;
}

/** Take the next line of the text that runs from *<b>cp</b> to <b>end</b>,
 * leave *<b>cp</b> after it, and split it into fields, which one space
 * separates. Set *<b>n_fields</b> to how many fields the line has; no more
 * than MAX_FIELDS of them are stored in <b>fields</b>.
 *
 * Return false if there is no whole line left, or if the line has an empty
 * field: that is, a space at either end of it, or two in a row. */
static bool
next_line(const char **cp, const char *end, field_t *fields, int *n_fields)
{
  const char *eol = memchr(*cp, '\n', end - *cp);
  const char *s = *cp;
  int n = 0;
  if (!eol)
    return false;
  *cp = eol + 1;
  while (1) {
    const char *space = memchr(s, ' ', eol - s);
    const char *field_end = space ? space : eol;
    if (field_end == s)
      return false;
    if (n < MAX_FIELDS) {
      fields[n].s = s;
      fields[n].len = field_end - s;
    }
    ++n;
    if (!space)
      break;
    s = space + 1;
  }
  *n_fields = n;
  return true;
}

/** Take the next line, which has to be the keyword <b>keyword</b> and then
 * exactly <b>n_values</b> more fields. Return false if it is not. */
static bool
next_keyword_line(const char **cp, const char *end, const char *keyword,
                  int n_values, field_t *fields)
{
  int n;
  return next_line(cp, end, fields, &n) && n == n_values + 1 &&
    field_is(&fields[0], keyword);
}

/** Free a snapshot. */
STATIC void
darknames_snapshot_free_(darknames_snapshot_t *snapshot)
{
  if (!snapshot)
    return;
  strmap_free(snapshot->names, tor_free_);
  tor_free(snapshot);
}

/** Parse the names of a snapshot whose signatures have been checked. The
 * lines to parse run from <b>cp</b> to <b>end</b>, and are all that is left
 * of the snapshot after its first two lines and before its last.
 *
 * Return false, and set *<b>problem_out</b>, if they are not what the format
 * says they are. */
static bool
parse_authenticated_body(darknames_snapshot_t *snapshot, const char *cp,
                         const char *end, const char **problem_out)
{
  field_t f[MAX_FIELDS];
  uint64_t n_names;
  char previous[DARKNAME_MAX_LEN + 1] = "";

  *problem_out = "it is malformed";
  if (!next_keyword_line(&cp, end, "head", 2, f) ||
      !field_to_uint(&f[1], &snapshot->head_index) ||
      !field_is_spelled_in(&f[2], HEX_DIGEST256_LEN, "0123456789abcdef"))
    return false;
  if (!next_keyword_line(&cp, end, "created", 1, f) ||
      !field_to_uint(&f[1], &snapshot->created))
    return false;
  if (!next_keyword_line(&cp, end, "valid-until", 1, f) ||
      !field_to_uint(&f[1], &snapshot->valid_until))
    return false;
  if (!next_keyword_line(&cp, end, "names", 1, f) ||
      !field_to_uint(&f[1], &n_names))
    return false;

  /* The names are found by their count, and not by how their lines begin:
   * a name may be spelled like a keyword of this format. Check the count
   * against what is left before believing it. */
  if (n_names > (uint64_t)(end - cp) / MIN_NAME_LINE_LEN)
    return false;

  for (uint64_t i = 0; i < n_names; ++i) {
    char name[DARKNAME_MAX_LEN + 1];
    darkname_entry_t *entry;
    ed25519_public_key_t owner;
    uint64_t expires, seq;
    int n;

    /* Fields after the fifth belong to a later revision of the format. */
    if (!next_line(&cp, end, f, &n) || n < 5)
      return false;
    if (f[0].len > DARKNAME_MAX_LEN ||
        !field_to_str(&f[0], f[0].len, name, sizeof(name)) ||
        !darknames_name_is_valid(name))
      return false;
    /* Sorted, and so never repeated. */
    if (strcmp(previous, name) >= 0)
      return false;
    strlcpy(previous, name, sizeof(previous));

    /* Only the shape of the address is checked. Were a single bad address to
     * make the snapshot unusable, registering one would take every name away
     * from everyone; a bad address fails for its own name, when it is used. */
    if (!field_is_spelled_in(&f[1], HS_SERVICE_ADDR_LEN_BASE32,
                             "abcdefghijklmnopqrstuvwxyz234567") ||
        !field_to_uint(&f[2], &expires) ||
        !field_to_public_key(&f[3], &owner) ||
        !field_to_uint(&f[4], &seq) || seq < 1)
      return false;

    entry = tor_malloc_zero(sizeof(*entry));
    memcpy(entry->address, f[1].s, HS_SERVICE_ADDR_LEN_BASE32);
    entry->expires = expires;
    strmap_set(snapshot->names, name, entry);
  }

  /* The names must be all that was left. */
  return cp == end;
}

/** Parse and verify the snapshot in the <b>len</b> bytes at <b>text</b>.
 *
 * Its signing key has to be certified by <b>root_key</b>, and it has to be
 * in force at the time <b>now</b>. If <b>accepted</b> is not NULL, it is the
 * freshness of the last snapshot that we accepted, and this one must not be
 * older.
 *
 * Return a new snapshot, or NULL if this one must not be used; then
 * *<b>problem_out</b> is set to a string constant that says why.
 */
STATIC darknames_snapshot_t *
darknames_snapshot_parse(const char *text, size_t len,
                         const ed25519_public_key_t *root_key,
                         time_t now,
                         const darknames_freshness_t *accepted,
                         const char **problem_out)
{
  const char *cp = text, *end = text + len;
  const char *certified, *last_line;
  darknames_snapshot_t *snapshot = NULL;
  ed25519_public_key_t signing_key;
  ed25519_signature_t signature;
  uint64_t certificate_expires;
  field_t f[MAX_FIELDS];
  int n;

  /* Until the signatures have been checked, we look at as little of the text
   * as it takes to check them: three lines. */
  *problem_out = "it is malformed";
  if (len < 2 || text[len - 1] != '\n' || memchr(text, '\0', len))
    return NULL;
  if (!next_line(&cp, end, f, &n) || n != 2 ||
      (size_t)(cp - text) != strlen(SNAPSHOT_VERSION_LINE) + 1 ||
      fast_memneq(text, SNAPSHOT_VERSION_LINE, strlen(SNAPSHOT_VERSION_LINE)))
    return NULL;

  /* The certificate: the root key's signature on the signing key and on
   * when the certificate expires, as those two fields are spelled. */
  if (!next_keyword_line(&cp, end, "signing-key", 3, f) ||
      !field_to_public_key(&f[1], &signing_key) ||
      !field_to_uint(&f[2], &certificate_expires) ||
      !field_to_signature(&f[3], &signature))
    return NULL;
  certified = f[1].s;
  if (ed25519_checksig_prefixed(&signature, (const uint8_t *)certified,
                                (size_t)(f[2].s + f[2].len - certified),
                                SIGNING_KEY_DOMAIN, root_key) < 0) {
    *problem_out = "its signing key is not certified by the root key";
    return NULL;
  }

  /* The last line is the signing key's signature on all the lines before
   * it. */
  last_line = end - 1;
  while (last_line > cp && last_line[-1] != '\n')
    --last_line;
  if (last_line < cp)
    return NULL;
  {
    const char *lp = last_line;
    if (!next_keyword_line(&lp, end, "signature", 1, f) || lp != end ||
        !field_to_signature(&f[1], &signature))
      return NULL;
  }
  if (ed25519_checksig_prefixed(&signature, (const uint8_t *)text,
                                (size_t)(last_line - text),
                                SNAPSHOT_DOMAIN, &signing_key) < 0) {
    *problem_out = "it is not signed by the signing key";
    return NULL;
  }

  /* From here on the text is the registry's own. */
  snapshot = tor_malloc_zero(sizeof(*snapshot));
  snapshot->names = strmap_new();
  snapshot->certificate_expires = certificate_expires;
  if (!parse_authenticated_body(snapshot, cp, last_line, problem_out))
    goto err;

  if (snapshot->created > snapshot->valid_until) {
    *problem_out = "it was never valid";
    goto err;
  }
  if (now < 0 || (uint64_t)now > snapshot->valid_until) {
    *problem_out = "it is no longer valid";
    goto err;
  }
  if ((uint64_t)now > snapshot->certificate_expires) {
    *problem_out = "the certificate of its signing key has expired";
    goto err;
  }
  if (accepted && (snapshot->head_index < accepted->head_index ||
                   snapshot->created < accepted->created)) {
    *problem_out = "it is older than one that was accepted before";
    goto err;
  }

  *problem_out = NULL;
  return snapshot;

 err:
  darknames_snapshot_free(snapshot);
  return NULL;
}

/** Look <b>name</b> up in <b>snapshot</b> at the time <b>now</b>. If it is
 * found, write the address it points to, which is HS_SERVICE_ADDR_LEN_BASE32
 * characters and a NUL, to <b>address_out</b>. */
STATIC darkname_result_t
darknames_snapshot_lookup(const darknames_snapshot_t *snapshot,
                          const char *name, time_t now, char *address_out)
{
  const darkname_entry_t *entry;

  /* A snapshot goes out of date while we hold it. */
  if (now < 0 || (uint64_t)now > snapshot->valid_until ||
      (uint64_t)now > snapshot->certificate_expires)
    return DARKNAME_UNAVAILABLE;

  entry = strmap_get(snapshot->names, name);
  /* So does a name, and that may be sooner. */
  if (!entry || entry->expires <= (uint64_t)now)
    return DARKNAME_NOT_FOUND;

  strlcpy(address_out, entry->address, HS_SERVICE_ADDR_LEN_BASE32 + 1);
  return DARKNAME_FOUND;
}

STATIC int
darknames_snapshot_n_names(const darknames_snapshot_t *snapshot)
{
  return strmap_size(snapshot->names);
}

/** The snapshot that names are resolved from, or NULL if there is none. */
static darknames_snapshot_t *current_snapshot = NULL;
/** The root key that current_snapshot was verified with, in base64. */
static char *current_root_key = NULL;
/** When we last looked at the snapshot file. */
static time_t last_checked = 0;
/** How the snapshot file ended when we last examined it, whether or not what
 * it held was any good. A snapshot ends with its signature, so two that
 * differ anywhere end differently: this is how we tell that the file has
 * changed. Its size and time would not do, since both can stay the same. */
static char examined_tail[ED25519_SIG_BASE64_LEN + 16] = "";

/** Return the base64 of the root key that is in force, or NULL. */
static const char *
get_root_key_base64(const or_options_t *options)
{
  return options->DarkNamesRootKey ? options->DarkNamesRootKey
                                   : DARKNAMES_BUILTIN_ROOT_KEY;
}

/** Set <b>freshness_out</b> to what we wrote down of the last snapshot that
 * we accepted, and return true; or return false if we wrote nothing down. */
static bool
read_accepted(darknames_freshness_t *freshness_out)
{
  char *fname = get_datadir_fname2("dark_names", "accepted");
  char *text = read_file_to_str(fname, RFTS_BIN | RFTS_IGNORE_MISSING, NULL);
  bool ok = false;
  if (text) {
    const char *cp = text, *end = text + strlen(text);
    field_t f[MAX_FIELDS];
    int n;
    ok = next_line(&cp, end, f, &n) && n == 2 && cp == end &&
      field_to_uint(&f[0], &freshness_out->head_index) &&
      field_to_uint(&f[1], &freshness_out->created);
    if (!ok)
      log_warn(LD_GENERAL, "Ignoring %s: it is malformed.", escaped(fname));
  }
  tor_free(text);
  tor_free(fname);
  return ok;
}

static void
write_accepted(const darknames_snapshot_t *snapshot)
{
  char *fname = get_datadir_fname2("dark_names", "accepted");
  char buf[64];
  tor_snprintf(buf, sizeof(buf), "%"PRIu64" %"PRIu64"\n",
               snapshot->head_index, snapshot->created);
  if (write_str_to_file(fname, buf, 1) < 0)
    log_warn(LD_GENERAL, "Could not write %s.", escaped(fname));
  tor_free(fname);
}

/** Read the snapshot file if it has changed since we last read it, and make
 * it the one that names are resolved from if it is good. A file that is not
 * good changes nothing: the snapshot we have stays for as long as it is
 * valid. */
static void
maybe_reload(time_t now)
{
  static ratelim_t problem_limit = RATELIM_INIT(3600);
  const or_options_t *options = get_options();
  const char *root_key_base64 = get_root_key_base64(options);
  const int interval = options->TestingTorNetwork ? 0
                                                  : DARKNAMES_CHECK_INTERVAL;
  ed25519_public_key_t root_key;
  darknames_freshness_t accepted;
  darknames_snapshot_t *snapshot;
  const char *problem = NULL;
  struct stat st;
  char *fname, *text;
  bool key_changed;

  if (last_checked && now >= last_checked && now - last_checked < interval)
    return;
  last_checked = now;

  key_changed = !current_root_key != !root_key_base64 ||
    (root_key_base64 && strcmp(current_root_key, root_key_base64));
  if (key_changed) {
    /* What we hold was vouched for by a key that is no longer the one we
     * trust. */
    darknames_snapshot_free(current_snapshot);
    tor_free(current_root_key);
    if (root_key_base64)
      current_root_key = tor_strdup(root_key_base64);
    examined_tail[0] = '\0';
  }
  if (!root_key_base64 || !parse_public_key(root_key_base64, &root_key))
    return;

  fname = get_datadir_fname2("dark_names", "snapshot");
  text = read_file_to_str(fname, RFTS_BIN | RFTS_IGNORE_MISSING, &st);
  if (!text)
    goto done;
  {
    const size_t len = (size_t)st.st_size;
    const size_t tail_len = MIN(len, sizeof(examined_tail) - 1);
    const char *tail = text + len - tail_len;
    if (strlen(examined_tail) == tail_len &&
        fast_memeq(examined_tail, tail, tail_len))
      goto done;
    /* A NUL in here makes the two never compare equal, which only means
     * that such a file is examined again each time. */
    memcpy(examined_tail, tail, tail_len);
    examined_tail[tail_len] = '\0';
  }

  snapshot = darknames_snapshot_parse(text, (size_t)st.st_size, &root_key, now,
                                      read_accepted(&accepted) ? &accepted
                                                               : NULL,
                                      &problem);
  if (!snapshot) {
    log_fn_ratelim(&problem_limit, LOG_WARN, LD_GENERAL,
                   "Not using the names snapshot in %s: %s.",
                   escaped(fname), problem);
    goto done;
  }
  darknames_snapshot_free(current_snapshot);
  current_snapshot = snapshot;
  write_accepted(snapshot);
  log_notice(LD_GENERAL, "Loaded a names snapshot with %d names.",
             darknames_snapshot_n_names(snapshot));

 done:
  tor_free(text);
  tor_free(fname);
}

/** Look <b>name</b> up in the registry's snapshot. If it is registered,
 * write the service address that it points to, which is
 * HS_SERVICE_ADDR_LEN_BASE32 characters and a NUL, to <b>address_out</b>,
 * and return DARKNAME_FOUND.
 *
 * The address is as the registry gave it: the caller has to validate it
 * like any other address. */
darkname_result_t
darknames_lookup(const char *name, char *address_out)
{
  const time_t now = approx_time();
  maybe_reload(now);
  if (!current_snapshot)
    return DARKNAME_UNAVAILABLE;
  return darknames_snapshot_lookup(current_snapshot, name, now, address_out);
}

/** Free all storage held in this file. */
void
darknames_free_all(void)
{
  darknames_snapshot_free(current_snapshot);
  tor_free(current_root_key);
  last_checked = 0;
  examined_tail[0] = '\0';
}

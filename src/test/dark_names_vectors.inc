/* Test vectors for the names snapshot. This file is generated: it is
 * written by registry/tests/vectors.py of the Dark repository, from the
 * same objects as the vectors that the registry itself is tested
 * against. Do not edit it here. */

#define DARK_VECTOR_CREATED 1800000000
#define DARK_VECTOR_VALID_UNTIL 1801209600
#define DARK_VECTOR_CERTIFICATE_EXPIRES 1807776000
#define DARK_VECTOR_HEAD_INDEX 13
#define DARK_VECTOR_DAY 86400
#define DARK_VECTOR_ROOT_KEY "wwk+MobHvShLivkD2PxuyJc0N2LPBUEpzJMR6UedgWE"
#define DARK_VECTOR_ADDRESS_SITE "nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd"
#define DARK_VECTOR_ADDRESS_SHOP "p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad"

static const char DARK_VECTOR_VALID[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 AnWdIhWne7YCrEAiwqINR5vZYex2NMLT+iq5wH02da2nJIQXxbTC69zmjPMXNUqlji4rh+iAlbf5ABpxwgCkAg\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000000\n"
  "valid-until 1801209600\n"
  "names 6\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature 43gAce1A7oHVq6j8YrcmE55GzFsHiiNAG8riZH9GO4pOc9M5x4kGprRdym5PZ2gE4GTycN+zSqjPTKsrpMGVDQ\n";

static const char DARK_VECTOR_TAMPERED[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 AnWdIhWne7YCrEAiwqINR5vZYex2NMLT+iq5wH02da2nJIQXxbTC69zmjPMXNUqlji4rh+iAlbf5ABpxwgCkAg\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000000\n"
  "valid-until 1801209600\n"
  "names 6\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature 43gAce1A7oHVq6j8YrcmE55GzFsHiiNAG8riZH9GO4pOc9M5x4kGprRdym5PZ2gE4GTycN+zSqjPTKsrpMGVDQ\n";

static const char DARK_VECTOR_EXTRA_FIELDS[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 AnWdIhWne7YCrEAiwqINR5vZYex2NMLT+iq5wH02da2nJIQXxbTC69zmjPMXNUqlji4rh+iAlbf5ABpxwgCkAg\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000000\n"
  "valid-until 1801209600\n"
  "names 6\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1 later-field\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature Y11jYolJvc5BywSF5E1XUsLFvP/MXzPVwzdkiu6nziDoJE75oYYNhtv6QQUNU8/MGtQiL6Sgi8w+Kjk85aCBDA\n";

static const char DARK_VECTOR_WRONG_ROOT[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 ZTIt22uJiEES7TXOn+27g5MnR72CuQM3NpLjobzfbaQxGQ0pwVYSWpkHBR3ilgRrFLDycAn0NmqEGrPuN0qNBw\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000000\n"
  "valid-until 1801209600\n"
  "names 6\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature Z3nUE3Z0EtNisixG0AHYjj1k83R1ms0UsQ4fEoSEMiJF4U4D5YbYcRzvkp+yXQlckAj2Phi31TUq2jNuxevVCA\n";

static const char DARK_VECTOR_SHORT_CERTIFICATE[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1800086400 4XYRZ+a3YYBTBxJ+lv2P9Hv3Mmyknb4asopUezYTdwJM2Leu/WCM4DyrDt+7zHj0akqz4YOhPkXk1Tj1w1jJDw\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000000\n"
  "valid-until 1801209600\n"
  "names 6\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature eKzqVzJ8thCZZe5OEfoYJh/7xaUiQM2Oz8U48QaIV6SZ4gzcDpBNBhlWffXaacrnZy9kMzevxsbbzClKp1ZPBQ\n";

static const char DARK_VECTOR_MOVED[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 AnWdIhWne7YCrEAiwqINR5vZYex2NMLT+iq5wH02da2nJIQXxbTC69zmjPMXNUqlji4rh+iAlbf5ABpxwgCkAg\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000060\n"
  "valid-until 1801209660\n"
  "names 6\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature fDVoKewfI0nB1XfwksNbQ1c2+xYjpgoznj+YFg1JTojMRm6q9lDrV4uyk0LZUBro5tYjMTNINMClQTUD0AOtCQ\n";

static const char DARK_VECTOR_UNSORTED[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 AnWdIhWne7YCrEAiwqINR5vZYex2NMLT+iq5wH02da2nJIQXxbTC69zmjPMXNUqlji4rh+iAlbf5ABpxwgCkAg\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000000\n"
  "valid-until 1801209600\n"
  "names 6\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature mrRQhwnqGxWQWGYJOKb3Bj/1FmmnCt1a2irc3X5KgJ3MSk67uDVp4+1qExYrGbkozJ13tteCNQq/JoFjChGgDQ\n";

static const char DARK_VECTOR_DUPLICATE[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 AnWdIhWne7YCrEAiwqINR5vZYex2NMLT+iq5wH02da2nJIQXxbTC69zmjPMXNUqlji4rh+iAlbf5ABpxwgCkAg\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000000\n"
  "valid-until 1801209600\n"
  "names 7\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature coXFroKdSK2G2dK7vp88r8hKj3mJwW0WsBaWaA1kir4a1R1VdwSo1xA0t0JFFc8p6WUXIxRMAdzQcqeIlTrrDQ\n";

static const char DARK_VECTOR_COUNT_LOW[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 AnWdIhWne7YCrEAiwqINR5vZYex2NMLT+iq5wH02da2nJIQXxbTC69zmjPMXNUqlji4rh+iAlbf5ABpxwgCkAg\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000000\n"
  "valid-until 1801209600\n"
  "names 5\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature QrNr+DknA4ZKDgQe551Ts3M8mfFol9dx98UebWjHqh5hLaJj52aFC/OLtudknckz03JGAXSYHSBWRjGQ6yp1Bw\n";

static const char DARK_VECTOR_COUNT_HIGH[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 AnWdIhWne7YCrEAiwqINR5vZYex2NMLT+iq5wH02da2nJIQXxbTC69zmjPMXNUqlji4rh+iAlbf5ABpxwgCkAg\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000000\n"
  "valid-until 1801209600\n"
  "names 7\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature 7Oefe6G4D5mjtTIXN96FJMU0RHlhgky0345dxOhyppBEmN5RqxbXoc7GWfa4LiPtTUF+gRT2K8oRRkmMvIDfCw\n";

static const char DARK_VECTOR_UNKNOWN_LINE[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 AnWdIhWne7YCrEAiwqINR5vZYex2NMLT+iq5wH02da2nJIQXxbTC69zmjPMXNUqlji4rh+iAlbf5ABpxwgCkAg\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 1800000000\n"
  "valid-until 1801209600\n"
  "comment hello\n"
  "names 6\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature kaYcCNUMfOBxIAnvK7EP8wctqf8R+Nars4H32Q37JxSiHPAAN4fdbQhyy7zfAfNyLCe5JBbfxXmgT2DBzbSiDA\n";

static const char DARK_VECTOR_LEADING_ZERO[] =
  "dark-names-snapshot 1\n"
  "signing-key eZ2gzMjeIEgcao6yUzk6NnR0wU8VRcmllmNpsV28KJ8 1807776000 AnWdIhWne7YCrEAiwqINR5vZYex2NMLT+iq5wH02da2nJIQXxbTC69zmjPMXNUqlji4rh+iAlbf5ABpxwgCkAg\n"
  "head 13 f07573cf86cf8e7f7cc9f147ce8526a00bd8cdf963a095fc48a75e5761562b3c\n"
  "created 01800000000\n"
  "valid-until 1801209600\n"
  "names 6\n"
  "head nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "names nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "shop p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1825920000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 1\n"
  "signature nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1825920000 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "site p7d3utxod2jo23qpvsowsynqdosqaynltu6r62xe752obcwrkoxusjad 1828512000 AhpkgPIBBA9cNB4+uG1EJbRMwkguYdlilC6+KGzgiSQ 4\n"
  "soon nqvipb7cbqsbniuyj745ljpgjvfxnntuvmxebnef2u4qqrjgzql5kfqd 1800086400 zqXQaerrW644WwcW7GaYRu2VqQxULwsCHDxMHfaWoh4 1\n"
  "signature hrbF6OBuoYjl+7TkcUjwUvLk/mVWhzhemitiloitoAvlB15CptqTruz9qVg4xrwrbeh3+fNmS5bPixXqCZTXCQ\n";

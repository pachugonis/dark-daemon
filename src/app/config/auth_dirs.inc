/* The directory authorities of the Dark network. The authorities of the Tor
 * network are deliberately absent, so that this build can never join that
 * network by default; test_config.c checks that none of them comes back.
 *
 * Each line is what the key ceremony writes to public/da/<name>.dirauthority.
 * A new address or new relay keys of an authority need a new build for
 * everyone; a new signing key, every three months, does not. */
"da1 orport=9001 "
  "v3ident=B092166F004CDE5BEE54FAC344396BA2D45033F4 "
  "199.195.193.79:9030 AF7A 8D6F DEF4 8968 395A EE9C 98C5 E7F5 5C09 B3C2",
"da2 orport=9001 "
  "v3ident=08031054A8EACC58E16E8C32728F6E9E5C277B49 "
  "213.155.11.233:9030 1B67 F55D 197E 6C70 2C4A 9360 C0A1 F0B3 D09F 800F",
"da3 orport=9001 "
  "v3ident=1BCAC393112982949F1CAE4F794467A4BBABED38 "
  "194.76.139.113:9030 481A 4261 058A 659B CA4F F37F 0482 F876 CBC7 8DF7",

# ldd-sym

Basic utility to map symbol names to SONAMEs of libraries defining them.

Only performs some rudimentary linker search path construction (parses `DT_RUNPATH`/`DT_RPATH` from file and performs basic `ld.so.conf` parsing).

Comma-separates symbol names it encounters multipple definitions of and responds with "NO MATCHES" if no matches are found.

Example output:
```sh
$ ldd-sym -path /bin/setcap
__libc_start_main: libc.so.6
__errno_location: libc.so.6
__read_chk: libc.so.6
strlen: libc.so.6
cap_from_text: libcap.so.2
cap_get_flag: libcap.so.2
cap_set_proc: libcap.so.2
strcmp: libc.so.6
cap_init: libcap.so.2
cap_get_proc: libcap.so.2
__printf_chk: libc.so.6
cap_set_nsowner: libcap.so.2
cap_get_file: libcap.so.2
perror: libc.so.6
cap_free: libcap.so.2
strtoul: libc.so.6
cap_set_flag: libcap.so.2
exit: libc.so.6
fwrite: libc.so.6
__fprintf_chk: libc.so.6
cap_compare: libcap.so.2
strerror: libc.so.6
cap_get_nsowner: libcap.so.2
cap_set_file: libcap.so.2
__cxa_finalize: libc.so.6
stderr: libc.so.6
```

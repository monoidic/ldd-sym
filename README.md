# ldd-sym

```
Usage of ldd-sym:
  -android
        search Android paths
  -full
        do not exit out early if all symbols are resolved (default true)
  -funcs
        track functions (default true)
  -json
        output json
  -objects
        track objects (default true)
  -other
        track other symbols
  -path string
        path to file
  -profile string
        path to CPU pprof file (only profiled if set)
  -root string
        directory to consider the root for SONAME resolution (default "/")
  -std
        search standard paths (default true)
  -weak
        get weak symbols
```

Basic utility to map symbol names to SONAMEs of libraries defining them.

Performs linker search path construction based on `DT_RUNPATH`/`DT_RPATH` and `ld.so.conf`.

Allows specifying a custom root directory; resolves all absolute and relative paths as if this directory were the root. This allows it to be used for quickly analyzing binaries in a dumped rootfs.

Support json output.

Comma-separates symbol names it encounters multiple definitions of and responds with "NO MATCHES" if no matches are found.

Example output:
```sh
$ ldd-sym -path /bin/ip
bpf_program__set_type: libbpf.so.0
__strcat_chk: libc.so.6
inet_ntop: libc.so.6
getenv: libc.so.6
gelf_getehdr: libelf.so.1
bpf_object__open_file: libbpf.so.0
bpf_map_update_elem: libbpf.so.0
__snprintf_chk: libc.so.6
free: libc.so.6
name_to_handle_at: libc.so.6
recv: libc.so.6
putchar: libc.so.6
strcasecmp: libc.so.6
localtime: libc.so.6
gelf_getshdr: libelf.so.1
__vfprintf_chk: libc.so.6
__libc_start_main: libc.so.6
__errno_location: libc.so.6
unlink: libc.so.6
bpf_program__priv: libbpf.so.0
strncpy: libc.so.6
elf_version: libelf.so.1
strncmp: libc.so.6
stdout: libc.so.6
_exit: libc.so.6
bpf_program__section_name: libbpf.so.0
bpf_map__next: libbpf.so.0
strcpy: libc.so.6
__isoc99_fscanf: libc.so.6
mkdir: libc.so.6
sendmsg: libc.so.6
puts: libc.so.6
ferror: libc.so.6
bpf_map__ifindex: libbpf.so.0
isatty: libc.so.6
fread: libc.so.6
stdin: libc.so.6
strtod: libc.so.6
setsockopt: libc.so.6
strchrnul: libc.so.6
unshare: libc.so.6
bpf_program__set_autoload: libbpf.so.0
readlink: libc.so.6
write: libc.so.6
bpf_object__find_map_by_name: libbpf.so.0
strlcat: libbsd.so.0
getpid: libc.so.6
lstat64: libc.so.6
umount2: libc.so.6
fclose: libc.so.6
opendir: libc.so.6
getpwuid: libc.so.6
mnl_attr_parse: libmnl.so.0
globfree64: libc.so.6
rmdir: libc.so.6
bpf_map__name: libbpf.so.0
strlen: libc.so.6
mount: libc.so.6
__stack_chk_fail: libc.so.6
getuid: libc.so.6
asctime: libc.so.6
stat64: libc.so.6
send: libc.so.6
strchr: libc.so.6
bpf_obj_get: libbpf.so.0
gelf_getsym: libelf.so.1
getgrgid: libc.so.6
symlink: libc.so.6
snprintf: libc.so.6
setns: libc.so.6
elf_strptr: libelf.so.1
strrchr: libc.so.6
setrlimit64: libc.so.6
gettimeofday: libc.so.6
__assert_fail: libc.so.6
fputs: libc.so.6
statfs64: libc.so.6
strtof: libc.so.6
fnmatch: libc.so.6
memset: libc.so.6
geteuid: libc.so.6
ioctl: libc.so.6
bpf_program__set_ifindex: libbpf.so.0
bpf_create_map_xattr: libbpf.so.0
fgetc: libc.so.6
close: libc.so.6
bpf_object__load: libbpf.so.0
strspn: libc.so.6
closedir: libc.so.6
fputc: libc.so.6
elf_getdata: libelf.so.1
strcspn: libc.so.6
cap_get_flag: libcap.so.2
read: libc.so.6
memcmp: libc.so.6
fgets: libc.so.6
strtoull: libc.so.6
__asprintf_chk: libc.so.6
calloc: libc.so.6
__getdelim: libc.so.6
cap_set_proc: libcap.so.2
strcmp: libc.so.6
putc: libc.so.6
dlopen: libc.so.6
bpf_map__reuse_fd: libbpf.so.0
strtoll: libc.so.6
getpwnam: libc.so.6
bpf_map__set_ifindex: libbpf.so.0
__memcpy_chk: libc.so.6
syscall: libc.so.6
ftell: libc.so.6
basename: libc.so.6
feof: libc.so.6
if_nametoindex: libc.so.6
fopen64: libc.so.6
strtol: libc.so.6
elf_end: libelf.so.1
freopen64: libc.so.6
glob64: libc.so.6
strlcpy: libbsd.so.0
memcpy: libc.so.6
getgrnam: libc.so.6
inet_pton: libc.so.6
inotify_init: libc.so.6
getprotobynumber: libc.so.6
sendfile64: libc.so.6
time: libc.so.6
fileno: libc.so.6
bpf_map__set_pin_path: libbpf.so.0
bpf_load_program: libbpf.so.0
open_by_handle_at: libc.so.6
malloc: libc.so.6
fflush: libc.so.6
inotify_add_watch: libc.so.6
cap_get_proc: libcap.so.2
strsep: libc.so.6
__isoc99_sscanf: libc.so.6
mnl_attr_validate: libmnl.so.0
getprotobyname: libc.so.6
fseek: libc.so.6
libbpf_get_error: libbpf.so.0
bpf_program__fd: libbpf.so.0
if_indextoname: libc.so.6
elf_begin: libelf.so.1
mnl_attr_get_str: libmnl.so.0
realloc: libc.so.6
__strcpy_chk: libc.so.6
mnl_attr_type_valid: libmnl.so.0
mnl_attr_get_type: libmnl.so.0
mnl_nlmsg_get_payload_len: libmnl.so.0
recvmsg: libc.so.6
__printf_chk: libc.so.6
bind: libc.so.6
open64: libc.so.6
strftime: libc.so.6
fcntl64: libc.so.6
ether_ntoa_r: libc.so.6
readdir64: libc.so.6
bpf_object__close: libbpf.so.0
waitpid: libc.so.6
getpass: libc.so.6
sethostent: libc.so.6
cap_clear: libcap.so.2
libbpf_set_print: libbpf.so.0
perror: libc.so.6
mnl_nlmsg_get_payload: libmnl.so.0
strtok: libc.so.6
sysconf: libc.so.6
cap_free: libcap.so.2
dlsym: libc.so.6
mnl_attr_get_u32: libmnl.so.0
accept: libc.so.6
getsockname: libc.so.6
strtoul: libc.so.6
execvp: libc.so.6
flock: libc.so.6
strcat: libc.so.6
gethostbyaddr: libc.so.6
exit: libc.so.6
connect: libc.so.6
fwrite: libc.so.6
elf_getscn: libelf.so.1
__fprintf_chk: libc.so.6
bpf_prog_attach: libbpf.so.0
fstat64: libc.so.6
bpf_map__is_offload_neutral: libbpf.so.0
strdup: libc.so.6
strerror: libc.so.6
bpf_program__set_priv: libbpf.so.0
bpf_program__next: libbpf.so.0
fork: libc.so.6
strstr: libc.so.6
elf_kind: libelf.so.1
bpf_map__fd: libbpf.so.0
__ctype_b_loc: libc.so.6
statvfs64: libc.so.6
stderr: libc.so.6
__sprintf_chk: libc.so.6
socket: libc.so.6
__cxa_finalize: libc.so.6

libbpf.so.0: /usr/lib/x86_64-linux-gnu/libbpf.so.0.5.0
libelf.so.1: /usr/lib/x86_64-linux-gnu/libelf-0.186.so
libmnl.so.0: /usr/lib/x86_64-linux-gnu/libmnl.so.0.2.0
libbsd.so.0: /usr/lib/x86_64-linux-gnu/libbsd.so.0.11.5
libcap.so.2: /usr/lib/x86_64-linux-gnu/libcap.so.2.44
libc.so.6: /usr/lib/x86_64-linux-gnu/libc.so.6
$ ./ldd-sym -path /bin/ip -json
{"Syms":["bpf_program__set_type","__strcat_chk","inet_ntop","getenv","gelf_getehdr","bpf_object__open_file","bpf_map_update_elem","__snprintf_chk","free","name_to_handle_at","recv","putchar","strcasecmp","localtime","gelf_getshdr","__vfprintf_chk","__libc_start_main","__errno_location","unlink","bpf_program__priv","strncpy","elf_version","strncmp","stdout","_exit","bpf_program__section_name","bpf_map__next","strcpy","__isoc99_fscanf","mkdir","sendmsg","puts","ferror","bpf_map__ifindex","isatty","fread","stdin","strtod","setsockopt","strchrnul","unshare","bpf_program__set_autoload","readlink","write","bpf_object__find_map_by_name","strlcat","getpid","lstat64","umount2","fclose","opendir","getpwuid","mnl_attr_parse","globfree64","rmdir","bpf_map__name","strlen","mount","__stack_chk_fail","getuid","asctime","stat64","send","strchr","bpf_obj_get","gelf_getsym","getgrgid","symlink","snprintf","setns","elf_strptr","strrchr","setrlimit64","gettimeofday","__assert_fail","fputs","statfs64","strtof","fnmatch","memset","geteuid","ioctl","bpf_program__set_ifindex","bpf_create_map_xattr","fgetc","close","bpf_object__load","strspn","closedir","fputc","elf_getdata","strcspn","cap_get_flag","read","memcmp","fgets","strtoull","__asprintf_chk","calloc","__getdelim","cap_set_proc","strcmp","putc","dlopen","bpf_map__reuse_fd","strtoll","getpwnam","bpf_map__set_ifindex","__memcpy_chk","syscall","ftell","basename","feof","if_nametoindex","fopen64","strtol","elf_end","freopen64","glob64","strlcpy","memcpy","getgrnam","inet_pton","inotify_init","getprotobynumber","sendfile64","time","fileno","bpf_map__set_pin_path","bpf_load_program","open_by_handle_at","malloc","fflush","inotify_add_watch","cap_get_proc","strsep","__isoc99_sscanf","mnl_attr_validate","getprotobyname","fseek","libbpf_get_error","bpf_program__fd","if_indextoname","elf_begin","mnl_attr_get_str","realloc","__strcpy_chk","mnl_attr_type_valid","mnl_attr_get_type","mnl_nlmsg_get_payload_len","recvmsg","__printf_chk","bind","open64","strftime","fcntl64","ether_ntoa_r","readdir64","bpf_object__close","waitpid","getpass","sethostent","cap_clear","libbpf_set_print","perror","mnl_nlmsg_get_payload","strtok","sysconf","cap_free","dlsym","mnl_attr_get_u32","accept","getsockname","strtoul","execvp","flock","strcat","gethostbyaddr","exit","connect","fwrite","elf_getscn","__fprintf_chk","bpf_prog_attach","fstat64","bpf_map__is_offload_neutral","strdup","strerror","bpf_program__set_priv","bpf_program__next","fork","strstr","elf_kind","bpf_map__fd","__ctype_b_loc","statvfs64","stderr","__sprintf_chk","socket","__cxa_finalize"],"Sonames":["libbpf.so.0","libelf.so.1","libmnl.so.0","libbsd.so.0","libcap.so.2","libc.so.6"],"SymnameToSonames":{"__asprintf_chk":["libc.so.6"],"__assert_fail":["libc.so.6"],"__ctype_b_loc":["libc.so.6"],"__cxa_finalize":["libc.so.6"],"__errno_location":["libc.so.6"],"__fprintf_chk":["libc.so.6"],"__getdelim":["libc.so.6"],"__isoc99_fscanf":["libc.so.6"],"__isoc99_sscanf":["libc.so.6"],"__libc_start_main":["libc.so.6"],"__memcpy_chk":["libc.so.6"],"__printf_chk":["libc.so.6"],"__snprintf_chk":["libc.so.6"],"__sprintf_chk":["libc.so.6"],"__stack_chk_fail":["libc.so.6"],"__strcat_chk":["libc.so.6"],"__strcpy_chk":["libc.so.6"],"__vfprintf_chk":["libc.so.6"],"_exit":["libc.so.6"],"accept":["libc.so.6"],"asctime":["libc.so.6"],"basename":["libc.so.6"],"bind":["libc.so.6"],"bpf_create_map_xattr":["libbpf.so.0"],"bpf_load_program":["libbpf.so.0"],"bpf_map__fd":["libbpf.so.0"],"bpf_map__ifindex":["libbpf.so.0"],"bpf_map__is_offload_neutral":["libbpf.so.0"],"bpf_map__name":["libbpf.so.0"],"bpf_map__next":["libbpf.so.0"],"bpf_map__reuse_fd":["libbpf.so.0"],"bpf_map__set_ifindex":["libbpf.so.0"],"bpf_map__set_pin_path":["libbpf.so.0"],"bpf_map_update_elem":["libbpf.so.0"],"bpf_obj_get":["libbpf.so.0"],"bpf_object__close":["libbpf.so.0"],"bpf_object__find_map_by_name":["libbpf.so.0"],"bpf_object__load":["libbpf.so.0"],"bpf_object__open_file":["libbpf.so.0"],"bpf_prog_attach":["libbpf.so.0"],"bpf_program__fd":["libbpf.so.0"],"bpf_program__next":["libbpf.so.0"],"bpf_program__priv":["libbpf.so.0"],"bpf_program__section_name":["libbpf.so.0"],"bpf_program__set_autoload":["libbpf.so.0"],"bpf_program__set_ifindex":["libbpf.so.0"],"bpf_program__set_priv":["libbpf.so.0"],"bpf_program__set_type":["libbpf.so.0"],"calloc":["libc.so.6"],"cap_clear":["libcap.so.2"],"cap_free":["libcap.so.2"],"cap_get_flag":["libcap.so.2"],"cap_get_proc":["libcap.so.2"],"cap_set_proc":["libcap.so.2"],"close":["libc.so.6"],"closedir":["libc.so.6"],"connect":["libc.so.6"],"dlopen":["libc.so.6"],"dlsym":["libc.so.6"],"elf_begin":["libelf.so.1"],"elf_end":["libelf.so.1"],"elf_getdata":["libelf.so.1"],"elf_getscn":["libelf.so.1"],"elf_kind":["libelf.so.1"],"elf_strptr":["libelf.so.1"],"elf_version":["libelf.so.1"],"ether_ntoa_r":["libc.so.6"],"execvp":["libc.so.6"],"exit":["libc.so.6"],"fclose":["libc.so.6"],"fcntl64":["libc.so.6"],"feof":["libc.so.6"],"ferror":["libc.so.6"],"fflush":["libc.so.6"],"fgetc":["libc.so.6"],"fgets":["libc.so.6"],"fileno":["libc.so.6"],"flock":["libc.so.6"],"fnmatch":["libc.so.6"],"fopen64":["libc.so.6"],"fork":["libc.so.6"],"fputc":["libc.so.6"],"fputs":["libc.so.6"],"fread":["libc.so.6"],"free":["libc.so.6"],"freopen64":["libc.so.6"],"fseek":["libc.so.6"],"fstat64":["libc.so.6"],"ftell":["libc.so.6"],"fwrite":["libc.so.6"],"gelf_getehdr":["libelf.so.1"],"gelf_getshdr":["libelf.so.1"],"gelf_getsym":["libelf.so.1"],"getenv":["libc.so.6"],"geteuid":["libc.so.6"],"getgrgid":["libc.so.6"],"getgrnam":["libc.so.6"],"gethostbyaddr":["libc.so.6"],"getpass":["libc.so.6"],"getpid":["libc.so.6"],"getprotobyname":["libc.so.6"],"getprotobynumber":["libc.so.6"],"getpwnam":["libc.so.6"],"getpwuid":["libc.so.6"],"getsockname":["libc.so.6"],"gettimeofday":["libc.so.6"],"getuid":["libc.so.6"],"glob64":["libc.so.6"],"globfree64":["libc.so.6"],"if_indextoname":["libc.so.6"],"if_nametoindex":["libc.so.6"],"inet_ntop":["libc.so.6"],"inet_pton":["libc.so.6"],"inotify_add_watch":["libc.so.6"],"inotify_init":["libc.so.6"],"ioctl":["libc.so.6"],"isatty":["libc.so.6"],"libbpf_get_error":["libbpf.so.0"],"libbpf_set_print":["libbpf.so.0"],"localtime":["libc.so.6"],"lstat64":["libc.so.6"],"malloc":["libc.so.6"],"memcmp":["libc.so.6"],"memcpy":["libc.so.6"],"memset":["libc.so.6"],"mkdir":["libc.so.6"],"mnl_attr_get_str":["libmnl.so.0"],"mnl_attr_get_type":["libmnl.so.0"],"mnl_attr_get_u32":["libmnl.so.0"],"mnl_attr_parse":["libmnl.so.0"],"mnl_attr_type_valid":["libmnl.so.0"],"mnl_attr_validate":["libmnl.so.0"],"mnl_nlmsg_get_payload":["libmnl.so.0"],"mnl_nlmsg_get_payload_len":["libmnl.so.0"],"mount":["libc.so.6"],"name_to_handle_at":["libc.so.6"],"open64":["libc.so.6"],"open_by_handle_at":["libc.so.6"],"opendir":["libc.so.6"],"perror":["libc.so.6"],"putc":["libc.so.6"],"putchar":["libc.so.6"],"puts":["libc.so.6"],"read":["libc.so.6"],"readdir64":["libc.so.6"],"readlink":["libc.so.6"],"realloc":["libc.so.6"],"recv":["libc.so.6"],"recvmsg":["libc.so.6"],"rmdir":["libc.so.6"],"send":["libc.so.6"],"sendfile64":["libc.so.6"],"sendmsg":["libc.so.6"],"sethostent":["libc.so.6"],"setns":["libc.so.6"],"setrlimit64":["libc.so.6"],"setsockopt":["libc.so.6"],"snprintf":["libc.so.6"],"socket":["libc.so.6"],"stat64":["libc.so.6"],"statfs64":["libc.so.6"],"statvfs64":["libc.so.6"],"stderr":["libc.so.6"],"stdin":["libc.so.6"],"stdout":["libc.so.6"],"strcasecmp":["libc.so.6"],"strcat":["libc.so.6"],"strchr":["libc.so.6"],"strchrnul":["libc.so.6"],"strcmp":["libc.so.6"],"strcpy":["libc.so.6"],"strcspn":["libc.so.6"],"strdup":["libc.so.6"],"strerror":["libc.so.6"],"strftime":["libc.so.6"],"strlcat":["libbsd.so.0"],"strlcpy":["libbsd.so.0"],"strlen":["libc.so.6"],"strncmp":["libc.so.6"],"strncpy":["libc.so.6"],"strrchr":["libc.so.6"],"strsep":["libc.so.6"],"strspn":["libc.so.6"],"strstr":["libc.so.6"],"strtod":["libc.so.6"],"strtof":["libc.so.6"],"strtok":["libc.so.6"],"strtol":["libc.so.6"],"strtoll":["libc.so.6"],"strtoul":["libc.so.6"],"strtoull":["libc.so.6"],"symlink":["libc.so.6"],"syscall":["libc.so.6"],"sysconf":["libc.so.6"],"time":["libc.so.6"],"umount2":["libc.so.6"],"unlink":["libc.so.6"],"unshare":["libc.so.6"],"waitpid":["libc.so.6"],"write":["libc.so.6"]},"SonamePaths":{"libbpf.so.0":["/usr/lib/x86_64-linux-gnu/libbpf.so.0.5.0"],"libbsd.so.0":["/usr/lib/x86_64-linux-gnu/libbsd.so.0.11.5"],"libc.so.6":["/usr/lib/x86_64-linux-gnu/libc.so.6"],"libcap.so.2":["/usr/lib/x86_64-linux-gnu/libcap.so.2.44"],"libelf.so.1":["/usr/lib/x86_64-linux-gnu/libelf-0.186.so"],"libmnl.so.0":["/usr/lib/x86_64-linux-gnu/libmnl.so.0.2.0"]},"UnneededSonames":[],"UndefinedSyms":[]}
```

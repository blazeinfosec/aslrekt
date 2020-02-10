# aslrekt

![ASLR](https://github.com/blazeinfosec/aslrekt/blob/master/ASLR%20B.jpg)

ASLREKT is a proof of concept for an unfixed generic local ASLR bypass in Linux.

ASLREKT requires a setuid binary that reads from stdin and writes to stdout/stderr (or to a readable file) the 
contents that it read.

/proc/pid/stat is world-readable, however, if we aren't permitted to ptrace pid (!ptrace_may_access()),
addresses aren't leaked and, instead, they are replaced with 0. The problem is that we can open() /proc/pid/stat
and pass the fd as stdin of a newly executed special setuid binary (which can now ptrace pid) and read
those addresses. In order for an attacker to be able to actually obtain them, the special setuid binary needs 
to write to stdout/stderr or readable file the contents that it read. There are several setuid binaries that do
this, such as "procmail" which seems to be setuid on Debian-based systems, this includes Ubuntu. Another
alternative is "spice-client-glib-usb-acl-helper". There may be more of these. This breaks ASLR for any process
running under another uid, such as root.

It's also possible to leak addresses via /proc/pid/syscall, it isn't world-readable, but we can open() it before a
target setuid execve, and later leak them through the special setuid binary method.

Modern Linux versions are still vulnerable.

Copyright 2016-2020, Blaze Information Security

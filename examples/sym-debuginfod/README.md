sym-debuginfod
==============

An example illustrating advanced usage scenarios of **blazesym**, by using a
[debuginfod][] client for retrieving debug information.

## Usage
```
$ echo $DEBUGINFOD_URLS
> https://debuginfod.fedoraproject.org/
# PID and addresses we captured out-of-band.
$ cargo run --package sym-debuginfod -- 3738900 0x7fd4e762a100 0x7fd4e762d200
> 0x007fd4e762a100: _init @ 0xe000+0x100
> 0x007fd4e762d200: gobject_init @ 0x10400+0xe00 /usr/src/debug/glib2-2.78.3-1.fc39.x86_64/redhat-linux-build/../gobject/gtype.c:4608:3
>                   _g_value_transforms_init @ /usr/src/debug/glib2-2.78.3-1.fc39.x86_64/redhat-linux-build/../gobject/gvaluetransform.c:321:3 [inlined]
```

To increase debug output to see more of what is going on, append the `-v` switch
one or more times.

Use `--help` to get general usage information:
```
$ cargo run --package sym-debuginfod -- --help
```

[debuginfod]: https://sourceware.org/elfutils/Debuginfod.html

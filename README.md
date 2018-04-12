# readelf-python

Python tool to read ELF format, more hackable than GNU's readelf.

> ELF: Executable and Linkable Format, the usual format of Unix/Linux's binaries.

Originated from my pull request to @detailyang's [readelf](https://github.com/detailyang/readelf).

Options:
```
usage: readelf.py [-h] [-v] [-eh] [-ph] [-sh] [-it] [-st] [-ds] [-a] file

positional arguments:
  file                  path to the ELF file

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         version info
  -eh, --elf-header     print ELF header
  -ph, --program-header
                        print program headers
  -sh, --section-header
                        print section headers
  -it, --interp         print interp, i.e. the dynamic loader (itself a shared
                        binary)
  -st, --symbol-table   print symbol table
  -ds, --dynamic-section
                        print dynamic section
  -a, --all             print all (default)
```

More on ELF:
- [Wikipedia article](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format") (this link is less likely to be unavailable)
- [ELF specification (version 1.2) from Stanford CS140](http://www.scs.stanford.edu/18wi-cs140/sched/readings/elf.pdf)
- [Linux Journal](https://www.linuxjournal.com/article/1060)
- [GNU's extension to ELF](https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=summary), you need to read the repo yourself. Particularly [this header](gnu-binutils-elfcpp.h), last updated on 2018-01-03	by Alan Modra.

# readelf-color

This is a simple colorizer mounted to the real (GNU's) `readelf`, like this: `readelf ... | readelf-color`

###### EOF

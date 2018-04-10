# readelf-python

Python tool to read ELF format, more hackable than GNU's readelf.

> ELF: Executable and Linkable Format, the usual format of Unix/Linux's binaries.

Originated from my pull request to @detailyang's [readelf](https://github.com/detailyang/readelf).

I may make further customizations to this file so I figured I might as well create (instead of fork) the repo. My forked repo is [here](https://github.com/Leedehai/readelf).

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

###### EOF
#! /usr/bin/env python
#-*-coding: utf-8 -*-

import sys
import struct
import argparse

def print_err(err):
	print("Error: %s" % err)
	sys.exit(1)


SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_MASKPROC = 0xF0000000


TAG = {
	0:"NULL",
	1:"NEEDED",
	2:"PLTRELSZ",
	3:"PLTGOT",
	4:"HASH",
	5:"STRTAB",
	6:"SYMTAB",
	7:"RELA",
	8:"RELASZ",
	9:"RELAENT",
	10:"STRSZ",
	11:"SYMENT",
	12:"INIT",
	13:"FINI",
	14:"SONAME",
	15:"RPATH",
	16:"SYMBOLIC",
	17:"REL",
	18:"RELSZ",
	19:"RELENT",
	20:"PLTREL",
	21:"DEBUG",
	22:"TEXTREL",
	23:"JMPREL",
	24:"BIND_NOW",
	25:"INIT_ARRAY",
	26:"FINI_ARRAY",
	27:"INIT_ARRAYSZ",
	28:"FINI_ARRAYSZ",
	29:"RUNPATH",
	30:"FLAGS",
	32:"ENCODING",
	32:"PREINIT_ARRAY",
	33:"PREINIT_ARRAYSZ",
	34:"MAXPOSTAGS",
	0x6000000d:"LOOS",
	0x6000000d:"SUNW_AUXILIARY",
	0x6000000e:"SUNW_RTLDINF",
	0x6000000e:"SUNW_FILTER",
	0x60000010:"SUNW_CAP",
	0x60000011:"SUNW_SYMTAB",
	0x60000012:"SUNW_SYMSZ",
	0x60000013:"SUNW_ENCODING",
	0x60000013:"SUNW_SORTENT",
	0x60000014:"SUNW_SYMSORT",
	0x60000015:"SUNW_SYMSORTSZ",
	0x60000016:"SUNW_TLSSORT",
	0x60000017:"SUNW_TLSSORTSZ",
	0x60000018:"SUNW_CAPINFO",
	0x60000019:"SUNW_STRPAD",
	0x6000001a:"SUNW_CAPCHAIN",
	0x6000001b:"SUNW_LDMACH",
	0x6000001d:"SUNW_CAPCHAINENT",
	0x6000001f:"SUNW_CAPCHAINSZ",
	0x6ffff000:"HIOS",
	0x6ffffd00:"VALRNGLO",
	0x6ffffdf8:"CHECKSUM",
	0x6ffffdf9:"PLTPADSZ",
	0x6ffffdfa:"MOVEENT",
	0x6ffffdfb:"MOVESZ",
	0x6ffffdfd:"POSFLAG_1",
	0x6ffffdfe:"SYMINSZ",
	0x6ffffdff:"SYMINENT",
	0x6ffffdff:"VALRNGHI",
	0x6ffffe00:"ADDRRNGLO",
	0x6ffffefa:"CONFIG",
	0x6ffffefb:"DEPAUDIT",
	0x6ffffefc:"AUDIT",
	0x6ffffefd:"PLTPAD",
	0x6ffffefe:"MOVETAB",
	0x6ffffeff:"SYMINFO",
	0x6ffffeff:"ADDRRNGHI",
	0x6ffffff9:"RELACOUNT",
	0x6ffffffa:"RELCOUNT",
	0x6ffffffb:"FLAGS_1",
	0x6ffffffc:"VERDEF",
	0x6ffffffd:"VERDEFNUM",
	0x6ffffffe:"VERNEED",
	0x6fffffff:"VERNEEDNUM",
	0x70000000:"LOPROC",
	0x70000001:"SPARC_REGISTER",
	0x7ffffffd:"AUXILIARY",
	0x7ffffffe:"USED",
	0x7fffffff:"FILTER",
	0x7fffffff:"HIPROC",
}


PT_FLAGS = {
	0: "None",
	1: "E",
	2: "W",
	3: "WE",
	4: "R",
	5: "RE",
	6: "RW",
	7: "RWE"
}


PT_TYPE = {
	0: "NULL",
	1: "LOAD",
	2: "DYNAMIC",
	3: "INTERP",
	4: "NOTE",
	5: "SHLIB",
	6: "PHDR",
	7: "TLS",
	0x70000000: "LOPROC",
	0x7fffffff: "HPROC"
}


STT_TYPE = {
	0: 'NOTYPE',
	1: 'OBJECT',
	2: 'FUNC',
	3: 'SECTION',
	4: 'FILE',
	5: 'COMMON',
	6: 'TLS',
	10: 'LOOS',
	12: 'HIOS',
	13: 'LOPROC',
	15: 'HIPROC'
}


STB_BIND = {
	0: 'LOCAL',
	1: 'GLOBAL',
	2: 'WEAK',
	13: 'LOPROC',
	15: 'HIPROC'
}


STV_VISIBILITY = {
	0: 'DEFAULT',
	1: 'INTERNAL',
	2: 'HIDDEN',
	3: 'PROTECTED'
}


SH_TYPE = {
	0:"NULL",
	1:"PROGBITS",
	2:"SYMTAB",
	3:"STRTAB",
	4:"RELA",
	5:"HASH",
	6:"DYNAMIC",
	7:"NOTE",
	8:"NOBITS",
	9:"REL",
	10:"SHLIB",
	11:"DYNSYM",
	14:"INIT_ARRAY",
	15:"FINI_ARRAY",
	16:"PREINIT_ARRAY",
	17:"GROUP",
	18:"SYMTAB_SHNDX",
	0x60000000:"LOOS",
	0x6fffffff:"HIOS",
	0x70000000:"LOPROC",
	0x7fffffff:"HIPROC",
	0x80000000:"LOUSER",
	0xffffffff:"HIUSER",
}


EI_MACHINE = {
	0:"No machine",
	1:"AT&T WE 32100",
	2:"SPARC",
	3:"Intel 80386",
	4:"Motorola 68000",
	5:"Motorola 88000",
	6:"Intel MCU",
	7:"Intel 80860",
	8:"MIPS I Architecture",
	9:"IBM System/370 Processor",
	10:"MIPS RS3000 Little-endian",
	11-14:"Reserved for future use",
	15:"Hewlett-Packard PA-RISC",
	16:"Reserved for future use",
	17:"Fujitsu VPP500",
	18:"Enhanced instruction set SPARC",
	19:"Intel 80960",
	20:"PowerPC",
	21:"64-bit PowerPC",
	22:"IBM System/390 Processor",
	23:"IBM SPU/SPC",
	24-35:"Reserved for future use",
	36:"NEC V800",
	37:"Fujitsu FR20",
	38:"TRW RH-32",
	39:"Motorola RCE",
	40:"ARM 32-bit architecture (AARCH32)",
	41:"Digital Alpha",
	42:"Hitachi SH",
	43:"SPARC Version 9",
	44:"Siemens TriCore embedded processor",
	45:"Argonaut RISC Core, Argonaut Technologies Inc.",
	46:"Hitachi H8/300",
	47:"Hitachi H8/300H",
	48:"Hitachi H8S",
	49:"Hitachi H8/500",
	50:"Intel IA-64 processor architecture",
	51:"Stanford MIPS-X",
	52:"Motorola ColdFire",
	53:"Motorola M68HC12",
	54:"Fujitsu MMA Multimedia Accelerator",
	55:"Siemens PCP",
	56:"Sony nCPU embedded RISC processor",
	57:"Denso NDR1 microprocessor",
	58:"Motorola Star*Core processor",
	59:"Toyota ME16 processor",
	60:"STMicroelectronics ST100 processor",
	61:"Advanced Logic Corp. TinyJ embedded processor family",
	62:"AMD x86-64 architecture",
	63:"Sony DSP Processor",
	64:"Digital Equipment Corp. PDP-10",
	65:"Digital Equipment Corp. PDP-11",
	66:"Siemens FX66 microcontroller",
	67:"STMicroelectronics ST9+ 8/16 bit microcontroller",
	68:"STMicroelectronics ST7 8-bit microcontroller",
	69:"Motorola MC68HC16 Microcontroller",
	70:"Motorola MC68HC11 Microcontroller",
	71:"Motorola MC68HC08 Microcontroller",
	72:"Motorola MC68HC05 Microcontroller",
	73:"Silicon Graphics SVx",
	74:"STMicroelectronics ST19 8-bit microcontroller",
	75:"Digital VAX",
	76:"Axis Communications 32-bit embedded processor",
	77:"Infineon Technologies 32-bit embedded processor",
	78:"Element 14 64-bit DSP Processor",
	79:"LSI Logic 16-bit DSP Processor",
	80:"Donald Knuth's educational 64-bit processor",
	81:"Harvard University machine-independent object files",
	82:"SiTera Prism",
	83:"Atmel AVR 8-bit microcontroller",
	84:"Fujitsu FR30",
	85:"Mitsubishi D10V",
	86:"Mitsubishi D30V",
	87:"NEC v850",
	88:"Mitsubishi M32R",
	89:"Matsushita MN10300",
	90:"Matsushita MN10200",
	91:"picoJava",
	92:"OpenRISC 32-bit embedded processor",
	93:"ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)",
	94:"Tensilica Xtensa Architecture",
	95:"Alphamosaic VideoCore processor",
	96:"Thompson Multimedia General Purpose Processor",
	97:"National Semiconductor 32000 series",
	98:"Tenor Network TPC processor",
	99:"Trebia SNP 1000 processor",
	100:"STMicroelectronics (www.st.com) ST200 microcontroller",
	101:"Ubicom IP2xxx microcontroller family",
	102:"MAX Processor",
	103:"National Semiconductor CompactRISC microprocessor",
	104:"Fujitsu F2MC16",
	105:"Texas Instruments embedded microcontroller msp430",
	106:"Analog Devices Blackfin (DSP) processor",
	107:"S1C33 Family of Seiko Epson processors",
	108:"Sharp embedded microprocessor",
	109:"Arca RISC Microprocessor",
	110:"Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University",
	111:"eXcess: 16/32/64-bit configurable embedded CPU",
	112:"Icera Semiconductor Inc. Deep Execution Processor",
	113:"Altera Nios II soft-core processor",
	114:"National Semiconductor CompactRISC CRX microprocessor",
	115:"Motorola XGATE embedded processor",
	116:"Infineon C16x/XC16x processor",
	117:"Renesas M16C series microprocessors",
	118:"Microchip Technology dsPIC30F Digital Signal Controller",
	119:"Freescale Communication Engine RISC core",
	120:"Renesas M32C series microprocessors",
	121-130:"Reserved for future use",
	131:"Altium TSK3000 core",
	132:"Freescale RS08 embedded processor",
	133:"Analog Devices SHARC family of 32-bit DSP processors",
	134:"Cyan Technology eCOG2 microprocessor",
	135:"Sunplus S+core7 RISC processor",
	136:"New Japan Radio (NJR) 24-bit DSP Processor",
	137:"Broadcom VideoCore III processor",
	138:"RISC processor for Lattice FPGA architecture",
	139:"Seiko Epson C17 family",
	140:"The Texas Instruments TMS320C6000 DSP family",
	141:"The Texas Instruments TMS320C2000 DSP family",
	142:"The Texas Instruments TMS320C55x DSP family",
	143:"Texas Instruments Application Specific RISC Processor, 32bit fetch",
	144:"Texas Instruments Programmable Realtime Unit",
	145-159:"Reserved for future use",
	160:"",
	145-159:"Reserved for future use",
	160:"STMicroelectronics 64bit VLIW Data Signal Processor",
	161:"Cypress M8C microprocessor",
	162:"Renesas R32C series microprocessors",
	163:"NXP Semiconductors TriMedia architecture family",
	164:"QUALCOMM DSP6 Processor",
	165:"Intel 8051 and variants",
	166:"STMicroelectronics STxP7x family of configurable and extensible RISC processors",
	167:"Andes Technology compact code size embedded RISC processor family",
	168:"Cyan Technology eCOG1X family",
	168:"Cyan Technology eCOG1X family",
	169:"Dallas Semiconductor MAXQ30 Core Micro-controllers",
	170:"New Japan Radio (NJR) 16-bit DSP Processor",
	171:"M2000 Reconfigurable RISC Microprocessor",
	172:"Cray Inc. NV2 vector architecture",
	173:"Renesas RX family",
	174:"Imagination Technologies META processor architecture",
	175:"MCST Elbrus general purpose hardware architecture",
	176:"Cyan Technology eCOG16 family",
	177:"National Semiconductor CompactRISC CR16 16-bit microprocessor",
	178:"Freescale Extended Time Processing Unit",
	179:"Infineon Technologies SLE9X core",
	180:"Intel L10M",
	181:"Intel K10M",
	182:"Reserved for future Intel use",
	183:"ARM 64-bit architecture (AARCH64)",
	184:"Reserved for future ARM use",
	185:"Atmel Corporation 32-bit microprocessor family",
	186:"STMicroeletronics STM8 8-bit microcontroller",
	187:"Tilera TILE64 multicore architecture family",
	188:"Tilera TILEPro multicore architecture family",
	189:"Xilinx MicroBlaze 32-bit RISC soft processor core",
	190:"NVIDIA CUDA architecture",
	191:"Tilera TILE-Gx multicore architecture family",
	192:"CloudShield architecture family",
	193:"KIPO-KAIST Core-A 1st generation processor family",
	194:"KIPO-KAIST Core-A 2nd generation processor family",
	195:"Synopsys ARCompact V2",
	196:"Open8 8-bit RISC soft processor core",
	197:"Renesas RL78 family",
	198:"Broadcom VideoCore V processor",
	199:"Renesas 78KOR family",
	200:"Freescale 56800EX Digital Signal Controller (DSC)",
	201:"Beyond BA1 CPU architecture",
	202:"Beyond BA2 CPU architecture",
	203:"XMOS xCORE processor family",
	204:"Microchip 8-bit PIC(r) family",
	205:"Reserved by Intel",
	206:"Reserved by Intel",
	207:"Reserved by Intel",
	208:"Reserved by Intel",
	209:"Reserved by Intel",
	210:"KM211 KM32 32-bit processor",
	211:"KM211 KMX32 32-bit processor",
	212:"KM211 KMX16 16-bit processor",
	213:"KM211 KMX8 8-bit processor",
	214:"KM211 KVARC processor",
	215:"Paneve CDP architecture family",
	216:"Cognitive Smart Memory Processor",
	217:"Bluechip Systems CoolEngine",
	218:"Nanoradio Optimized RISC",
	219:"CSR Kalimba architecture family",
	220:"Zilog Z80",
	221:"Controls and Data Services VISIUMcore processor",
	222:"FTDI Chip FT32 high performance 32-bit RISC architecture",
	223:"Moxie processor family",
	224:"AMD GPU architecture",
	243:"RISC-V",
}


def ELF_ST_BIND(i):
	return ((i) >> 4)


def ELF_ST_TYPE(i):
	return ((i)&0x0f)


def ELF_ST_INFO(b, t):
	return ((b)<<4 + ((t)&0x0f))


def ELF_ST_VISIBILITY(i):
	return ((i)&0x3)


def readelf(elf, args):
	'''
	#define EI_NIDENT 16
	typedef struct{
	unsigned char e_ident[EI_NIDENT];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_abiversion;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
	}Elf32_Ehdr;
	'''

	print_elf_header, print_ph, print_sh = args.elf_header, args.program_header, args.section_header
	print_interp, print_symbol_table, print_dynamic_section = args.interp, args.symbol_table, args.dynamic_section

	e_type = e_class = 'dummpy'

	ei_ident = struct.unpack('16B', elf.read(16)) # first 16 bytes (byte 0-15)
	ei_mag0, ei_mag1, ei_mag2, ei_mag3, ei_class, ei_data, ei_version, ei_osabi, ei_abiversion = ei_ident[:9] # byte 0-8
	e_osabi = "Often set to 0 regardless of the target"
	e_abiversion = str(ei_abiversion)
	ei_nident = ei_ident[8:] # byte 9-15, usused
	if ei_mag0 != 0x7F and ei_mag1 != ord('E') and ei_mag2 != ord('L') and ei_mag3 != ord('F'):
		print_err('File not in ELF format')
	if ei_class == 0:
		print_err('Invalid class')
	elif ei_class == 1: # 32-bit
		e_class = '32-bit objects'
	elif ei_class == 2:
		e_class = '64-bit objects'
	
	if ei_data == 0:
		print_err('Invalid data encoding')
	elif ei_data == 1:
		e_data = 'little endian'
	elif ei_data == 2:
		e_data = 'big endian'

	ei_type  = struct.unpack('H', elf.read(2))[0]
	if ei_type == 0:
		e_type = 'No file type'
	elif ei_type == 1:
		e_type = 'Relocatable file'
	elif ei_type == 2:
		e_type = 'Executable file'
	elif ei_type == 3:
		e_type = 'Shared object file'
	elif ei_type == 4:
		e_type = 'Core file'
	elif ei_type == 0xff00:
		e_type = 'Processor-specific'
	elif ei_type == 0xffff:
		e_type = 'Processor-specific'

	ei_machine  = struct.unpack('H', elf.read(2))[0]
	if ei_machine in EI_MACHINE:
		e_machine = EI_MACHINE[ei_machine]
	else:
		e_machine = 'Unknow machine'

	ei_version = struct.unpack('I', elf.read(4))[0]
	if ei_version == 1:
		e_version = "ELF original"
	else:
		e_version = "ELF unrecognized"

	if ei_class == 1: # 32-bit
		ei_entry = struct.unpack('I', elf.read(4))[0]
		e_entry = ei_entry
		e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack('IIIHHHHHH', elf.read(24))
	else: # 64-bit
		ei_entry = struct.unpack('Q', elf.read(8))[0]
		e_entry = ei_entry
		e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack('QQIHHHHHH', elf.read(32))
	if print_elf_header:
		print("")
		print("ELF Header (offset for %s) =====================" % ('32-bit' if ei_class == 1 else '64-bit'))
		print("Identification (0x0-0x8):                        %02x %02x %02x %02x (Magic: \\x7ELF)" %(ei_mag0, ei_mag1, ei_mag2, ei_mag3))
		print("                                                 %02x %02x %02x %02x %02x" %(ei_class, ei_data, ei_version, ei_osabi, ei_abiversion))
		print("Class (0x4):                                     0x%02x\t%s" %(ei_class, e_class))
		print("Data (0x5):                                      0x%02x\t%s" %(ei_data, e_data))
		print("Version (0x6, same as 0x14):                     0x%02x\t%s" %(ei_version, e_version))
		print("ABI of target system (0x7):                      0x%02x\t%s" %(ei_osabi, e_osabi))
		print("ABI Version (0x8), undefined for Linux:          0x%02x\t%s" %(ei_version, e_version))
		print("Padding (0x9):                                   00 00 00 00 00 00 00 (7 bytes)")
		print("Type (0x10):                                     0x%02x\t%s" %(ei_type, e_type))
		print("Machine (0x12):                                  0x%02x\t%s" %(ei_machine, e_machine))
		print("Version (0x14, same as 0x6):                     0x%x\t%s" %(ei_version, e_version))
		print("Entry point address (0x18):                      0x%x" %(e_entry));
		print("Program headers offset (%s):                   0x%x\t%d (bytes into file)" % ('0x1c' if ei_class == 1 else '0x20', e_phoff, e_phoff))
		print("Section headers offset (%s):                   0x%x\t%d (bytes into file)" % ('0x20' if ei_class == 1 else '0x28', e_shoff, e_shoff))
		print("Flags (%s):                                    0x%01x" % ('0x24' if ei_class == 1 else '0x30', e_flags))
		print("Size of this header (%s):                      0x%x\t%d (bytes)" % ('0x28' if ei_class == 1 else '0x34', e_ehsize, e_ehsize))
		print("Size of program header (%s):                   0x%x\t%d (bytes)" % ('0x2a' if ei_class == 1 else '0x36', e_phentsize, e_phentsize))
		print("Number of program headers (%s):                0x%x\t%d" % ('0x2c' if ei_class == 1 else '0x38', e_shnum, e_shnum))
		print("Size of section headers (%s):                  0x%x\t%d (bytes)" % ('0x2e' if ei_class == 1 else '0x3a', e_shentsize, e_shentsize))
		print("Number of section headers (%s):                0x%x\t%d" % ('0x30' if ei_class == 1 else '0x3c', e_shnum, e_shnum))
		print("Index of section header table names (%s):      0x%x\t%d" % ('0x32' if ei_class == 1 else '0x3e', e_shstrndx, e_shstrndx))

	elf.seek(e_shoff + e_shentsize * e_shstrndx)
	if ei_class == 1: # 32-bit
		sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIIHHIIIII', elf.read(48))
	else: # 64-bit
		sh_name, sh_type, sh_flags, sh_addr, sh_offset,  sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIQQQQIIQQ', elf.read(64))

	elf.seek(sh_offset)
	str_section = elf.read(sh_size)

	string_table = {}
	lastnull = 0
	for i, s in enumerate(str_section):
		if s == '\0':
			string_table[lastnull] = str_section[lastnull:i]
			lastnull = i + 1
	if print_ph:
		print("")
		print("Program Headers: =====================")
		print("%10s  0x%08s  0x%14s  0x%14s  0x%10s  0x%10s  %05s" %("Type", "Offset", "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flags"))

	
	e_shinterpndx = -1
	for i in range(0, e_phnum):
		elf.seek(e_phoff + e_phentsize * i)


		if ei_class == 1: # 32-bit
			p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = strcut.unpack('IIIIIIII', elf.read(32))
		else:
			p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack('IIQQQQQQ', elf.read(56))


		#INTERP
		if p_type == 3:
			e_shinterpndx = i
			
		if print_ph:
			print("%10s  0x%08x  0x%014x  0x%014x  0x%010x  0x%010x  %05s" %(PT_TYPE[p_type] if p_type in PT_TYPE else p_type,p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, PT_FLAGS[p_flags]))

	if e_shinterpndx >= 0:
		elf.seek(e_phoff + e_phentsize * e_shinterpndx)
		if ei_class == 1: # 32-bit
			p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = strcut.unpack('IIIIIIII', elf.read(32))
		else: # 64-bit
			p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack('IIQQQQQQ', elf.read(56))
		elf.seek(p_offset)
		interp = elf.read(p_filesz)
		if print_interp:
			print("")
			print("Interp (the dynamic loader): =====================")
			print(interp)

	e_shsymndx = -1
	e_shstrndx = -1
	e_shdynsym = -1
	e_shdynstr = -1
	e_shdynamic = -1

	if print_sh:
		print("")
		print("Section Headers =====================")
		print("[NR] %19s%15s%10s%10s%8s%8s%5s%5s%5s%6s" % ("Name", "Type", "Addr.", "Offset", "Size", "EntSize", "Flag", "Link", "Info", "Align"))
	for i in range(0, e_shnum):
		elf.seek(e_shoff + e_shentsize * i)

		if ei_class == 1: # 32-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIIHHIIIII', elf.read(48))
		else: # 64-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset,  sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIQQQQIIQQ', elf.read(64))

		f = ""
		if sh_flags & SHF_WRITE:
			f += "W"
		if sh_flags & SHF_ALLOC:
			f += "A"
		if sh_flags & SHF_EXECINSTR:
			f += "X"
		if sh_flags & SHF_MASKPROC:
			f += "M"

		if sh_name in string_table:
			if print_sh:
				print("[%02d]%20s%15s%10x%10d%8d%8d%5s%5s%5s%6s" % (i, string_table[sh_name], SH_TYPE[sh_type] if sh_type in SH_TYPE else sh_type, sh_addr, sh_offset, sh_size, sh_entsize, f, sh_link, sh_info, sh_addralign))

			if string_table[sh_name] == '.symtab':
				e_shsymndx = i

			if string_table[sh_name] == '.strtab':
				e_shstrndx = i

			if string_table[sh_name] == '.dynsym':
				e_shdynsym = i

			if string_table[sh_name] == '.dynstr':
				e_shdynstr = i
			
			if string_table[sh_name] == '.dynamic':
				e_shdynamic = i

		else:
			if print_sh:
				print("[%02d]%20s%15s%10x%10d%8d%8d%5s%5s%5s%6s" % (i, sh_name, SH_TYPE[sh_type] if sh_type in SH_TYPE else sh_type, sh_addr, sh_offset, sh_size, sh_entsize, f, sh_link, sh_info, sh_addralign))
		
		
	if e_shdynsym >= 0 and e_shdynstr >= 0:
		elf.seek(e_shoff + e_shentsize * e_shdynstr)
		if ei_class == 1: # 32-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIIHHIIIII', elf.read(48))
		else: # 64-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset,  sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIQQQQIIQQ', elf.read(64))

		elf.seek(sh_offset)
		dynsym_section = elf.read(sh_size)
		dynsymbol_table = {}
		lastnull = 0
		for i, s in enumerate(dynsym_section):
			if s == '\0':
				dynsymbol_table[lastnull] = dynsym_section[lastnull:i]
				lastnull = i + 1

		elf.seek(e_shoff + e_shentsize * e_shdynsym)

		if ei_class == 1: # 32-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIIHHIIIII', elf.read(48))
		else: # 64-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset,  sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIQQQQIIQQ', elf.read(64))

		elf.seek(sh_offset)
		dynsym_section = elf.read(sh_size)

		if print_symbol_table:
			print("")
			if ei_class == 1: # 32-bit
				print("Symbol Table '.dynsym' contains %d entries: =====================" % (sh_size / 16))
			else: # 64-bit
				print("Symbol Table '.dynsym' contains %d entries: =====================" % (sh_size / 24))
			print("%04s%10s%10s%10s%10s%10s%10s%30s" %("Num", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name"))

		for i in range(0, sh_size / 24):
			if ei_class == 1: # 32-bit
				st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack('IIIBBH', dynsym_section[i*16:(i+1)*16])
			else: # 64-bit
				st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack('IBBHQQ', dynsym_section[i*24:(i+1)*24])

			if st_name in dynsymbol_table:
				if print_symbol_table:
					print("%4d%10d%10d%10s%10s%10s%10d%30s" %(i, st_value, st_size, STT_TYPE[ELF_ST_TYPE(st_info)],
						STB_BIND[ELF_ST_BIND(st_info)], STV_VISIBILITY[ELF_ST_VISIBILITY(st_other)], st_shndx, dynsymbol_table[st_name],))
			else:
				if print_symbol_table:
					print("%4d%10d%10d%10s%10s%10s%10d%30d" %(i, st_value, st_size, STT_TYPE[ELF_ST_TYPE(st_info)],
						STB_BIND[ELF_ST_BIND(st_info)], STV_VISIBILITY[ELF_ST_VISIBILITY(st_other)], st_shndx, st_name,))


	if e_shsymndx >= 0 and e_shstrndx >= 0:
		elf.seek(e_shoff + e_shentsize * e_shstrndx)
		if ei_class == 1: # 32-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIIHHIIIII', elf.read(48))
		else: # 64-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset,  sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIQQQQIIQQ', elf.read(64))

		elf.seek(sh_offset)
		sym_section = elf.read(sh_size)
		lastnull = 0
		symbol_table = {}
		for i, s in enumerate(sym_section):
			if s == '\0':
				symbol_table[lastnull] = sym_section[lastnull:i]
				lastnull = i + 1

		elf.seek(e_shoff + e_shentsize * e_shsymndx)

		if ei_class == 1: # 32-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIIHHIIIII', elf.read(48))
		else: # 64-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset,  sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIQQQQIIQQ', elf.read(64))

		elf.seek(sh_offset)
		sym_section = elf.read(sh_size)

	if print_symbol_table:
		print("")
		if ei_class == 1: # 32-bit
			print("Symbol Table '.symtab' contains %d entries: =====================" % (sh_size / 16))
		else: # 64-bit
			print("Symbol Table '.symtab' contains %d entries: =====================" % (sh_size / 24))
		print("%04s%10s%10s%10s%10s%10s%10s%30s" %("Num", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name"))

		for i in range(0, sh_size / 24):
			if ei_class == 1: # 32-bit
				st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack('IIIBBH', sym_section[i*16:(i+1)*16])
			else:
				st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack('IBBHQQ', sym_section[i*24:(i+1)*24])

			if st_name in symbol_table:
				if print_symbol_table:
					print("%4d%10d%10d%10s%10s%10s%10d%30s" %(i, st_value, st_size, STT_TYPE[ELF_ST_TYPE(st_info)],
						STB_BIND[ELF_ST_BIND(st_info)], STV_VISIBILITY[ELF_ST_VISIBILITY(st_other)], st_shndx, symbol_table[st_name],))
			else:
				if print_symbol_table:
					print("%4d%10d%10d%10s%10s%10s%10d%30d" %(i, st_value, st_size, STT_TYPE[ELF_ST_TYPE(st_info)],
						STB_BIND[ELF_ST_BIND(st_info)], STV_VISIBILITY[ELF_ST_VISIBILITY(st_other)], st_shndx, st_name,))

	if e_shdynamic >= 0:
		elf.seek(e_shoff + e_shentsize * e_shdynamic)
		if ei_class == 1: # 32-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIIHHIIIII', elf.read(48))
		else: # 64-bit
			sh_name, sh_type, sh_flags, sh_addr, sh_offset,  sh_size, sh_link, sh_info, sh_addralign, sh_entsize  = struct.unpack('IIQQQQIIQQ', elf.read(64))

		elf.seek(sh_offset)
		dynamic_section = elf.read(sh_size)	
		if print_dynamic_section:
			print('')
			print("Dynamic Section =====================")
			print('%20s %20s %20s' %("Tag", "Type", "Name/Value"))
		if ei_class == 1: # 32-bit
			pass
		else: # 64-bit
			for i in range(0, sh_size/16):
				elf.seek(sh_offset + i * 16)		
				d_tag, d_un = struct.unpack('QQ', elf.read(16))
				if d_tag in TAG:
					if d_tag == 1 or d_tag == 15:
						if print_dynamic_section:
							print('0x%018x %20s %20s' %(d_tag, TAG[d_tag], dynsymbol_table[d_un]))
					else:
						if print_dynamic_section:
							print('0x%018x %20s %20s' %(d_tag, TAG[d_tag], d_un))
				else:
					if d_tag == 1 or d_tag == 15:
						if print_dynamic_section:
							print('0x%018x %20s %20s' %(d_tag, d_tag, dynsymbol_table[d_un]))
					else:
						if print_dynamic_section:
							print('0x%018x %20s %20s' %(d_tag, d_tag, d_un))
		
	return


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-v', '--version', action='store_true', help='version info')
	parser.add_argument('-r', '--reference', action='store_true', help='links to learn more about ELF')
	parser.add_argument('-eh', '--elf-header', action='store_true', help='print ELF header')
	parser.add_argument('-ph', '--program-header', action='store_true', help='print program headers')
	parser.add_argument('-sh', '--section-header', action='store_true', help='print section headers')
	parser.add_argument('-it', '--interp', action='store_true', help='print interp, i.e. the dynamic loader (itself a shared binary)')
	parser.add_argument('-st', '--symbol-table', action='store_true', help='print symbol table')
	parser.add_argument('-ds', '--dynamic-section', action='store_true', help='print dynamic section')
	parser.add_argument('-a', '--all', action='store_true', help='print all (default)')
	parser.add_argument('file', metavar='file', type=str, help='path to the ELF file')
	
	args = parser.parse_args()
	
	if args.version:
		print("Python tool to read ELF format\nCopyright (C) detailyang and Leedehai")

	if args.reference:
		print("Reference: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format")
		print("           https://www.linuxjournal.com/article/1060")
	
	if args.version or args.reference:	
		sys.exit(0)

	if args.elf_header is False and args.program_header is False \
		and args.section_header is False and args.interp is False \
		and args.symbol_table is False and args.dynamic_section is False:
		args.all = True
	if args.all:
		args.elf_header = True; args.program_header = True; args.section_header = True
		args.interp = True; args.symbol_table = True; args.dynamic_section = True

	print("Input file: %s" % args.file)
	try:
		elf = open(args.file, 'r')
	except(IOError):
		print_err("IO Error when opening file")
	else:
		readelf(elf, args)
		elf.close()

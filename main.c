#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>

typedef uint8_t Elf8_Byte;

#define __PT_GNU_STACK	0x6474e551UL

#define FSIZE	0x20UL
#define ROT4W	0x18UL
#define ROT4B	0x08UL

#define MAGIC	0x00UL
#define CLASS	0x04UL
#define DATA	0x05UL
#define OSABI	0x07UL
#define ABIVER	0x08UL
#define MACHI	0x12UL

#define SPACE 	"  "

#define INFO(msg) puts(msg)
#define ROT(val, co) val << co | val >> (32 - co)

struct binary {
	struct stat f_st;
	int fd;
	size_t file_size;
	size_t read_ret;
	char elf_head[0x100000];
	char flags[FSIZE][0x20];
} bin;

struct elf_header {
	Elf64_Half magic_number;
	Elf8_Byte e_class, endian, abi_version;
	Elf64_Half machine;
	Elf8_Byte nx, aslr, pie, canary;
} glob_e_hdr;

bool check_canary(char src[], size_t elf_size)
{
	char chk[] = "__stack_chk_fail";

	int x = 0, y = 0;
	while (x++ != elf_size)
	{
		if (chk[y] == src[x])
		{
			if (y++ == (strlen(chk) - 1))
				return true;
		}

		else { if (y) y--; }
	}

	return false;
}

bool check_pie(char src[], size_t elf_size)
{
	char chk[] = "_dl_relocate_static_pie";

	int x = 0, y = 0;
	while (x++ != elf_size)
	{
		if (chk[y] == src[x])
		{
			if (y++ == (strlen(chk) - 1))
				return false;
		}

		else { if (y) y--; }
	}

	return true;
}

bool check_nx(char src[])
{
	int x = 1;
	while (x++ != 0x1001)
	{
		if (((uint32_t *)src)[x] == __PT_GNU_STACK)
			return (src[(x * 4) + 4] % 8 == 6) ? true : false;
	}
}

struct elf_header SET_ELF(char elf_head[])
{
	struct elf_header e_hdr = {
		.magic_number = ((Elf64_Word *)elf_head)[MAGIC],
		.e_class = elf_head[CLASS],
		.endian = elf_head[DATA],
		.abi_version = elf_head[OSABI],
		.machine = (Elf64_Half)elf_head[MACHI]
	};

	return e_hdr;
}

struct elf_header CHECK_ELF(size_t elf_size)
{
	struct elf_header e_hdr;

	// find flags offset & dump flags
	//	int flags_offset = search_flags_offset(bin.elf_head, elf_size);
	//	
	//	int fg_byte = 0, n_byte = 0, fg_counter = 0;
	//	for (fg_byte = flags_offset; fg_byte != elf_size; fg_byte++)
	//	{
	//		if (bin.elf_head[fg_byte] == '-')
	//		{
	//			if (!(bin.elf_head[fg_byte + 1] >= 0x61 && bin.elf_head[fg_byte + 1] <= 0x7a))
	//				goto _endif;
	//
	//			while (bin.elf_head[fg_byte] != ' ')
	//			{
	//				bin.flags[fg_counter][n_byte++] = bin.elf_head[fg_byte++]; 
	//				if (bin.elf_head[fg_byte] == '\0') goto _endfor;
	//			} bin.elf_head[fg_byte] = '\0';
	//
	//			n_byte = 0;
	//			fg_counter++;
	//_endif:
	//		}
	//	}
	//_endfor:

	// check "__stack_chk_fail" in elf_head
	e_hdr.canary = check_canary(bin.elf_head, elf_size);

	// check "_dl_relocate_static_pie" in elf_head
	e_hdr.pie = check_pie(bin.elf_head, elf_size);

	// check nx
	e_hdr.nx = check_nx(bin.elf_head);

	return e_hdr;
}

void INFO_ELF()
{
	puts("ELF:");
	
	// print magic number
	printf(
		SPACE "Magic: %#20x (%s)\n",
		ROT(glob_e_hdr.magic_number, ROT4W), "Magic Number"
	);

	// print class
	printf(
		SPACE "Class: %#20x (%s)\n",
		glob_e_hdr.e_class, (glob_e_hdr.e_class == 1) ? "32-bit" : "64-bit"
	);

	// print data
	printf(
		SPACE "Data:  %#20x (%s)\n",
		glob_e_hdr.endian, (glob_e_hdr.endian == 1) ? "little" : "big"
	);

	// print abi version	
	char *os_abi[] = {
		"System V", "HP-UX", "NetBSD",
		"Linux", "GNU Hurd", "Solaris",
		"AIX", "IRIX", "FreeBSD",
		"Tru64", "Novell Modesto", "OpenBSD",
		"OpenVMS", "NonStop Kernel", "AROS",
		"FenixOS", "Nuxi CloudABI", "OpenVOS"
	};
	
	printf(
		SPACE "ABI Version: %#14x (%s)\n",
		glob_e_hdr.abi_version, os_abi[glob_e_hdr.abi_version]
	);

	// print machine
	int arch_vals[] = {
		0x02, // SPARC
		0x03, // x86
		0x08, // MIPS
		0x14, // PowerPC
		0x15, // PowerPC-64
		0x2b, // SPARC-64 
		0x32, // IA-64
		0x3e, // AMD x86-64
		0xb7, // AArch64
	};

	char *arch[1] = { 0 };
	char *archs[] = {
		"SPARC",
		"i386",
		"MIPS",
		"PowerPC",
		"PowerPC (64-bit)",
		"SPARC (64-bit)",
		"IA-64",
		"amd64",
		"aarch64"
	};

	int i;
	for (i = 0; i != sizeof(arch_vals); i++)
		if (arch_vals[i] == glob_e_hdr.machine)
			arch[0] = archs[i];

	printf(
		SPACE "Machine: %#18x (%s)\n",
		glob_e_hdr.machine, arch[0]
	);

	// print canary
	printf(
		SPACE "Canary: %#19x (%s)\n",
		glob_e_hdr.canary, glob_e_hdr.canary ? "Enable" : "Disable"
	);

	// print pie
	printf(
		SPACE "PIE: %#22x (%s)\n",
		glob_e_hdr.pie, glob_e_hdr.pie ? "Enable" : "Disable"
	);

	// print nx
	printf(
		SPACE "NX: %#23x (%s)\n",
		glob_e_hdr.nx, glob_e_hdr.nx ? "Enable": "Disable"
	);

}

int main(int argc, char *argv[])
{
	if (argc != 2) 
	{
		printf("usage: %s <binary>\n", argv[0]);
		goto _exit;
	}

	bin.fd = open(argv[1], O_RDONLY);
	if (bin.fd == -1)
	{
		INFO("[!] error: open() = -1");
		goto _exit;
	}

	if (fstat(bin.fd, &bin.f_st))
	{
		INFO("[!] error: stat() = -1");
		goto _exit;
	}

	bin.read_ret = read(bin.fd, bin.elf_head, bin.f_st.st_size);
	if (!bin.read_ret)
	{
		INFO("[!] error: read() = 0");
		goto _exit;
	}

	glob_e_hdr = SET_ELF(bin.elf_head);
	glob_e_hdr = CHECK_ELF(bin.f_st.st_size);
	INFO_ELF();

_exit:	exit(-1);
}

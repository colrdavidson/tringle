#include "minilib.c"

#define panic(...) do { dprintf(2, __VA_ARGS__); exit(1); } while (0)
#define floor_size(addr, size) ((addr) - ((addr) % (size)))
#define round_size(addr, size) (((addr) + (size)) - ((addr) % (size)))

#define ELFCLASS64  2
#define ELFDATA2LSB 1
#define EM_X86_64   62

#define SHF_WRITE (1 << 0)
#define SHF_ALLOC (1 << 1)
#define SHF_TLS   (1 << 10)

#define PT_LOAD   1
#define PT_INTERP 3
#define PT_TLS    7

#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & (0xFFFFFFFFL))

enum {
	SHT_NULL     = 0,
	SHT_PROGBITS = 1,
	SHT_SYMTAB   = 2,
	SHT_STRTAB   = 3,
	SHT_RELA     = 4,
	SHT_HASH     = 5,
	SHT_DYNAMIC  = 6,
	SHT_NOTE     = 7,
	SHT_NOBITS   = 8,
	SHT_REL      = 9,
};

#pragma pack(1)
typedef struct {
	u8 magic[4];
	u8 class;
	u8 endian;
	u8 hdr_version;
	u8 target_abi;
	u8 pad[8];
} ELF_Pre_Header;

typedef struct {
	u8  ident[16];
	u16 type;
	u16 machine;
	u32 version;
	u64 entrypoint;
	u64 program_hdr_offset;
	u64 section_hdr_offset;
	u32 flags;
	u16 eh_size;
	u16 program_hdr_entry_size;
	u16 program_hdr_num;
	u16 section_hdr_entry_size;
	u16 section_hdr_num;
	u16 section_hdr_str_idx;
} ELF64_Header;

typedef struct {
	u32 type;
	u32 flags;
	u64 offset;
	u64 virtual_addr;
	u64 physical_addr;
	u64 file_size;
	u64 mem_size;
	u64 align;
} ELF64_Program_Header;

typedef struct {
	u32 name;
	u32 type;
	u64 flags;
	u64 addr;
	u64 offset;
	u64 size;
	u32 link;
	u32 info;
	u64 addr_align;
	u64 entry_size;
} ELF64_Section_Header;
#pragma pack()

typedef struct {
	u8 *data;
	u64 size;
} Segment;

typedef struct {
	u8 *data;
	u64 size;
} Slice;

static Slice to_slice(u8 *data, u64 size) {
	Slice s;
	s.data = data;
	s.size = size;
	return s;
}

static Slice slice_idx(Slice s, u64 idx) {
	if (idx > s.size) {
		panic("Invalid idx %d:%d!\n", idx, s.size);
	}

	Slice out;
	out.data = s.data + idx;
	out.size = s.size - idx;
	return out;
}

static Slice load_file(char *filename) {
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		panic("Failed to open %s\n", filename);
	}

	u64 length = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	u64 aligned_length = round_size(length, 0x1000);

	u8 *data = mmap(NULL, aligned_length, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd, 0);
	return to_slice(data, length);
}

static bool is_elf(Slice s) {
	if (s.size < sizeof(ELF64_Header)) {
		return false;
	}

	// Checking a small chunk of the ELF header (Calling it a Pre_Header here)
	// to know how to interpret the rest of the header
	// The full header could be ELF32 or ELF64 or garbage,
	// I won't know until I've scanned the Pre_Header fields
	u8 magic[4] = { 0x7F, 'E', 'L', 'F' };
	ELF_Pre_Header *pre_hdr = (ELF_Pre_Header *)s.data;
	if (!memeq(pre_hdr->magic, magic, sizeof(magic))) {
		return false;
	}
	if (pre_hdr->class != ELFCLASS64 || pre_hdr->endian != ELFDATA2LSB) {
		panic("TODO: Only supports 64 bit, little endian ELF\n");
	}

	ELF64_Header *elf_hdr = (ELF64_Header *)s.data;
	if (elf_hdr->machine != EM_X86_64) {
		panic("TODO: Only supports x86_64\n");
	}
	if (elf_hdr->version != 1) {
		panic("Invalid ELF version\n");
	}

	return true;
}

static char *get_interp(Slice s) {
	ELF64_Header *elf_hdr = (ELF64_Header *)s.data;

	// Ensure that the ELF file actually has enough space to fit the full claimed program header table
	if (elf_hdr->program_hdr_offset + (elf_hdr->program_hdr_num * sizeof(ELF64_Program_Header)) > s.size) {
		panic("Invalid elf file!\n");
	}
	ELF64_Program_Header *program_hdr_table = (ELF64_Program_Header *)(s.data + elf_hdr->program_hdr_offset);
	for (int i = 0; i < elf_hdr->program_hdr_num; i += 1) {
		ELF64_Program_Header *p_hdr = &program_hdr_table[i];

		switch (p_hdr->type) {
		case PT_INTERP: {
			return (char *)(s.data + p_hdr->offset);
		} break;
		}
	}
	return NULL;
}

static void patch_interp(Slice s, char *interp_str) {
	if (!is_elf(s)) {
		panic("Failed to load elf\n");
	}

	ELF64_Header *elf_hdr = (ELF64_Header *)s.data;
	// Ensure that the ELF file actually has enough space to fit the full claimed program header table
	if (elf_hdr->program_hdr_offset + (elf_hdr->program_hdr_num * sizeof(ELF64_Program_Header)) > s.size) {
		panic("Invalid elf file!\n");
	}
	ELF64_Program_Header *program_hdr_table = (ELF64_Program_Header *)(s.data + elf_hdr->program_hdr_offset);
	for (int i = 0; i < elf_hdr->program_hdr_num; i += 1) {
		ELF64_Program_Header *p_hdr = &program_hdr_table[i];

		switch (p_hdr->type) {
		case PT_INTERP: {
			int interp_len = strlen(interp_str);
			if (interp_len >= p_hdr->file_size) {
				panic("Unable to stick interp str into the interp spot\n");
			}
			printf("%s -- %d\n", interp_str, interp_len);

			char *out_str = (char *)(s.data + p_hdr->offset);
			memcpy(out_str, interp_str, interp_len);
			out_str[interp_len] = 0;
		} break;
		}
	}
}

int main(int argc, char **argv, char **envp) {
	if (argc < 2) {
		printf("expected tringle <program>\n");
		return 1;
	}

	char *env_path = "/usr/bin/env";
	Slice env_slice = load_file(env_path);
	if (!is_elf(env_slice)) {
		panic("Could not load %s\n", env_path);
	}
	char *interp_str = get_interp(env_slice);
	if (interp_str == NULL) {
		panic("Could not get interpreter for %s", env_path);
	}

	printf("Found interpreter %s\n", interp_str);

	Slice prog_slice = load_file(argv[1]);
	if (!is_elf(prog_slice)) {
		panic("Could not load %s\n", argv[1]);
	}

	patch_interp(prog_slice, interp_str);

	int fd = memfd_create(argv[1], O_RDONLY);
	if (fd < 0) {
		panic("Failed to open memfile for %s\n", argv[1]);
	}
	write(fd, prog_slice.data, prog_slice.size);

	char fd_path_prefix[] = "/proc/self/fd/";
	int max_int_chars = 20;
	char path_buffer[sizeof(fd_path_prefix) + max_int_chars];
	memcpy(path_buffer, fd_path_prefix, sizeof(fd_path_prefix));
	int c_count = itoa(fd, 10, (uint8_t *)(path_buffer + sizeof(fd_path_prefix) - 1));
	path_buffer[sizeof(fd_path_prefix) + c_count] = 0;

	execve(path_buffer, argv + 2, envp);
	return 1;
}

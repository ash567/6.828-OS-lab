// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static int
mon_octal(int argc, char **argv, struct Trapframe *tf);

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf);

static struct Command commands[] = {
	{ "backtrace", "Display callbacks", mon_backtrace},
	{ "help", "Display this list of commands", mon_help },
	{ "octal", "Display octal", mon_octal},
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
    { "showmappings", "Display the physical pages mappings and permission\
 bits that apply to the pages", mon_showmappings },
    { "setmappings", "Set new mapping on a virtual address", mon_setmappings },
    { "clearmappings", "Set new mapping on a virtual address", mon_clearmappings },
    { "changepermission", "changepermission permission on mapping page", mon_changepermission },
    { "dumpcontents", "dump contents on a virtual/physical address", mon_dumpcontents },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/
unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/
int
mon_octal(int argc, char **argv, struct Trapframe *tf)
{
	int i;
	if (argc < 2) {
		cprintf("syntax: octal <Decimal>\n");
		return 0;
	}
	unsigned int num = strtol(argv[1], NULL, 10);
	cprintf("octal(%u)=%o(o)\n", num, num);
	return 0;
}

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%d) %s - %s\n", i, commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

/*
int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	uint32_t *ebp, *eip;
	uint32_t arg0, arg1, arg2, arg3, arg4;
	struct Eipdebuginfo info;

	ebp = (uint32_t*) read_ebp();

	cprintf("Stack backtrace:\n");
	while (ebp != 0) {
		eip = (uint32_t*) ebp[1];
		arg0 = ebp[2];
		arg1 = ebp[3];
		arg2 = ebp[4];
		arg3 = ebp[5];
		arg4 = ebp[6];
		cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n",
			ebp, eip, arg0, arg1, arg2, arg3, arg4);
		debuginfo_eip((uintptr_t) eip, &info);
		cprintf("         %s:%d: %.*s+%d\n", info.eip_file, info.eip_line, info.eip_fn_namelen, info.eip_fn_name, info.eip_fn_addr);
		ebp = (uint32_t*) ebp[0];
	}
    return 0;
}*/
#define J_NEXT_EBP(ebp) (*(uint *)ebp)
#define J_ARG_N(ebp, n) (*(uint *)(ebp + n))

//extern unsigned int bootstacktop;
typedef unsigned int uint;
static struct Eipdebuginfo info = {0};
static inline uint*
dump_stack(uint *p)
{
	uint i;
	cprintf("ebp %08x  eip %08x args", p, J_ARG_N(p, 1));
	for (i=2; i < 7; i++) {
		cprintf(" %08x",J_ARG_N(p,i)); 
	}

	memset(&info, 0, sizeof(info));
	debuginfo_eip((uintptr_t)*(p+1), &info);
	cprintf("\n");
	return (uint *)J_NEXT_EBP(p);
}
int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	uint *p = (uint *) read_ebp();
	uint eip = read_eip();	
	cprintf("current eip=%08x", eip);
	debuginfo_eip((uintptr_t) eip, &info);
	cprintf("\n");
	do {
		p = dump_stack(p);
	} while(p); // && *p != 0);
	return 0;
}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf) {
    uint32_t lower, upper, cur, tmp;
    pte_t *page_table_entry;

    if (argc != 3) {
        cprintf("usage: showmappings LOWER_ADDR UPPER_ADDR\n");
        return 0;
    }

    lower = strtol(argv[1], 0, 16);
    upper = strtol(argv[2], 0, 16);
    if (lower > upper) {
        tmp = lower; lower = upper; upper = tmp;
    }
    lower = ROUNDDOWN(lower, PGSIZE);
    upper = ROUNDUP(upper, PGSIZE);

    // 'lower' and 'upper' are virtual addresses
    cur = lower;
    while (cur <= upper) {
        page_table_entry = pgdir_walk(kern_pgdir, (void *) cur, 0);
        cprintf("va [0x%x, 0x%x) -> ", cur, cur + PGSIZE);

        if (page_table_entry && (*page_table_entry & PTE_P)) {
            cprintf("pa [0x%x, 0x%x) ", PTE_ADDR(*page_table_entry), PTE_ADDR(*page_table_entry) + PGSIZE);
            cprintf(" permission: %s, %s", (*page_table_entry & PTE_U) ? "USER": "SUPERVISOR", (*page_table_entry & PTE_W) ? "READ/WRITE": "READ ONLY");
        } else {
            cprintf("no mapped");
        }
        cprintf("\n");
        cur += PGSIZE;
    }
    return 0;
}

int
mon_setmappings(int argc, char **argv, struct Trapframe *tf) {
    uint32_t va, pa;
    char perm[2];
    int perm_int;

    if (argc != 4 || strlen(argv[3]) != 2) {
        cprintf("usage: setmappings VIR_ADDR PHYS_ADDR PERMISSION\n");
        cprintf("       PERMISSION should be one of \"UR\", \"UW\", \"SR\", \"SW\"\n");
        return 0;
    }

    va = strtol(argv[1], 0, 16);
    pa = strtol(argv[2], 0, 16);
    strcpy(perm, argv[3]);
    va = ROUNDDOWN(va, PGSIZE);
    pa = ROUNDDOWN(pa, PGSIZE);

    argv[2] = argv[1];
    mon_showmappings(3, argv, tf);

    perm_int = 0;
    if (perm[0] == 'U') perm_int |= PTE_U;
    if (perm[1] == 'W') perm_int |= PTE_W;

    page_insert(kern_pgdir, pa2page(pa), (void *)va, perm_int);

    mon_showmappings(3, argv, tf);

    return 0;
}

int
mon_clearmappings(int argc, char **argv, struct Trapframe *tf) {
    uint32_t va;

    if (argc != 2) {
        cprintf("usage: clearmappings VIR_ADDR\n");
        return 0;
    }

    va = strtol(argv[1], 0, 16);
    va = ROUNDDOWN(va, PGSIZE);

    argv[2] = argv[1];
    mon_showmappings(3, argv, tf);
    page_remove(kern_pgdir, (void *)va);
    mon_showmappings(3, argv, tf);

    return 0;
}

int
mon_changepermission(int argc, char **argv, struct Trapframe *tf) {
    uint32_t va;
    char perm[2];
    pte_t *page_table_entry;

    if (argc != 3 || strlen(argv[2]) != 2) {
        cprintf("usage: changepermission ADDR PERMISSION\n");
        cprintf("       PERMISSION should be one of \"UR\", \"UW\", \"SR\", \"SW\"\n");
        return 0;
    }

    va = strtol(argv[1], 0, 16);
    strcpy(perm, argv[2]);
    va = ROUNDDOWN(va, PGSIZE);

    argv[2] = argv[1];
    mon_showmappings(argc, argv, tf);

    page_table_entry = pgdir_walk(kern_pgdir, (void *) va, 0);
    *page_table_entry = PTE_ADDR(*page_table_entry) | PTE_P;

    if (perm[0] == 'U') *page_table_entry |= PTE_U;
    if (perm[1] == 'W') *page_table_entry |= PTE_W;

    mon_showmappings(argc, argv, tf);

    return 0;
}

int
mon_dumpcontents(int argc, char **argv, struct Trapframe *tf) {
    uint32_t addr;
    int size, i, j;

    if (argc != 4) {
        cprintf("usage: dumpcontents virtual/physical LOWER_ADDR UPPER_ADDR\n");
        return 0;
    }

    addr = strtol(argv[2], 0, 16);
    addr = ROUNDDOWN(addr, PGSIZE);
    if (!strcmp(argv[1], "physical")) addr += KERNBASE;
    size = strtol(argv[3], 0, 10);

    i = 0;
    while (i < size) {
        cprintf("0x%08x: ", addr);
        j = 0;
        while (j < 4 && i < size) { 
            cprintf("0x%08x  ", *(uint32_t *) addr);
            addr += 4;
            j++;
            i++;
        }
        cprintf("\n");
    }
    return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}

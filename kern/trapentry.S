/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>



###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)					            	    \
	.globl name;		    /* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		    \
	.align 2;		        /* align function definition */		    \
	name:			        /* function starts here */		        \
	pushl $(num);							                        \
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							        \
	.type name, @function;						    \
	.align 2;							            \
	name:                                           \
	pushl $0;                                       \
	pushl $(num);                                   \
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
*/

TRAPHANDLER_NOEC(_divide_err, T_DIVIDE)         // 0 divide error
TRAPHANDLER_NOEC(_debug_exception, T_DEBUG)     // 1 debug exception 
TRAPHANDLER_NOEC(_nmi, T_NMI)                   // 2 non-maskable interrupt 
TRAPHANDLER_NOEC(_breakpoint, T_BRKPT)          // 3 breakpoint
TRAPHANDLER_NOEC(_overflow, T_OFLOW)            // 4 overflow
TRAPHANDLER_NOEC(_bounds_check, T_BOUND)        // 5 bounds check
TRAPHANDLER_NOEC(_illegal_opcode, T_ILLOP)      // 6 illegal opcode
TRAPHANDLER_NOEC(_dev_not_avail, T_DEVICE)      // 7 device not available
TRAPHANDLER(_double_fault, T_DBLFLT)            // 8 double fault
// 9 is a reserved interrupt 
TRAPHANDLER(_invalid_tss, T_TSS)                // 10 invalid task switch segment
TRAPHANDLER(_segment_not_present, T_SEGNP)      // 11 segment not present
TRAPHANDLER(_stack_exception, T_STACK)          // 12 stack exception 
TRAPHANDLER(_general_protect, T_GPFLT)          // 13 general protection fault
TRAPHANDLER(_page_fault, T_PGFLT)               // 14 page fault 
// 15 is reserved too
TRAPHANDLER_NOEC(_fp_err, T_FPERR)              // 16 floating point error 
TRAPHANDLER(_alig_check, T_ALIGN)               // 17 aligment check 
TRAPHANDLER_NOEC(_machine_check, T_MCHK)        // 18 machine check 
TRAPHANDLER_NOEC(_simd_fp_err, T_SIMDERR)       // 19 SIMD floating point error 

TRAPHANDLER_NOEC(_syscall, T_SYSCALL)           // 48 system call  


/*
 * Lab 3: Your code here for _alltraps
 */

_alltraps:
	pushl %ds   // what's mean ?
	pushl %es
	pushal

	movw $GD_KD, %ax
	movw %ax, %ds 
	movw %ax, %es 

	pushl %esp 
	call  trap

.data
.globl isrs
isrs:
	.long _divide_err
	.long _debug_exception 
	.long _nmi 
	.long _breakpoint	
	.long _overflow	
	.long _bounds_check 
	.long _illegal_opcode
	.long _dev_not_avail
	.long _double_fault
	.long 0	
	.long _invalid_tss
	.long _segment_not_present
	.long _stack_exception
	.long _general_protect
	.long _page_fault
	.long 0
	.long _fp_err
	.long _alig_check
	.long _machine_check
	.long _simd_fp_err
.fill 12, 4, 0     // 20-31 is reserved
.fill 0x10, 4, 0   // 0x20 - 0x2f is for IRQ
	.long _syscall
.fill 0xcf, 4, 0  // 0x31 - 0xff is reserved



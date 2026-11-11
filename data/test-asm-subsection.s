/*
 * When assembled by LLVM (e.g., `clang -g`), the switch back from
 * subsection 1 to subsection 0 results in a DW_LNS_advance_pc with a
 * wrapped around (i.e., negative) operand in the line number program.
 *
 * Expected line table: a single sequence, rows in emission order
 * (offsets for x86_64, where nop and ret are one byte each):
 *
 *   address    line  instruction
 *   asm_fn+0   21    nop, subsection 0
 *   asm_fn+3   23    nop, subsection 1 (laid out after subsection 0)
 *   asm_fn+4   24    nop, subsection 1
 *   asm_fn+1   26    nop, subsection 0 (advance_pc by -3, wrapped)
 *   asm_fn+2   27    ret, subsection 0
 *   asm_fn+3         end_sequence
 */
	.text
	.globl	asm_fn
	.type	asm_fn, %function
asm_fn:
	nop
	.subsection 1
	nop
	nop
	.subsection 0
	nop
	ret
	.size	asm_fn, .-asm_fn

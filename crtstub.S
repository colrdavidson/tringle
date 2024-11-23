bits 64

section .text

global _start
extern __main

; argc, argv, envp
; rdi,   rsi,  rdx
_start:
	xor rbp, rbp
	pop rdi
	mov rsi, rsp
	lea rdx, [rsp + 8*rdi + 8]
	push rax
	and rsp, -16
	call __main

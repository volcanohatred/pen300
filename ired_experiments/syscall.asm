;In the syscalls.asm, let's define a procedure SysNtCreateFile
;with a syscall number 55 that is reserved for NtCreateFile 
.code
		SysNtCreateFile proc
						mov r10, rcx
						mov eax, 55h
						syscall
						ret
		SysNtCreateFile endp
end
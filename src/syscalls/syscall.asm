.data
    NtReadId    DWORD 0
    NtWriteId   DWORD 0
    NtOpenId    DWORD 0
    NtCloseId   DWORD 0
    NtProtectId DWORD 0
    NtCreateThreadId DWORD 0

.code

Luck_NtReadVirtualMemory PROC
    mov r10, rcx
    mov eax, NtReadId
    syscall
    ret
Luck_NtReadVirtualMemory ENDP

Luck_NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, NtWriteId
    syscall
    ret
Luck_NtWriteVirtualMemory ENDP

Luck_NtOpenProcess PROC
    mov r10, rcx
    mov eax, NtOpenId
    syscall
    ret
Luck_NtOpenProcess ENDP

Luck_NtClose PROC
    mov r10, rcx
    mov eax, NtCloseId
    syscall
    ret
Luck_NtClose ENDP

Luck_NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, NtProtectId
    syscall
    ret
Luck_NtProtectVirtualMemory ENDP

Luck_NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, NtCreateThreadId
    syscall
    ret
Luck_NtCreateThreadEx ENDP

PUBLIC NtReadId
PUBLIC NtWriteId
PUBLIC NtOpenId
PUBLIC NtCloseId
PUBLIC NtProtectId
PUBLIC NtCreateThreadId

END

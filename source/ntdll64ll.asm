;---------------------------------------------------------------------------
;   Functions that implementations require 32bit to 64 bit segment switching
;---------------------------------------------------------------------------

.686p

EXTERNDEF _X64Function : proc
EXTERNDEF _MemCpy : proc
EXTERNDEF _MemCmp : proc
EXTERNDEF _GetTEB64 : proc

EnterX64 macro 
    push  ebp
    mov	  ebp, esp
    and	  esp, 0FFFFFFF0h
    push  33h
    push  offset X64
    retf 
X64:
    mov	ebp, ebp
    mov	esp, esp
endm

LeaveX64 macro 
    push 23h
    push offset X86
    db 48h ; REX.W
    retf
X86:
    mov	cx, ss ; AMD K8 stack segment issue workaround
    mov	ss, cx
    
    mov	esp, ebp
    pop	ebp
endm

.code

_X64Function proc
    EnterX64

    db 48h ; REX.W
    mov	eax, [ebp + 8]
    mov	ecx, [ebp + 10h]
    
CopyArgs:
    push [ebp + ecx * 8 + 0Ch]
    loop CopyArgs
    
    db 48h ; REX.W
    mov ecx, [esp]
    db 48h ; REX.W
    mov edx, [esp + 8]
    db 4Ch ; REX.WX
    mov eax, [esp + 10h] ; mov r8, [esp + 10h]
    db 4Ch ; REX.WX
    mov ecx, [esp + 18h] ; mov r9, [esp + 18h]
    
    call eax
    
    LeaveX64
    
    ret
    
_X64Function endp

_MemCpy proc 
    push edi
    push esi
    
    EnterX64
    
    mov	edi, [ebp + 10h]
    db 48h ; REX.W
    mov	esi, [ebp + 14h]
    mov	ecx, [ebp + 1Ch]
    rep movsb
    
    LeaveX64

    pop	esi
    pop	edi
    ret
    
_MemCpy endp
    
_MemCmp proc
    push edi
    push esi
    xor  eax, eax
    
    EnterX64
    
    mov	edi, [ebp + 10h]
    db 48h; REX.W
    mov	esi, [ebp + 14h]
    mov	ecx, [ebp + 1Ch]
    repe cmpsb
    
    mov	esi, 0FFFFFFFFh
    mov edi, 1
    cmova eax, edi
    cmovb eax, esi
    
    LeaveX64

    pop	esi
    pop	edi
    ret
_MemCmp endp

_GetTEB64 proc
    EnterX64
    
    mov eax, [ebp + 8]
    db 4Ch ; REX.WX
    mov [eax], esp ; mov [rax], r12
    
    LeaveX64
    ret
_GetTEB64 endp

end

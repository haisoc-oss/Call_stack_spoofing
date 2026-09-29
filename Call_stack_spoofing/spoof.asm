.code
Spoof PROC
	pop r15 ;save original ret adress to r15

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;	create our fake stack frame for each function	 ;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	push 0					;this will terminate the stack unwinding

	mov  rax ,[rsp + 40]	;get pointer to param struct and save to rax - rax become pointer to param struct
	mov  [rax+ 64], r15		;save original ret adress to param struct
	
	mov	 r15 ,[rax + 8]		;get size of BaseThreadInitThunk
	sub  rsp, r15			;create stack frame for BaseThreadInitThunk
	mov  r15 ,[rax]			;save ret adress of BaseThreadInitThunk
	push r15				;push ret adress of BaseThreadInitThunk

	mov	 r15 ,[rax + 24]  ;get size of RtlUserThreadStart
	sub  rsp, r15			;create stack frame for RtlUserThreadStart
	mov  r15 ,[rax + 16]	;save ret adress of RtlUserThreadStart
	push r15				;push ret adress of RtlUserThreadStart

	mov	 r15 ,[rax + 40]	;get size of Gadget
	sub  rsp, r15			;create stack frame for Gadget
	mov  r15 ,[rax + 32]	;save ret adress of Gadget
	push r15				;push ret adress of Gadget - which is ret address when calling fake


	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;    Change rbx value and jump to messbox to print fake mess	   ;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	mov [rax + 48] , rbx	;save rbx
	mov rbx , [Restore]	    ;move adress of Restore part to rbx
	mov [rax] , rbx			;save adress of Restore part from rbx to frist member of param struct
	mov rbx, rax			;rbx replace rax to become pointer to param struct
	mov r15 ,[rax + 56]		;mov messbox adress to r15
	jmp r15					;jmp to fake messbox

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;	   Restore part - restore stack and rbx, and call messbox to print origin mess		;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	Restore:
	add  rsp, 24			;restore stack for 3 push adress

	mov	 r15 ,[rbx + 8]  ;get size of BaseThreadInitThunk
	add  rsp, r15			;Restore stack frame for BaseThreadInitThunk

	mov	 r15 ,[rbx + 24]  ;get size of RtlUserThreadStart
	add  rsp, r15			;Restore stack frame for RtlUserThreadStart

	mov	 r15 ,[rbx + 40]  ;get size of Gadget
	add  rsp, r15			;Restore stack frame for Gadget

	mov r15, [rbx + 64]
	push r15

	mov rcx , [rsp+48]
	mov rdx , [rsp+56]
	mov r8 ,  [rsp+64]
	mov r9,   [rsp+72]

	mov r15, [rbx + 56]
	mov rbx, [rbx + 38]

	jmp r15

Spoof ENDP
END
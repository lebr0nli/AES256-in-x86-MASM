; Constants

Nr = 14      ; Nb = 128//32, Nk = 256//32 (Sec 3.5 in The Design of Rijndael)
ITER_SIZE = 8       ; 32 // 4 = 8

; Prototypes

Sub_Bytes PROTO, s: PTR BYTE, is_inv: BYTE

Expand_Key PROTO, pMaster_key: PTR BYTE, pRound_keys: PTR BYTE

Add_Round_Keys PROTO, s: PTR BYTE, k: PTR BYTE

Shift_Rows PROTO, s: PTR BYTE

Inv_Shift_Rows PROTO, s: PTR BYTE

xtime PROTO, x: BYTE

Mix_Single_Column PROTO, arr: PTR BYTE

Mix_Columns PROTO, s: PTR BYTE

Inv_Mix_Columns PROTO, s: PTR BYTE

AES256_Encrypt PROTO,
     pMaster_key: PTR BYTE,         ; ptr to 32 bytes key
     pData: PTR BYTE                ; ptr to 16 bytes buffer you want to encrypt

AES256_Decrypt PROTO,
     pMaster_key: PTR BYTE,         ; ptr to a 32 bytes key
     pData: PTR BYTE                ; ptr to a 16 bytes buffer you want to decrypt

AES256_File_Encrypt_ECB_PKCS7 PROTO,
    pMaster_key: PTR BYTE,          ; ptr to a 32 bytes key
    pInputFilename: PTR BYTE,       ; ptr to an input filename
    pOutputFilename: PTR BYTE       ; ptr to an output filename

AES256_File_Decrypt_ECB_PKCS7 PROTO,
    pMaster_key: PTR BYTE,          ; ptr to a 32 bytes key
    pInputFilename: PTR BYTE,       ; ptr to an input filename
    pOutputFilename: PTR BYTE       ; ptr to an output filename

.data
s_box BYTE 63h, 7Ch, 77h, 7Bh, 0F2h, 6Bh, 6Fh, 0C5h, 30h, 01h, 67h, 2Bh, 0FEh, 0D7h, 0ABh, 76h
      BYTE 0CAh, 82h, 0C9h, 7Dh, 0FAh, 59h, 47h, 0F0h, 0ADh, 0D4h, 0A2h, 0AFh, 9Ch, 0A4h, 72h, 0C0h
      BYTE 0B7h, 0FDh, 93h, 26h, 36h, 3Fh, 0F7h, 0CCh, 34h, 0A5h, 0E5h, 0F1h, 71h, 0D8h, 31h, 15h
      BYTE 04h, 0C7h, 23h, 0C3h, 18h, 96h, 05h, 9Ah, 07h, 12h, 80h, 0E2h, 0EBh, 27h, 0B2h, 75h
      BYTE 09h, 83h, 2Ch, 1Ah, 1Bh, 6Eh, 5Ah, 0A0h, 52h, 3Bh, 0D6h, 0B3h, 29h, 0E3h, 2Fh, 84h
      BYTE 53h, 0D1h, 00h, 0EDh, 20h, 0FCh, 0B1h, 5Bh, 6Ah, 0CBh, 0BEh, 39h, 4Ah, 4Ch, 58h, 0CFh
      BYTE 0D0h, 0EFh, 0AAh, 0FBh, 43h, 4Dh, 33h, 85h, 45h, 0F9h, 02h, 7Fh, 50h, 3Ch, 9Fh, 0A8h
      BYTE 51h, 0A3h, 40h, 8Fh, 92h, 9Dh, 38h, 0F5h, 0BCh, 0B6h, 0DAh, 21h, 10h, 0FFh, 0F3h, 0D2h
      BYTE 0CDh, 0Ch, 13h, 0ECh, 5Fh, 97h, 44h, 17h, 0C4h, 0A7h, 7Eh, 3Dh, 64h, 5Dh, 19h, 73h
      BYTE 60h, 81h, 4Fh, 0DCh, 22h, 2Ah, 90h, 88h, 46h, 0EEh, 0B8h, 14h, 0DEh, 5Eh, 0Bh, 0DBh
      BYTE 0E0h, 32h, 3Ah, 0Ah, 49h, 06h, 24h, 5Ch, 0C2h, 0D3h, 0ACh, 62h, 91h, 95h, 0E4h, 79h
      BYTE 0E7h, 0C8h, 37h, 6Dh, 8Dh, 0D5h, 4Eh, 0A9h, 6Ch, 56h, 0F4h, 0EAh, 65h, 7Ah, 0AEh, 08h
      BYTE 0BAh, 78h, 25h, 2Eh, 1Ch, 0A6h, 0B4h, 0C6h, 0E8h, 0DDh, 74h, 1Fh, 4Bh, 0BDh, 8Bh, 8Ah
      BYTE 70h, 3Eh, 0B5h, 66h, 48h, 03h, 0F6h, 0Eh, 61h, 35h, 57h, 0B9h, 86h, 0C1h, 1Dh, 9Eh
      BYTE 0E1h, 0F8h, 98h, 11h, 69h, 0D9h, 8Eh, 94h, 9Bh, 1Eh, 87h, 0E9h, 0CEh, 55h, 28h, 0DFh
      BYTE 8Ch, 0A1h, 89h, 0Dh, 0BFh, 0E6h, 42h, 68h, 41h, 99h, 2Dh, 0Fh, 0B0h, 54h, 0BBh, 16h

inv_s_box BYTE 52h, 09h, 6Ah, 0D5h, 30h, 36h, 0A5h, 38h, 0BFh, 40h, 0A3h, 9Eh, 81h, 0F3h, 0D7h, 0FBh
          BYTE 7Ch, 0E3h, 39h, 82h, 9Bh, 2Fh, 0FFh, 87h, 34h, 8Eh, 43h, 44h, 0C4h, 0DEh, 0E9h, 0CBh
          BYTE 54h, 7Bh, 94h, 32h, 0A6h, 0C2h, 23h, 3Dh, 0EEh, 4Ch, 95h, 0Bh, 42h, 0FAh, 0C3h, 4Eh
          BYTE 08h, 2Eh, 0A1h, 66h, 28h, 0D9h, 24h, 0B2h, 76h, 5Bh, 0A2h, 49h, 6Dh, 8Bh, 0D1h, 25h
          BYTE 72h, 0F8h, 0F6h, 64h, 86h, 68h, 98h, 16h, 0D4h, 0A4h, 5Ch, 0CCh, 5Dh, 65h, 0B6h, 92h
          BYTE 6Ch, 70h, 48h, 50h, 0FDh, 0EDh, 0B9h, 0DAh, 5Eh, 15h, 46h, 57h, 0A7h, 8Dh, 9Dh, 84h
          BYTE 90h, 0D8h, 0ABh, 00h, 8Ch, 0BCh, 0D3h, 0Ah, 0F7h, 0E4h, 58h, 05h, 0B8h, 0B3h, 45h, 06h
          BYTE 0D0h, 2Ch, 1Eh, 8Fh, 0CAh, 3Fh, 0Fh, 02h, 0C1h, 0AFh, 0BDh, 03h, 01h, 13h, 8Ah, 6Bh
          BYTE 3Ah, 91h, 11h, 41h, 4Fh, 67h, 0DCh, 0EAh, 97h, 0F2h, 0CFh, 0CEh, 0F0h, 0B4h, 0E6h, 73h
          BYTE 96h, 0ACh, 74h, 22h, 0E7h, 0ADh, 35h, 85h, 0E2h, 0F9h, 37h, 0E8h, 1Ch, 75h, 0DFh, 6Eh
          BYTE 47h, 0F1h, 1Ah, 71h, 1Dh, 29h, 0C5h, 89h, 6Fh, 0B7h, 62h, 0Eh, 0AAh, 18h, 0BEh, 1Bh
          BYTE 0FCh, 56h, 3Eh, 4Bh, 0C6h, 0D2h, 79h, 20h, 9Ah, 0DBh, 0C0h, 0FEh, 78h, 0CDh, 5Ah, 0F4h
          BYTE 1Fh, 0DDh, 0A8h, 33h, 88h, 07h, 0C7h, 31h, 0B1h, 12h, 10h, 59h, 27h, 80h, 0ECh, 5Fh
          BYTE 60h, 51h, 7Fh, 0A9h, 19h, 0B5h, 4Ah, 0Dh, 2Dh, 0E5h, 7Ah, 9Fh, 93h, 0C9h, 9Ch, 0EFh
          BYTE 0A0h, 0E0h, 3Bh, 4Dh, 0AEh, 2Ah, 0F5h, 0B0h, 0C8h, 0EBh, 0BBh, 3Ch, 83h, 53h, 99h, 61h
          BYTE 17h, 2Bh, 04h, 7Eh, 0BAh, 77h, 0D6h, 26h, 0E1h, 69h, 14h, 63h, 55h, 21h, 0Ch, 7Dh
r_con BYTE 00h, 01h, 02h, 04h, 08h, 10h, 20h, 40h

INPUT_ERROR BYTE "Can't open input file (maybe not exist): ", 0

OUTPUT_ERROR BYTE "Can't write (maybe exist already): ", 0

.code

Sub_Bytes PROC USES eax ecx esi edi, s: PTR BYTE, is_inv: BYTE
    ; Sec 3.4.2 in The Design of Rijndael
    LOCAL box: PTR BYTE
    mov ecx, 16
    mov esi, s
    mov al, is_inv
    .if al != 1     ; not Inv_Sub_Bytes
        mov box, OFFSET s_box
    .else
        mov box, OFFSET inv_s_box
    .endif
    mov edi, box
    .while ecx > 0
        movzx eax, BYTE PTR [esi]
        add edi, eax
        mov al, [edi]
        mov [esi], al
        mov edi, box
        inc esi
        dec ecx
    .endw
    ret
Sub_Bytes ENDP

Expand_Key PROC USES eax ebx ecx esi edi, pMaster_key: PTR BYTE, pRound_keys: PTR BYTE
    LOCAL rc_idx: BYTE, word_count: WORD
    mov edi, pRound_keys
    mov esi, pMaster_key
    mov ecx, ITER_SIZE * 8
    cld
    rep movsb
    mov rc_idx, 1
    mov word_count, ITER_SIZE
    mov ecx, 32                         ; generated bytes count
    .while ecx < 240                    ;(Nr + 1) * 16
        mov edi, pRound_keys         
        add edi, ecx                    ; edi = new_word
        mov ax, word_count
        mov bl, ITER_SIZE
        div bl
        .if ah == 0
            ; circular shift last 4 bytes (1 WORD)
            mov esi, edi      
            sub esi, 4                  ; esi = previous generated WORD 
            mov al, [esi + 1]
            mov [edi], al
            mov al, [esi + 2]
            mov [edi + 1], al
            mov al, [esi + 3]
            mov [edi + 2], al
            mov al, [esi]
            mov [edi + 3], al 
            ; map to S-BOX
            xor eax, eax
            mov esi, OFFSET s_box
            mov al, [edi]
            mov al, [esi + eax]
            mov [edi], al
            mov al, [edi + 1]
            mov al, [esi + eax]
            mov [edi + 1], al
            mov al, [edi + 2]
            mov al, [esi + eax]
            mov [edi + 2], al
            mov al, [edi + 3]
            mov al, [esi + eax]
            mov [edi + 3], al
            ; XOR with R_CON[rc_idx]
            mov al, [edi]
            movzx ebx, rc_idx
            mov esi, OFFSET r_con
            xor al, [esi + ebx]
            mov [edi], al
            inc rc_idx
        .else
            ; copy previous key
            mov esi, edi
            sub esi, 4                  ; esi = previous generated WORD 
            mov al, [esi]
            mov [edi], al
            mov al, [esi + 1]
            mov [edi + 1], al
            mov al, [esi + 2]
            mov [edi + 2], al
            mov al, [esi + 3]
            mov [edi + 3], al
            .if ah == 4
                ; map to S-BOX
                xor eax, eax
                mov esi, OFFSET s_box  ; esi = s_box
                mov al, [edi]
                mov al, [esi + eax]
                mov [edi], al
                mov al, [edi + 1]
                mov al, [esi + eax]
                mov [edi + 1], al
                mov al, [edi + 2]
                mov al, [esi + eax]
                mov [edi + 2], al
                mov al, [edi + 3]
                mov al, [esi + eax]
                mov [edi + 3], al
            .endif
        .endif
        ; XOR new WORD with previous iteration WORD
        mov esi, edi
        sub esi, ITER_SIZE * 4      ; esi = last_iter_word = now - ITER_SIZE * 4
        mov al, [edi]
        xor al, [esi]
        mov [edi], al
        mov al, [edi + 1]
        xor al, [esi + 1]
        mov [edi + 1], al
        mov al, [edi + 2]
        xor al, [esi + 2]
        mov [edi + 2], al
        mov al, [edi + 3]
        xor al, [esi + 3]
        mov [edi + 3], al

        inc word_count
        add ecx, 4
    .endw
    ret
Expand_Key ENDP


Add_Round_Keys PROC USES eax ecx esi edi, s: PTR BYTE, k: PTR BYTE
    ; Sec 3.4.4 in The Design of Rijndael
    mov ecx, 16
    mov esi, s
    mov edi, k
    .while ecx > 0
        mov al, [esi]
        xor al, [edi]
        mov [esi], al
        inc esi
        inc edi
        dec ecx
    .endw
    ret
Add_Round_Keys ENDP

Shift_Rows PROC USES eax esi, s: PTR BYTE
    ; Sec 3.4.2 in The Design of Rijndael
    LOCAL tmp1: BYTE, tmp2:BYTE
    mov esi, s

    ; left shift row two 1 byte
    mov al, [esi + 1]
    mov tmp1, al
    mov al, [esi + 5]
    mov [esi + 1], al
    mov al, [esi + 9]
    mov [esi + 5], al
    mov al, [esi + 13]
    mov [esi + 9], al
    mov al, tmp1
    mov [esi + 13], al

    ; left shift row three 2 bytes
    mov al, [esi + 2]
    mov tmp1, al
    mov al, [esi + 6]
    mov tmp2, al
    mov al, [esi + 10]
    mov [esi + 2], al
    mov al, [esi + 14]
    mov [esi + 6], al
    mov al, tmp1
    mov [esi + 10], al
    mov al, tmp2
    mov [esi + 14], al

    ; left shift row four 3 bytes == right shift 1 bytes
    mov al, [esi + 15]
    mov tmp1, al
    mov al, [esi + 11]
    mov [esi + 15], al
    mov al, [esi + 7]
    mov [esi + 11], al
    mov al, [esi + 3]
    mov [esi + 7], al
    mov al, tmp1
    mov [esi + 3], al

    ret
Shift_Rows ENDP

Inv_Shift_Rows PROC USES eax esi, s: PTR BYTE
    ; Sec 3.4.2 in The Design of Rijndael
    LOCAL tmp1: BYTE, tmp2: BYTE
    mov esi, s

    ; right shift row two 1 byte
    mov al, [esi + 13]
    mov tmp1, al
    mov al, [esi + 9]
    mov [esi + 13], al
    mov al, [esi + 5]
    mov [esi + 9], al
    mov al, [esi + 1]
    mov [esi + 5], al
    mov al, tmp1
    mov [esi + 1], al

    ; right shift row three 2 bytes
    mov al, [esi + 10]
    mov tmp1, al
    mov al, [esi + 14]
    mov tmp2, al
    mov al, [esi + 2]
    mov [esi + 10], al
    mov al, [esi + 6]
    mov [esi + 14], al
    mov al, tmp1
    mov [esi + 2], al
    mov al, tmp2
    mov [esi + 6], al
    
    ; right shift row four 3 bytes == left shift 1 bytes
    mov al, [esi + 3]
    mov tmp1, al
    mov al, [esi + 7]
    mov [esi + 3], al
    mov al, [esi + 11]
    mov [esi + 7], al
    mov al, [esi + 15]
    mov [esi + 11], al
    mov al, tmp1
    mov [esi + 15], al

    ret
Inv_Shift_Rows ENDP

xtime PROC, x:BYTE
    xor eax, eax
    mov al, x
    shl ax, 1
    .if ah != 0
        xor al, 1Bh
    .endif
    xor ah, ah
    ret
xtime ENDP

Mix_Single_Column PROC USES eax esi, arr: PTR BYTE
    LOCAL t: BYTE, u: BYTE
    mov esi, arr
    ; t = arr[0] ^ arr[1] ^ arr[2] ^ arr[3]
    mov al, [esi]
    xor al, [esi + 1]
    xor al, [esi + 2]
    xor al, [esi + 3]
    mov t, al
    ; u = arr[0]
    mov al, [esi]
    mov u, al
    ; arr[0] ^= t ^ xtime(arr[0] ^ arr[1])
    mov al, [esi]
    xor al, [esi + 1]
    INVOKE xtime, al
    xor al, t
    xor al, [esi]
    mov [esi], al
    ; arr[1] ^= t ^ xtime(arr[1] ^ arr[2])
    mov al, [esi + 1]
    xor al, [esi + 2]
    INVOKE xtime, al
    xor al, t
    xor al, [esi + 1]
    mov [esi + 1], al
    ; arr[2] ^= t ^ xtime(arr[2] ^ arr[3])
    mov al, [esi + 2]
    xor al, [esi + 3]
    INVOKE xtime, al
    xor al, t
    xor al, [esi + 2]
    mov [esi + 2], al
    ; arr[3] ^= t ^ xtime(arr[3] ^ u)
    mov al, [esi + 3]
    xor al, u
    INVOKE xtime, al
    xor al, t
    xor al, [esi + 3]
    mov [esi + 3], al
    ret
Mix_Single_Column ENDP

Mix_Columns PROC USES eax ecx esi, s: PTR BYTE
    mov ecx, 4
    mov esi, s
    .while ecx > 0
        INVOKE Mix_Single_Column, esi
        add esi, 4
        dec ecx
    .endw
    ret
Mix_Columns ENDP

Inv_Mix_Columns PROC USES eax ecx esi, s: PTR BYTE
    LOCAL u: BYTE, v: BYTE
    mov ecx, 4
    mov esi, s
    .while ecx > 0
        ; u = xtime(xtime(esi[0] ^ esi[2]))
        mov al, [esi + 0]
        xor al, [esi + 2]
        INVOKE xtime, al
        INVOKE xtime, al
        mov u, al
        ; v = xtime(xtime(esi[1] ^ esi[3]))
        mov al, [esi + 1]
        xor al, [esi + 3]
        INVOKE xtime, al
        INVOKE xtime, al
        mov v, al
        ; esi[0] ^= u
        mov al, [esi]
        xor al, u
        mov [esi], al
        ; esi[1] ^= v
        mov al, [esi + 1]
        xor al, v
        mov [esi + 1], al
        ; esi[2] ^= u
        mov al, [esi + 2]
        xor al, u
        mov [esi + 2], al
        ; esi[3] ^= v
        mov al, [esi + 3]
        xor al, v
        mov [esi + 3], al
        add esi, 4
        dec ecx
    .endw
    INVOKE Mix_Columns, s
    ret
Inv_Mix_Columns ENDP

AES256_Encrypt PROC USES eax ecx esi, pMaster_key: PTR BYTE, pData: PTR BYTE
    LOCAL round_keys[240]: BYTE
    ; Expand 32 bytes (256 bits) key
    INVOKE Expand_Key, pMaster_key, ADDR round_keys
    lea esi, round_keys


    ; Initialize (Round 0): Only add round key
    INVOKE Add_Round_Keys, pData, esi
    add esi, 16
    mov ecx, 1

    .while ecx < Nr
        ; Round 1 ~ (Nr-1): Sub -> Permuation(shift rows -> mix columns) -> add round key
        INVOKE Sub_Bytes, pData, 0
        INVOKE Shift_Rows, pData
        INVOKE Mix_Columns, pData
        INVOKE Add_Round_Keys, pData, esi
        add esi, 16
        inc ecx
    .endw

    ; Final Round (Round Nr): Sub -> Permuation(shift rows only) -> add round key
    INVOKE Sub_Bytes, pData, 0
    INVOKE Shift_Rows, pData
    INVOKE Add_Round_Keys, pData, esi

    ret
AES256_Encrypt ENDP

AES256_Decrypt PROC USES eax ecx esi, pMaster_key: PTR BYTE, pData: PTR BYTE
    LOCAL round_keys[240]: BYTE
    ; Expand 32 bytes (256 bits) key
    INVOKE Expand_Key, pMaster_key, ADDR round_keys
    lea esi, round_keys
    add esi, Nr * 16


    ; Initialize (Round 0): Only add round key
    INVOKE Add_Round_Keys, pData, esi
    sub esi, 16
    mov ecx, 1

    .while ecx < Nr
        ; Round 1 ~ (Nr-1): inv shift rows -> inv Sub -> add round key -> inv mix columns
        INVOKE Inv_Shift_Rows, pData
        INVOKE Sub_Bytes, pData, 1
        INVOKE Add_Round_Keys, pData, esi
        INVOKE Inv_Mix_Columns, pData
        sub esi, 16
        inc ecx
    .endw

    ; Final Round (Round Nr): inv shift rows only -> inv Sub -> add round key
    INVOKE Inv_Shift_Rows, pData
    INVOKE Sub_Bytes, pData, 1
    INVOKE Add_Round_Keys, pData, esi

    ret
AES256_Decrypt ENDP

AES256_File_Encrypt_ECB_PKCS7 PROC USES eax ecx edi esi, pMaster_key: PTR BYTE, pInputFilename: PTR BYTE, pOutputFilename: PTR BYTE
	LOCAL readFileHandle: DWORD, writeFileHandle: DWORD, data[16]: BYTE, byteRead: DWORD, byteWritten: DWORD
	
	; open input file
	INVOKE CreateFile, pInputFilename, GENERIC_READ, DO_NOT_SHARE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
	.if eax == INVALID_HANDLE_VALUE
		mov edx, OFFSET INPUT_ERROR
		call WriteString
		mov edx, pInputFilename
		call WriteString
		call Crlf
		ret
	.endif
	mov readFileHandle, eax

	; open output file
	INVOKE CreateFile, pOutputFilename, GENERIC_WRITE, DO_NOT_SHARE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
	.if eax == INVALID_HANDLE_VALUE
		mov edx, OFFSET OUTPUT_ERROR
		call WriteString
		mov edx, pOutputFilename
		call WriteString
		call Crlf
		ret
	.endif
	mov writeFileHandle, eax

	; read data and check EOF
	INVOKE ReadFile, readFileHandle, ADDR data, 16, ADDR byteRead, 0
	mov edx, byteRead
	.while edx == 16					; while not EOF
		; encrypt and write data
		INVOKE AES256_Encrypt, pMaster_key, ADDR data
		INVOKE WriteFile, writeFileHandle, ADDR data, 16, ADDR byteWritten, 0
		; read data and check EOF
		INVOKE ReadFile, readFileHandle, ADDR data, 16, ADDR byteRead, 0
		mov edx, byteRead
	.endw

	; EOF now, add padding to last part (PKCS#7)
	lea edi, data
	.if edx != 0                        ; edx is last block size
		xor eax, eax
		mov al, dl
		add edi, eax
		mov ecx, 16
		sub ecx, eax
		cld
		mov al, 16
		sub eax, edx
		rep stosb
		INVOKE AES256_Encrypt, pMaster_key, ADDR data
		INVOKE WriteFile, writeFileHandle, ADDR data, 16, ADDR byteWritten, 0
	.else
		mov ecx, 16
		mov al, 16
		cld
		rep stosb
		INVOKE AES256_Encrypt, pMaster_key, ADDR data
		INVOKE WriteFile, writeFileHandle, ADDR data, 16, ADDR byteWritten, 0
	.endif

	INVOKE CloseHandle, readFileHandle
	INVOKE CloseHandle, writeFileHandle
	ret
AES256_File_Encrypt_ECB_PKCS7 ENDP

AES256_File_Decrypt_ECB_PKCS7 PROC USES eax ecx edx edi esi, pMaster_key: PTR BYTE, pInputFilename: PTR BYTE, pOutputFilename: PTR BYTE
	LOCAL readFileHandle: DWORD, writeFileHandle: DWORD, data[16]: BYTE, tmp[16]: BYTE, byteRead: DWORD, byteWritten: DWORD
	
	; open input file
	INVOKE CreateFile, pInputFilename, GENERIC_READ, DO_NOT_SHARE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
	.if eax == INVALID_HANDLE_VALUE
		mov edx, OFFSET INPUT_ERROR
		call WriteString
		mov edx, pInputFilename
		call WriteString
		call Crlf
		ret
	.endif
	mov readFileHandle, eax

	; open output file
	INVOKE CreateFile, pOutputFilename, GENERIC_WRITE, DO_NOT_SHARE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
	.if eax == INVALID_HANDLE_VALUE
		mov edx, OFFSET OUTPUT_ERROR
		call WriteString
		mov edx, pOutputFilename
		call WriteString
		call Crlf
		ret
	.endif
	mov writeFileHandle, eax

	; read data and check EOF
	INVOKE ReadFile, readFileHandle, ADDR data, 16, ADDR byteRead, 0
	INVOKE ReadFile, readFileHandle, ADDR tmp, 16, ADDR byteRead, 0
	INVOKE SetFilePointer, readFileHandle, -16, 0, FILE_CURRENT
	mov edx, byteRead
	.while edx == 16					; while not EOF, which means data is not a padding
		; decrypt and write data
		INVOKE AES256_Decrypt, pMaster_key, ADDR data
		INVOKE WriteFile, writeFileHandle, ADDR data, 16, ADDR byteWritten, 0
		; read data and check EOF
		INVOKE ReadFile, readFileHandle, ADDR data, 16, ADDR byteRead, 0
		INVOKE ReadFile, readFileHandle, ADDR tmp, 16, ADDR byteRead, 0
		INVOKE SetFilePointer, readFileHandle, -16, 0, FILE_CURRENT
		mov edx, byteRead
	.endw

	; EOF now, unpadding last part (PKCS#7)
	lea esi, data
	mov ecx, 16
	mov ebx, 1
	INVOKE AES256_Decrypt, pMaster_key, ADDR data
	lea esi, data
	mov ecx, 16
	mov ebx, 1
	xor edx, edx
	mov dl, [esi + 15]			; dl = data length without padding
	.if edx < 16					; all padding, skip
		mov ecx, 16
		sub ecx, edx
		INVOKE WriteFile, writeFileHandle, ADDR data, ecx, ADDR byteWritten, 0
	.endif


	INVOKE CloseHandle, readFileHandle
	INVOKE CloseHandle, writeFileHandle
	ret
AES256_File_Decrypt_ECB_PKCS7 ENDP
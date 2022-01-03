TITLE AES256

INCLUDE Irvine32.inc
INCLUDE AES256.inc

main EQU start@0

.data
key BYTE 131, 202, 76, 209, 102, 238, 198, 126, 73, 168, 201, 124, 162, 61, 93, 222, 165, 156, 50, 126, 153, 6, 133, 196, 49, 96, 206, 118, 35, 68, 130, 112

crypted_file BYTE "flag.enc", 0

plaintext_file BYTE "flag.txt", 0

plaintext_file2 BYTE "flag2.txt", 0

string1 BYTE "Encrypt finish!", 0ah, 0

string2 BYTE "Decrypt finish!", 0ah, 0

.code

main PROC
    ; encrypt flag.txt and save the result to flag.enc
	INVOKE AES256_File_Encrypt_ECB_PKCS7, OFFSET key, OFFSET plaintext_file, OFFSET crypted_file
	mov edx, OFFSET string1
	call WriteString

    ; decrypt flag.enc and save the result to flag2.txt
	INVOKE AES256_File_Decrypt_ECB_PKCS7, OFFSET key, OFFSET crypted_file, OFFSET plaintext_file2
	mov edx, OFFSET string2
	call WriteString

	call WaitMsg
	exit
main ENDP
END main

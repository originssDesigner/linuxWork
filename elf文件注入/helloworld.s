.section .data
   output:
          .ascii "helloworld"
          len = . -output
.section .text
.global _start
_start:     
      mov  $4,    %eax
      mov  $1,    %ebx
      mov  $output, %ecx
      mov  $len,   %edx
      int  $0x80
      
      mov  $1,    %eax
      mov  $0,    %ebx
      int $0x80


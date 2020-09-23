.text
.global main
.type main,@function

main:
   pushq   %rax
   pushq   %rbx
   pushq   %rcx
   pushq   %rdx
   
   movq   $4, %rax
   movq   $1, %rbx
   movq   $output,%rcx
   movq   $10, %rdx

   popq  %rdx
   popq  %rcx
   popq  %rbx
   popq  %rax
  
   movq $1,%rax
   movq $0,%rbx
   int  $0x80
output:
  .string "helloworld"

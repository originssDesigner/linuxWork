#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <elf.h>
//32位 
void fileheader(const char *pbuff,FILE* fp);
void secheader(const char *pbuff,FILE* fp);
void tableheader(const char *pbuff,FILE* fp);
void outputsyminfo(const Elf32_Sym *psym, const char *pbuffstr, int ncount,FILE* fp);
void proheader(const char *pbuff,FILE* fp);
void relocheader(const char *pbuff,FILE* fp);
int main()
{

    FILE *fp1;
    fp1=fopen("test32","r");
    FILE *fp11;
    fp11 = fopen( "file32.txt" , "w" );
	char *pbuff1=(char*)malloc(65535);
	fread(pbuff1,sizeof(Elf32_Half),500,fp1);
        fileheader(pbuff1,fp11);	
    printf("\n");
    
	FILE *fp2;
    fp2=fopen("test32","r");
	char *pbuff2=(char*)malloc(65535);
	fread(pbuff2,sizeof(Elf32_Shdr),500,fp2);
        secheader(pbuff2,fp11);
    printf("\n");
    
   	FILE *fp3;
    fp3=fopen("test32","r");
	char *pbuff3=(char*)malloc(65535);
	fread(pbuff3,sizeof(Elf32_Shdr),500,fp3);
        tableheader(pbuff3,fp11);
    printf("\n");

	FILE *fp4;
    fp4=fopen("test32","r");
	char *pbuff4=(char*)malloc(65535);
	fread(pbuff4,sizeof(Elf32_Ehdr),500,fp4);
        proheader(pbuff4,fp11);
	printf("\n");

/*	FILE *fp5;
    fp5=fopen("hello","r");
	char *pbuff5=(char*)malloc(65535);
	fread(pbuff5,sizeof(Elf32_Ehdr),500,fp5);
    relocheader(pbuff5,fp11);
	return 0;*/

//    fclose(fp5);
	fclose(fp4); 
    fclose(fp3);
	fclose(fp2);
    fclose(fp11);
    fclose(fp1);
   
}
//read reloc header
void relocheader(const char *pbuff,FILE* fp)
{
    //get sectionheader
    Elf32_Ehdr* pfilehead = (Elf32_Ehdr*)pbuff;
    Elf32_Shdr* psecheader = (Elf32_Shdr*)(pbuff + pfilehead->e_shoff);
    Elf32_Shdr* pshstr = (Elf32_Shdr*)(psecheader + pfilehead->e_shstrndx);
    char* pstrbuff = (char*)(pbuff + pshstr->sh_offset);
    for(int i = 0;i<pfilehead->e_shnum;++i)
    {
        if(!strncmp(psecheader[i].sh_name + pstrbuff, ".rel", 4))
        {
            int ncount = psecheader[i].sh_size / psecheader[i].sh_entsize;
            fprintf(fp,"\r\nRelocation section '%s' at offset %0lX contains %d entries:\r", psecheader[i].sh_name + pstrbuff, psecheader[i].sh_offset,
                   ncount);
            Elf32_Rela* preltable = (Elf32_Rela*)(pbuff + psecheader[i].sh_offset);

            fprintf(fp,"%-16s  %-16s  %-16s  %-16s  %-16s\r", "Offset", "Info", "Type", "Sym.Value", "Sym.Name + Addend");
            int symnum = psecheader[i].sh_link;
            int strnum = psecheader[symnum].sh_link;
            //str addr
            char* prelstrbuf = (char*)(psecheader[strnum].sh_offset + pbuff);
            //symbol
            Elf32_Sym* psym = (Elf32_Sym*)(pbuff + psecheader[symnum].sh_offset);
            for(int n = 0;n<ncount;++n)
            {
                fprintf(fp,"%016lX  %016lX  ", preltable[n].r_offset, preltable[n].r_info);
                switch(ELF64_R_TYPE(preltable[n].r_info))
                {
                    case R_386_NONE:
                        fprintf(fp,"%-16s", "R_386_NONE");break;
                    case R_386_32:
                        fprintf(fp,"%-16s", "R_386_32");break;
                    case R_386_PC32:
                        fprintf(fp,"%-16s", "R_386_PC32");break;
                    case R_386_GOT32:
                        fprintf(fp,"%-16s", "R_386_GOT32");break;
                    case R_386_PLT32:
                        fprintf(fp,"%-16s", "R_386_PLT32");break;
                    case R_386_COPY:
                        fprintf(fp,"%-16s", "R_386_COPY");break;
                    case R_386_GLOB_DAT:
                        fprintf(fp,"%-16s", "R_386_GLOB_DAT");break;
                    case R_386_JMP_SLOT:
                        fprintf(fp,"%-16s", "R_386_JMP_SLOT");break;
                    case R_386_RELATIVE:
                        fprintf(fp,"%-16s", "R_386_RELATIVE");break;
                    case R_386_GOTOFF:
                        fprintf(fp,"%-16s", "R_386_GOTOFF");break;
                    case R_386_GOTPC:
                        fprintf(fp,"%-16s", "R_386_GOTPC");break;
                    default:
                        break;
                }
                fprintf(fp,"  %016lX  ", (psym + ELF32_R_SYM(preltable[n].r_info))->st_value);

                fprintf(fp,"%s + %lu\r", (char*)(prelstrbuf + (psym + ELF32_R_SYM(preltable[n].r_info))->st_name), preltable[n].r_addend);
            }

        }
    }
    printf("relocheader存储成功！"); 
}

//read program header
void proheader(const char *pbuff,FILE* fp)
{
    Elf32_Ehdr* pfilehead = (Elf32_Ehdr*)pbuff;
    Elf32_Phdr* pproheader = (Elf32_Phdr*)(pbuff + pfilehead->e_phoff);
    Elf32_Shdr* psecheader = (Elf32_Shdr*)(pbuff + pfilehead->e_shoff);
    Elf32_Shdr* pshstr = (Elf32_Shdr*)(psecheader + pfilehead->e_shstrndx);
    char* pstrbuff = (char*)(pbuff + pshstr->sh_offset);
    fprintf(fp,"Elf 文件类型是");
    switch(pfilehead->e_type)
    {
        case 0:
            fprintf(fp," No file type\r\n");
            break;
        case 1:
            fprintf(fp," Relocatable file\r\n");
            break;
        case 2:
            fprintf(fp," Executable file\r\n");
            break;
        case 3:
            fprintf(fp," Shared object file\r\n");
            break;
        case 4:
            fprintf(fp," Core file\r\n");
            break;
        default:
            fprintf(fp," ERROR\r\n");
            break;
    }
    fprintf(fp,"入口点位置 0X%0lX\r\n", pfilehead->e_entry);
    fprintf(fp,"共有 %d 程序头, 偏移位置 %lu\r\n\r\n", pfilehead->e_phnum, pfilehead->e_phoff);
    fprintf(fp,"Program Headers:\r\n");
    fprintf(fp,"  %-14s  %-16s  %-16s  %-16s\r\n", "Type", "Offset", "VirtAddr", "PhysAddr");
    fprintf(fp,"  %-14s  %-16s  %-16s  %-6s  %-6s\r\n", "", "FileSiz", "MemSiz", "Flags", "Align");
    for(int i=0;i<pfilehead->e_phnum;++i)
    {
        //type
        switch(pproheader[i].p_type)
        {
            case PT_NULL:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_LOAD:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "LOAD", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_DYNAMIC:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "DYNAMIC", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_INTERP:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "INTERP", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_NOTE:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "NOTE", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_SHLIB:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "SHLIB", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_PHDR:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "PHDR", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_TLS:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "TLS", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_NUM:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "NUM", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_GNU_EH_FRAME:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "GNU_EH_FRAME", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_GNU_RELRO:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "GNU_RELRO", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            case PT_GNU_STACK:
                fprintf(fp,"  %-14s  %016lX  %016lX  %016lX\r\n  %-14s  %016lX  %016lX  ", "GNU_STACK", pproheader[i].p_offset, pproheader[i].p_vaddr,
                       pproheader[i].p_paddr, "", pproheader[i].p_filesz, pproheader[i].p_memsz);break;
            default:
                break;
        }
        //
        switch(pproheader[i].p_flags)
        {
            case PF_X:
                fprintf(fp,"%-6s  %-lX\r\n", "  E", pproheader[i].p_align);break;
            case PF_W:
                fprintf(fp,"%-6s  %-lX\r\n", " W ", pproheader[i].p_align);break;
            case PF_R:
                fprintf(fp,"%-6s  %-lX\r\n", "R  ", pproheader[i].p_align);break;
            case PF_X|PF_W:
                fprintf(fp,"%-6s  %-lX\r\n", " WE", pproheader[i].p_align);break;
            case PF_X|PF_R:
                fprintf(fp,"%-6s  %-lX\r\n", "R E", pproheader[i].p_align);break;
            case PF_W|PF_R:
                fprintf(fp,"%-6s  %-lX\r\n", "RW ", pproheader[i].p_align);break;
            case PF_X|PF_R|PF_W:
                fprintf(fp,"%-6s  %-lX\r\n", "RWE", pproheader[i].p_align);break;
            default:
                fprintf(fp,"\r\n");
                break;
        }
        if(PT_INTERP == pproheader[i].p_type)
            fprintf(fp,"      [Requesting program interpreter: %s]\r\n", (char*)(pbuff + pproheader[i].p_offset));
    }
    fprintf(fp,"\r\n Section to Segment mapping:\r\n");
    fprintf(fp,"  段节...\r\n");
    for(int i=0;i<pfilehead->e_phnum;++i)
    {
        fprintf(fp,"   %-7d", i);
        for(int n = 0;n<pfilehead->e_shnum;++n)
        {
            Elf64_Off temp = psecheader[n].sh_addr + psecheader[n].sh_size;
            if((psecheader[n].sh_addr>pproheader[i].p_vaddr && psecheader[n].sh_addr<pproheader[i].p_vaddr + pproheader[i].p_memsz)  ||
                    (temp > pproheader[i].p_vaddr && temp<=pproheader[i].p_vaddr + pproheader[i].p_memsz))
            {
                fprintf(fp,"%s ", (char*)(psecheader[n].sh_name + pstrbuff));
            }
        }
        fprintf(fp,"\r\n");
    }
    printf("programeheader存储成功！"); 
}

//read symbol table
void tableheader(const char *pbuff,FILE* fp)
{
    //从节区里面定位到偏移
    Elf32_Ehdr* pfilehead = (Elf32_Ehdr*)pbuff;
    Elf32_Half eshstrndx = pfilehead->e_shstrndx;
    Elf32_Shdr* psecheader = (Elf32_Shdr*)(pbuff + pfilehead->e_shoff);
    Elf32_Shdr* pshstr = (Elf32_Shdr*)(psecheader + eshstrndx);
    char* pshstrbuff = (char *)(pbuff + pshstr->sh_offset);
     
    for(int i = 0;i<pfilehead->e_shnum;++i)
    {
        if(!strcmp(psecheader[i].sh_name + pshstrbuff, ".dynsym") || !strcmp(psecheader[i].sh_name + pshstrbuff, ".symtab"))
        {
            Elf32_Sym* psym = (Elf32_Sym*)(pbuff + psecheader[i].sh_offset);
            int ncount = psecheader[i].sh_size / psecheader[i].sh_entsize;
            char* pbuffstr = (char*)((psecheader + psecheader[i].sh_link)->sh_offset + pbuff);
            fprintf(fp,"Symbol table '%s' contains %d entries:\r\n", psecheader[i].sh_name + pshstrbuff, ncount);
            outputsyminfo(psym, pbuffstr, ncount,fp);
            continue;
        }
    }
    printf("tableheader存储成功！"); 
}
void outputsyminfo(const Elf32_Sym *psym, const char *pbuffstr, int ncount,FILE* fp)
{
    fprintf(fp,"%7s  %-8s          %s  %s    %s   %s      %s  %s\r\n",
           "Num:", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
    for(int i = 0;i<ncount;++i)
    {
        fprintf(fp,"%6d:  %016x  %-6u", i, psym[i].st_value, psym[i].st_size);
        char typelow = ELF32_ST_TYPE(psym[i].st_info);
        char bindhig = ELF32_ST_BIND(psym[i].st_info);
        switch(typelow)
        {
            case STT_NOTYPE:
                fprintf(fp,"%-8s", "NOTYPE");break;
            case STT_OBJECT:
                fprintf(fp,"%-8s", "OBJECT");break;
            case STT_FUNC:
                fprintf(fp,"%-8s", "FUNC");break;
            case STT_SECTION:
                fprintf(fp,"%-8s", "SECTION");break;
            case STT_FILE:
                fprintf(fp,"%-8s", "FILE");break;
            default:
                break;
        }
        switch(bindhig)
        {
            case STB_LOCAL:
                fprintf(fp,"%-8s", "LOCAL"); break;
            case STB_GLOBAL:
                fprintf(fp,"%-8s", "GLOBAL"); break;
            case STB_WEAK:
                fprintf(fp,"%-8s", "WEAK"); break;
            default:
                break;
        }
        fprintf(fp,"%-8d", psym[i].st_other);
        switch(psym[i].st_shndx)
        {
            case SHN_UNDEF:
                fprintf(fp,"%s  %s\r\n", "UND", psym[i].st_name + pbuffstr);break;
            case SHN_ABS:
                fprintf(fp,"%s  %s\r\n", "ABS", psym[i].st_name + pbuffstr);break;
            case SHN_COMMON:
                fprintf(fp,"%s  %s\r\n", "COM", psym[i].st_name + pbuffstr);break;
            default:
                fprintf(fp,"%3d  %s\r\n", psym[i].st_shndx, psym[i].st_name + pbuffstr);break;
        }
    }
}

//read Section Header
void secheader(const char *pbuff,FILE* fp)
{
    //get number Section
    int nNumSec = *(Elf32_Half*)(pbuff + 48);
    //get shstrndex
    Elf32_Ehdr* pfilehead = (Elf32_Ehdr*)pbuff;
    Elf32_Half eshstrndx = pfilehead->e_shstrndx;
    //get section offset
    Elf32_Shdr* psecheader = (Elf32_Shdr*)(pbuff + pfilehead->e_shoff);
    Elf32_Shdr* pshstr = (Elf32_Shdr*)(psecheader + eshstrndx);
    char* pshstrbuff = (char *)(pbuff + pshstr->sh_offset);
    //output info
    fprintf(fp,"There are %d section headers, starting at offset 0x%lx:\r",
           nNumSec, *(Elf32_Off*)(pbuff + 32));
    fprintf(fp,"Section Headers:\r");
    fprintf(fp,"  [Nr] %-16s  %-16s  %-16s  %-16s\r", "Name", "Type", "Address", "Offset");
    fprintf(fp,"       %-16s  %-16s  %-5s  %-5s  %-5s  %-5s\r", "Size", "EntSize", "Flags", "Link", "Info", "Align");
    //travlest
    for(int i = 0;i<nNumSec;++i)
    {
        fprintf(fp,"  [%2d] %-16s  ", i, (char *)(psecheader[i].sh_name + pshstrbuff));
        //Type
        switch(psecheader[i].sh_type)
        {
            case SHT_NULL:
                fprintf(fp,"%-16s  ", "NULL");break;
            case SHT_PROGBITS:
                fprintf(fp,"%-16s  ", "PROGBITS");break;
            case SHT_SYMTAB:
                fprintf(fp,"%-16s  ", "SYMTAB");break;
            case SHT_STRTAB:
                fprintf(fp,"%-16s  ", "STRTAB");break;
            case SHT_RELA:
                fprintf(fp,"%-16s  ", "RELA");break;
            case SHT_HASH:
                fprintf(fp,"%-16s  ", "GNU_HASH");break;
            case SHT_DYNAMIC:
                fprintf(fp,"%-16s  ", "DYNAMIC");break;
            case SHT_NOTE:
                fprintf(fp,"%-16s  ", "NOTE");break;
            case SHT_NOBITS:
                fprintf(fp,"%-16s  ", "NOBITS");break;
            case SHT_REL:
                fprintf(fp,"%-16s  ", "REL");break;
            case SHT_SHLIB:
                fprintf(fp,"%-16s  ", "SHLIB");break;
            case SHT_DYNSYM:
                fprintf(fp,"%-16s  ", "DYNSYM");break;
            case SHT_INIT_ARRAY:
                fprintf(fp,"%-16s  ", "INIT_ARRY");break;
            case SHT_FINI_ARRAY:
                fprintf(fp,"%-16s  ", "FINI_ARRY");break;
            case SHT_PREINIT_ARRAY:
                fprintf(fp,"%-16s  ", "PREINIT_ARRAY");break;
            case SHT_GNU_HASH:
                fprintf(fp,"%-16s  ", "GNU_HASH");break;
            case SHT_GNU_ATTRIBUTES:
                fprintf(fp,"%-16s  ", "GNU_ATTRIBUTES");break;
            case SHT_GNU_LIBLIST:
                fprintf(fp,"%-16s  ", "GNU_LIBLIST");break;
            case SHT_GNU_verdef:
                fprintf(fp,"%-16s  ", "GNU_verdef");break;
            case SHT_GNU_verneed:
                fprintf(fp,"%-16s  ", "GNU_verneed");break;
            case SHT_GNU_versym:
                fprintf(fp,"%-16s  ", "GNU_versym");break;
            default:
                fprintf(fp,"%-16s  ", "NONE");break;
        }
        fprintf(fp,"%016lX  %08lX\r", psecheader[i].sh_addr, psecheader[i].sh_offset);
        fprintf(fp,"       %016lX  %016lx  ", psecheader[i].sh_size, psecheader[i].sh_entsize);
            switch (psecheader[i].sh_flags) {
                case 0:
                    fprintf(fp,"%3s    %4u  %4u  %4lu\r",
                           "", psecheader[i].sh_link, psecheader[i].sh_info, psecheader[i].sh_addralign);
                    break;
                case 1:
                    fprintf(fp,"%3s    %4u  %4u  %4lu\r",
                           "W", psecheader[i].sh_link, psecheader[i].sh_info, psecheader[i].sh_addralign);
                    break;
                case 2:
                    fprintf(fp,"%3s    %4u  %4u  %4lu\r",
                           "A", psecheader[i].sh_link, psecheader[i].sh_info, psecheader[i].sh_addralign);
                    break;
                case 4:
                    fprintf(fp,"%3s    %4u  %4u  %4lu\r",
                           "X", psecheader[i].sh_link, psecheader[i].sh_info, psecheader[i].sh_addralign);
                    break;
                case 3:
                    fprintf(fp,"%3s    %4u  %4u  %4lu\r",
                           "WA", psecheader[i].sh_link, psecheader[i].sh_info, psecheader[i].sh_addralign);
                    break;
                case 5://WX
                    fprintf(fp,"%3s    %4u  %4u  %4lu\r",
                           "WX", psecheader[i].sh_link, psecheader[i].sh_info, psecheader[i].sh_addralign);
                    break;
                case 6://AX
                    fprintf(fp,"%3s    %4u  %4u  %4lu\r",
                           "AX", psecheader[i].sh_link, psecheader[i].sh_info, psecheader[i].sh_addralign);
                    break;
                case 7://WAX
                    fprintf(fp,"%3s    %4u  %4u  %4lu\r",
                           "WAX", psecheader[i].sh_link, psecheader[i].sh_info, psecheader[i].sh_addralign);
                    break;
                case SHF_MASKPROC://MS
                    fprintf(fp,"%3s    %4u  %4u  %4lu\r",
                           "MS", psecheader[i].sh_link, psecheader[i].sh_info, psecheader[i].sh_addralign);
                    break;
                default:
                    fprintf(fp,"NONE\r");
                    break;
            }

    }
    fprintf(fp,"Key to Flags:\r");
    fprintf(fp,"  W (write), A (alloc), X (execute), M (merge), S (strings), l (large)\r");
    fprintf(fp,"  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)\r");
    fprintf(fp,"  O (extra OS processing required) o (OS specific), p (processor specific)\r");
    printf("secheader 存储成功！"); 
}

//read File Header
void fileheader(const char *pbuff,FILE* fp)
{
    fprintf(fp,"ELF Header:\r");
    //Magic
    fprintf(fp,"  Magic:   ");
    for(int i = 0;i<EI_NIDENT;++i)
    {
        fprintf(fp,"%02X  ", pbuff[i]);
    }
    fprintf(fp,"\r");
    //Class
    fprintf(fp,"  %-33s:", "Class");
    switch(pbuff[4])
    {
        case 0:
            fprintf(fp," Invalid class\r");
            break;
        case 1:
            fprintf(fp," ELF32\r");
            break;
        case 2:
            fprintf(fp," ELF64\r");
            break;
        default:
            fprintf(fp," ERROR\r");
            break;
    }
    //Data
    fprintf(fp,"  %-33s:", "Data");
    switch(pbuff[5])
    {
        case 0:
            fprintf(fp," Invalid data encoding\r");
            break;
        case 1:
            fprintf(fp," 2's complement, little endian\r");
            break;
        case 2:
            fprintf(fp," 2's complement, big endian\r");
            break;
        default:
            fprintf(fp," ERROR\r");
            break;
    }
    //Version
    fprintf(fp,"  %-33s: %s\r", "Version", "1(current)");
    //OS/ABI
    fprintf(fp,"  %-33s: %s\r", "OS/ABI", "UNIX - System V");
    //ABI Version
    fprintf(fp,"  %-33s: %s\r", "ABI Version", "0");
    pbuff += EI_NIDENT;
    //Type
    fprintf(fp,"  %-33s:", "Type");
    switch(*(uint16_t*)pbuff)
    {
        case 0:
            fprintf(fp," No file type\r");
            break;
        case 1:
            fprintf(fp," Relocatable file\r");
            break;
        case 2:
            fprintf(fp," Executable file\r");
            break;
        case 3:
            fprintf(fp," Shared object file\r");
            break;
        case 4:
            fprintf(fp," Core file\r");
            break;
        default:
            fprintf(fp," ERROR\r");
            break;
    }
    pbuff += sizeof(uint16_t);
    //Machine
    fprintf(fp,"  %-33s:", "Machine");
    switch(*(uint16_t*)pbuff)
    {
        case EM_386:
            fprintf(fp," Intel 80386\r");
            break;
        case EM_ARM:
            fprintf(fp," ARM\r");
            break;
        case EM_X86_64:
            fprintf(fp," AMD X86-64 arrchitecture\r");
            break;
        default:
            fprintf(fp," ERROR\r");
            break;
    }
    pbuff += sizeof(uint16_t);
    //Version
    fprintf(fp,"  %-33s: %s\r", "version", "0X1");
    pbuff += sizeof(uint32_t);
    //Entry point address
    fprintf(fp,"  %-33s: 0X%lx\r", "Entry point address", *(uint64_t*)pbuff);
    pbuff += sizeof(uint32_t);                                                                        //1 
    //Start of program headers
    fprintf(fp,"  %-33s: %lu (bytes into file)\r", "Start of program headers", *(uint64_t*)pbuff);
    pbuff += sizeof(uint32_t);                                                                        //2 
    //Start of section headers
    fprintf(fp,"  %-33s: %lu (bytes into file)\r", "Start of section headers", *(uint64_t*)pbuff);
    pbuff += sizeof(uint32_t);                                                                        //3 
    //Flags
    fprintf(fp,"  %-33s: 0X0\r", "Flags");
    pbuff += sizeof(Elf32_Word);
    //Size of this header
    fprintf(fp,"  %-33s: %d (bytes)\r", "Size of this header", *(Elf32_Half*)pbuff);
    pbuff += sizeof(Elf32_Half);
    //Size of program headers
    fprintf(fp,"  %-33s: %d (bytes)\r", "Size of program headers", *(Elf32_Half*)pbuff);
    pbuff += sizeof(Elf32_Half);
    //Number of program headers
    fprintf(fp,"  %-33s: %d\r", "Number of program headers", *(Elf32_Half*)pbuff);
    pbuff += sizeof(Elf32_Half);
    //Size of section headers
    fprintf(fp,"  %-33s: %d (bytes)\r", "Size of section headers", *(Elf32_Half*)pbuff);
    pbuff += sizeof(Elf32_Half);
    //Number of section headers
    fprintf(fp,"  %-33s: %d\r", "Number of section headers", *(Elf32_Half*)pbuff);
    pbuff += sizeof(Elf32_Half);
    //Section header string table index
    fprintf(fp,"  %-33s: %d\r", "Section header string table index", *(Elf32_Half*)pbuff);
    printf("头文件信息存储成功！"); 
}
 

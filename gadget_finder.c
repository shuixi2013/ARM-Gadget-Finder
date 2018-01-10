//
//  gadget_finder.c
//  
//
//  Created by Billy Ellis on 26/10/2017.
//
//  This code scans ARM & ARM64 binaries for ROP gadgets useful to exploit developers


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define RESET   "\x1b[0m"

int filesize;
char *instruction;

//this function checks bytes to see if they match common ARM instruction encodings
//only some instruction encodings are stored here, feel free to add others :)
char * check_instruction_32(int c1, int c2, int c3, int c4){
    
    // check for 07 D0 A0 E1 / mov sp, r7
    if (c1 == 0x07 && c2 == 0xD0 && c3 == 0xA0 && c4 == 0xE1){
        return "mov sp, r7";
    }
    // check for 00 00 81 E5 / str r0, [r1]
    if (c1 == 0x00 && c2 == 0x00 && c3 == 0x81 && c4 == 0xE5){
        return "str r0, [r1]";
    }
    // check for 80 80 BD E8 / pop {r7, pc}
    if (c1 == 0x80 && c2 == 0x80 && c3 == 0xBD && c4 == 0xE8){
        return "pop {r7, pc}";
    }
    // check for 03 80 BD E8 / pop {r0, r1, pc}
    if (c1 == 0x03 && c2 == 0x80 && c3 == 0xBD && c4 == 0xE8){
        return "pop {r0, r1, pc}";
    }
    return "UNKNOWN INSTRUCTION";
}

char * check_instruction_64(int c1, int c2, int c3, int c4){
    
    // check for 07 D0 A0 E1 / mov sp, r7
    if (c1 == 0x07 && c2 == 0xD0 && c3 == 0xA0 && c4 == 0xE1){
        return "mov sp, r7";
    }
    return "UNKNOWN INSTRUCTION";
}

char * detect_exec_type(int one, int two, int three, int four){
    
    if (one == 0xCE && two == 0xFA && three == 0xED && four == 0xFE){
        // 32-bit Mach-O 0xFEEDFACE
        return "Mach-O 32-bit";
    }else if (one == 0xCF && two == 0xFA && three == 0xED && four == 0xFE){
        // 64-bit Mach-O 0xFEEDFACF
        return "Mach-O 64-bit";
    }else if (one == 0xBE && two == 0xBA && three == 0xFE && four == 0xCA){
        // FAT Mach-O 0xCAFEBABE
        return "Mach-O FAT";
    }
    
    return "unrecognised";
}

int get_size(char *filepath){
    
    struct stat st;
    stat(filepath, &st);
    
    return st.st_size;
}

void find_gadgets_32(unsigned char hex[filesize]){
    
    int i = 0;
    // search for 80 80 BD E8 / pop {r7, pc}
    // this is the common "return" instruction in the 32-bit ARM instruction set
    
    while (i < filesize){
        // if pop {r7, pc} is found...
        if (hex[i] == 0x80 && hex[i+1] == 0x80 && hex[i+2] == 0xBD && hex[i+3] == 0xE8){
            // search backwards 4 bytes for previous instruction
            instruction = check_instruction_32(hex[i-4],hex[i-3],hex[i-2],hex[i-1]);
            
            printf(CYAN"%s\n"RESET,instruction);
            // calculation of the address is very broken
            // the '16384' is a number I've found that works for ARM binaries compiled by me using clang
            // does not work for all binaries, need to figure this out
            printf(CYAN"pop {r7, pc}" RESET " found at address \x1B[32m0x%x\n\n\x1B[0m",(i+16384)-0x4);
        }
        i++;
    }
    
    //reset loop counter to 0
    i = 0;
    
    // search for 1E FF 2F E1  / bx lr
    // this is another "return" instruction in the 32-bit ARM instruction set
    
    while (i < filesize){
        if (hex[i] == 0x1E && hex[i+1] == 0xFF && hex[i+2] == 0x2F && hex[i+3] == 0xE1){
            // search backwards 4 bytes for previous instruction
            instruction = check_instruction_32(hex[i-4],hex[i-3],hex[i-2],hex[i-1]);
            
            printf(CYAN"%s\n"RESET,instruction);
            // calculation of the address is very broken
            // the '16384' is a number I've found that works for ARM binaries compiled by me using clang
            // does not work for all binaries, need to figure this out
            printf(CYAN"bx lr" RESET "        found at address \x1B[32m0x%x\n\n\x1B[0m",(i+16384)-0x4);
        }
        i++;
    }
}

void find_gadgets_64(unsigned char hex[filesize]){
    
    long long i = 0;
    
    // search for C0 03 5F D6 / ret
    
    while (i < filesize){
        // if pop {r7, pc} is found...
        if (hex[i] == 0xC0 && hex[i+1] == 0x03 && hex[i+2] == 0x5F && hex[i+3] == 0xD6){
            // search backwards 4 bytes for previous instruction
            instruction = check_instruction_32(hex[i-4],hex[i-3],hex[i-2],hex[i-1]);
            
            printf(CYAN"%s\n"RESET,instruction);
            // calculation of the address is very broken
            // the '16384' is a number I've found that works for ARM64 binaries compiled by me using clang
            // does not work for all binaries, need to figure this out
            printf(CYAN"ret" RESET " found at address \x1B[32m0x%llx\n\n\x1B[0m",(i+0x100000004)-0x4);
        }
        i++;
    }
}

int main(){
    
    char path[256];

    unsigned char c;
    int i = 0;
    char *exec_type;
    int arch = 0;
    
    system("clear");
    printf("=============================================\nWelcome to @bellis1000's ROP Gadget Finder!\n=============================================\nEnter path to ARM binary:\n");
    scanf("%s",path);
    
    filesize = get_size(path);
    
    unsigned char hex[filesize];
    
    FILE *f = fopen(path,"r");
   
    fread(&hex, 1, filesize, f);
    
    exec_type = detect_exec_type(hex[0],hex[1],hex[2],hex[3]);
    
    if (strcmp(exec_type,"Mach-O 64-bit") == 0){
        arch = 1;
    }
    
    printf(GREEN"\n%s executable detected\nwith filesize 0x%x\n\n"RESET,exec_type,filesize);
    printf("\nSearching binary for gadgets...\n\n"RESET);
    
    switch (arch){
        case 0:
            find_gadgets_32(hex);
            break;
        case 1:
            find_gadgets_64(hex);
            break;
        default:
            break;
    }

    
    return 0;
}

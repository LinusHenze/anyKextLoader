//
//  libinject.h
//  inj
//
//  Created by qwertyoruiop on 31/07/15.
//  Copyright (c) 2015 kim jong cracks. All rights reserved.
//

#ifndef __inj__libinject__
#define __inj__libinject__
#if defined(__OBJC)
#import <Foundation/Foundation.h>
#endif
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <sys/types.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <mach/i386/thread_state.h>
#include <mach-o/dyld_images.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <stdint.h>
typedef mach_port_t inject_t;
inject_t libinj_inject_pid (pid_t pid);
mach_port_t libinj_create_thread (inject_t inj, unsigned long* stack, void* initial_instr);
void* libinj_find_symbol(inject_t inj, char* name);
void libinj_find_regions(inject_t inj);
struct mach_header* libinj_main_header(inject_t inj);
vm_address_t libinj_exec(inject_t inj);
vm_address_t libinj_dy_linker(inject_t inj);
void* libinj_copyout(inject_t inj, void* data, size_t size);
void* libinj_map_mem(inject_t inj, size_t size, uint64_t* remote_map_virtaddr);
#endif /* defined(__inj__libinject__) */

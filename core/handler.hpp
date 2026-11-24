#pragma once

#include <functional>

#include "common.hpp"
#include "vm_utils.hpp"

namespace handlers 
{
	vm_inline bool handle_nop(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_mov(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_mov_imm(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_add(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_sub(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_mul(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_div(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_x86_div(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_load_mem(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_store_mem(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_mov_reg(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_and(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_or(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_xor(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_not(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_shl(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_shr(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_sar(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_call_native(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_store_mem8(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_store_mem_zero128(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_call_native_indirect(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_call_native_mem(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_cmpxchg_mem64(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_call_native_reg(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_xchg_mem64(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_jmp(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_jz(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_cmp(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_jnz(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_jl(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_jg(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_jle(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_jge(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_jb(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_jbe(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_jae(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_ja(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_push(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_pop(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_call(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_ret(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_cpuid(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_rdtsc(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_stosb(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_rep_stosb(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_loop(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_loope(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_loopne(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_halt(vm_state& vm, vm_flags& flags);
	vm_inline bool handle_invalid(vm_state& vm, vm_flags& flags);
};

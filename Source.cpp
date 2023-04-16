#define _CRT_SECURE_NO_WARNINGS

//FrameWorks and Libs
#include <z3++.h> 
#include <z3_api.h>
#include <boost/scoped_array.hpp>
#include <Zydis/Zydis.h>

//stl
#include <exception>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <list>
#include <string> 
#include <sstream> 
#include <vector>

typedef std::list<ZydisDisassembledInstruction_> instruction_optimize_list;

struct Struct_Of_Dissamble_Function {
	ZydisDisassembledInstruction instr;
	instruction_optimize_list optimized_instructions;
	int Counter;
};

struct x86_ctx {
	z3::expr* rax;
	z3::expr* al;
	z3::expr* rbx;
	z3::expr* bl;
	z3::expr* rcx;
	z3::expr* rdx;
	z3::expr* rbp;
	z3::expr* rsp;
	z3::expr* rsi;
	z3::expr* rdi;
	z3::expr* r8;
	z3::expr* r9;
	z3::expr* r10;
	z3::expr* r11;
	z3::expr* r12;
	z3::expr* r13;
	z3::expr* r14;
	z3::expr* r15;

	z3::expr* rflags;

	z3::expr* xmm0;
	z3::expr* xmm1;
	z3::expr* xmm2;
	z3::expr* xmm3;
	z3::expr* xmm4;
	z3::expr* xmm5;
	z3::expr* xmm6;
	z3::expr* xmm7;
	z3::expr* xmm8;
	z3::expr* xmm9;
	z3::expr* xmm10;
	z3::expr* xmm11;
	z3::expr* xmm12;
	z3::expr* xmm13;
	z3::expr* xmm14;
	z3::expr* xmm15;

	z3::expr* EShadowStackPTR;
	//void* ShadowStackPTR;
	//std::vector<z3::expr> ShadowStack;
	// 
	//void* ShadowStackPTR;
	//z3::array<z3::expr> ShadowStack;
	//z3::expr* memory;

	z3::expr* cf;
	z3::expr* of;
	z3::expr* zf;
	z3::expr* sf;

	std::list<z3::expr*> temp;

	x86_ctx()
		: rax(nullptr)
		, al(nullptr)
		, rbx(nullptr)
		, bl(nullptr)
		, rcx(nullptr)
		, rdx(nullptr)
		, rbp(nullptr)
		, rsp(nullptr)
		, rsi(nullptr)
		, rdi(nullptr)
		, r8(nullptr)
		, r9(nullptr)
		, r10(nullptr)
		, r11(nullptr)
		, r12(nullptr)
		, r13(nullptr)
		, r14(nullptr)
		, r15(nullptr)
		
		, rflags(nullptr)

		, xmm0(nullptr)
		, xmm1(nullptr)
		, xmm2(nullptr)
		, xmm3(nullptr)
		, xmm4(nullptr)
		, xmm5(nullptr)
		, xmm6(nullptr)
		, xmm7(nullptr)
		, xmm8(nullptr)
		, xmm9(nullptr)
		, xmm10(nullptr)
		, xmm11(nullptr)
		, xmm12(nullptr)
		, xmm13(nullptr)
		, xmm14(nullptr)
		, xmm15(nullptr)

		, EShadowStackPTR(nullptr)
		//, ShadowStackPTR(&ShadowStack)
		//, ShadowStackPTR(nullptr)
		//, memory(nullptr)

		, of(nullptr)
		, zf(nullptr)
		, sf(nullptr)
		, cf(nullptr)
	{}
};


//Prototypes
Struct_Of_Dissamble_Function  Dissamble(ZyanU64 runtime_address, ZyanUSize offset, std::vector<ZyanU8> data, const ZyanUSize length, Struct_Of_Dissamble_Function SODF);

void eleminate_dead_code(Struct_Of_Dissamble_Function& SODF, const ZyanUSize length);

void translate_instructions(z3::context& z3c, x86_ctx& state, Struct_Of_Dissamble_Function& SODF, instruction_optimize_list::iterator skip);

bool can_eliminate_instruction(Struct_Of_Dissamble_Function& SODF, instruction_optimize_list::iterator iter);

void create_initial_state(z3::context& z3c, x86_ctx& ctx);

void copy_changed_state(x86_ctx& old_state, x86_ctx& new_state);

void translate_instruction(z3::context& z3c, ZydisDisassembledInstruction_ ins, x86_ctx& state, Struct_Of_Dissamble_Function SODF);

void translate_mov(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins);

void translate_add(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins);

void translate_sub(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins);

void translate_push(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins);

void translate_pop(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins);

void translate_popfq(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins);

void translate_pushfq(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins);

z3::expr** get_val_expr(z3::context& z3c, x86_ctx& state, ZydisDecodedOperand op);
//Prototypes

int main()
{
	Struct_Of_Dissamble_Function SODF{};

	ZyanU64 runtime_address = 0x1000;

	std::vector<ZyanU8> data = {
		0xB0, 0x02,// MOV AL, 0x2
		0xB0, 0x01,// MOV AL, 0x1
		0xB3, 0x01,// MOV BL, 0x1
		0x00, 0xD8// ADD AL, BL
	};

	int Counter = 0;

	ZyanUSize offset = 0; const ZyanUSize length = data.size();

    SODF = Dissamble(runtime_address,offset,data,length,SODF);

	eleminate_dead_code(SODF,length);

	for (ZydisDisassembledInstruction_ ins : SODF.optimized_instructions)
	{
		std::cout << "After dead code elimination: " << ins.text << "\n";
	}

	return 0;
};

Struct_Of_Dissamble_Function Dissamble(ZyanU64 runtime_address, ZyanUSize offset, std::vector<ZyanU8> data, const ZyanUSize length, Struct_Of_Dissamble_Function SODF)
{
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, runtime_address, &data[0] + offset, length - offset,
		&SODF.instr)))
	{
		offset += SODF.instr.info.length;

		std::cout << "Disassembled: " << SODF.instr.text << "\n";

		SODF.optimized_instructions.push_back(SODF.instr);
	}

	std::cout << std::endl;

	return (SODF);
};

void eleminate_dead_code(Struct_Of_Dissamble_Function& SODF, const ZyanUSize length)
{
	bool eliminated; 

	do
	{
		eliminated = false;

		for (instruction_optimize_list::iterator iter = SODF.optimized_instructions.begin(); iter != SODF.optimized_instructions.end(); ++iter)
		{
			if (can_eliminate_instruction(SODF, iter) == true)
			{
				std::cout << "Removing: " << iter->text << std::endl;
				SODF.optimized_instructions.erase(iter);
				eliminated = true;
				break;
			}
			
		}
	} while (eliminated);
	std::cout << std::endl;
};

bool can_eliminate_instruction(Struct_Of_Dissamble_Function& SODF, instruction_optimize_list::iterator iter)
{
	x86_ctx		base;
	z3::context	c;

	create_initial_state(c, base);

	x86_ctx orig = base;
	x86_ctx opt = base;

	translate_instructions(c, orig, SODF, SODF.optimized_instructions.end());
	translate_instructions(c, opt, SODF, iter);

	z3::solver s(c);
	
	s.add(!(*orig.rax == *opt.rax && *orig.rbx == *opt.rbx && *orig.rcx == *opt.rcx && *orig.rdx == *opt.rdx && *orig.rsi == *opt.rsi && *orig.rdi == *opt.rdi && *orig.rbp == *opt.rbp));

	return (s.check() == z3::unsat);
}

void translate_instructions(z3::context& z3c, x86_ctx& state, Struct_Of_Dissamble_Function& SODF, instruction_optimize_list::iterator skip) 
{
	for (instruction_optimize_list::iterator iter = SODF.optimized_instructions.begin(); iter != SODF.optimized_instructions.end(); ++iter)
	{
		if (iter != skip)
		{
			translate_instruction(z3c, *iter, state, SODF);
		}
	}
};

void create_initial_state(z3::context& z3c, x86_ctx& ctx)
{
	ctx.rax = new z3::expr(z3c.bv_const("init_rax", 64));
	ctx.al = new z3::expr(z3c.bv_const("init_al", 8));
	ctx.rbx = new z3::expr(z3c.bv_const("init_rbx", 64));
	ctx.bl = new z3::expr(z3c.bv_const("init_bl", 8));
	ctx.rcx = new z3::expr(z3c.bv_const("init_rcx", 64));
	ctx.rdx = new z3::expr(z3c.bv_const("init_rdx", 64));
	ctx.rbp = new z3::expr(z3c.bv_const("init_rbp", 64));
	ctx.rsp = new z3::expr(z3c.bv_const("init_rsp", 64));
	ctx.rsi = new z3::expr(z3c.bv_const("init_rsi", 64));
	ctx.rdi = new z3::expr(z3c.bv_const("init_rdi", 64));
	ctx.r8 = new z3::expr(z3c.bv_const("init_r8", 64));
	ctx.r9 = new z3::expr(z3c.bv_const("init_r9", 64));
	ctx.r10 = new z3::expr(z3c.bv_const("init_r10", 64));
	ctx.r11 = new z3::expr(z3c.bv_const("init_r11", 64));
	ctx.r12 = new z3::expr(z3c.bv_const("init_r12", 64));
	ctx.r13 = new z3::expr(z3c.bv_const("init_r13", 64));
	ctx.r14 = new z3::expr(z3c.bv_const("init_r14", 64));
	ctx.r15 = new z3::expr(z3c.bv_const("init_r15", 64));

	ctx.rflags = new z3::expr(z3c.bv_const("init_rflags", 64));

	ctx.xmm0 = new z3::expr(z3c.bv_const("init_xmm0", 128));
	ctx.xmm1 = new z3::expr(z3c.bv_const("init_xmm1", 128));
	ctx.xmm2 = new z3::expr(z3c.bv_const("init_xmm2", 128));
	ctx.xmm3 = new z3::expr(z3c.bv_const("init_xmm3", 128));
	ctx.xmm4 = new z3::expr(z3c.bv_const("init_xmm4", 128));
	ctx.xmm5 = new z3::expr(z3c.bv_const("init_xmm5", 128));
	ctx.xmm6 = new z3::expr(z3c.bv_const("init_xmm6", 128));
	ctx.xmm7 = new z3::expr(z3c.bv_const("init_xmm7", 128));
	ctx.xmm8 = new z3::expr(z3c.bv_const("init_xmm8", 128));
	ctx.xmm9 = new z3::expr(z3c.bv_const("init_xmm9", 128));
	ctx.xmm10 = new z3::expr(z3c.bv_const("init_xmm10", 128));
	ctx.xmm11 = new z3::expr(z3c.bv_const("init_xmm11", 128));
	ctx.xmm12 = new z3::expr(z3c.bv_const("init_xmm12", 128));
	ctx.xmm13 = new z3::expr(z3c.bv_const("init_xmm13", 128));
	ctx.xmm14 = new z3::expr(z3c.bv_const("init_xmm14", 128));
	ctx.xmm15 = new z3::expr(z3c.bv_const("init_xmm15", 128));

	ctx.EShadowStackPTR = new z3::expr(z3c.bv_const("ShadowStack", 64));

	ctx.of = new z3::expr(z3c.bool_const("init_of"));
	ctx.zf = new z3::expr(z3c.bool_const("init_zf"));
	ctx.sf = new z3::expr(z3c.bool_const("init_sf"));
	ctx.cf = new z3::expr(z3c.bool_const("init_cf"));
}

#define check_and_copy(var_name) if (new_state.var_name) old_state.var_name = new_state.var_name;

void copy_changed_state(x86_ctx& old_state, x86_ctx& new_state)
{
	check_and_copy(rax);
	check_and_copy(al);
	check_and_copy(rbx);
	check_and_copy(bl);
	check_and_copy(rcx);
	check_and_copy(rdx);
	check_and_copy(rbp);
	check_and_copy(rsp);
	check_and_copy(rsi);
	check_and_copy(rdi);
	check_and_copy(r8);
	check_and_copy(r9);
	check_and_copy(r10);
	check_and_copy(r11);
	check_and_copy(r12);
	check_and_copy(r13);
	check_and_copy(r14);
	check_and_copy(r15);

	check_and_copy(rflags);

	check_and_copy(xmm0);
	check_and_copy(xmm1);
	check_and_copy(xmm2);
	check_and_copy(xmm3);
	check_and_copy(xmm4);
	check_and_copy(xmm5);
	check_and_copy(xmm6);
	check_and_copy(xmm7);
	check_and_copy(xmm8);
	check_and_copy(xmm9);
	check_and_copy(xmm10);
	check_and_copy(xmm12);
	check_and_copy(xmm13);
	check_and_copy(xmm14);
	check_and_copy(xmm15);

	check_and_copy(EShadowStackPTR);

	check_and_copy(of);
	check_and_copy(zf);
	check_and_copy(sf);
	check_and_copy(cf);
}

#undef check_and_copy

void translate_instruction(z3::context& z3c, ZydisDisassembledInstruction_ ins, x86_ctx& state, Struct_Of_Dissamble_Function SODF)
{
	x86_ctx new_state;

	if (ins.info.mnemonic == ZYDIS_MNEMONIC_MOV)
	{
		translate_mov(z3c, state, new_state, ins);
	}
	else if (ins.info.mnemonic == ZYDIS_MNEMONIC_ADD)
	{
		translate_add(z3c, state, new_state, ins);
	}
	else if (ins.info.mnemonic == ZYDIS_MNEMONIC_SUB)
	{
		translate_sub(z3c, state, new_state, ins);
	}
	else if (ins.info.mnemonic == ZYDIS_MNEMONIC_PUSH)
	{
		translate_push(z3c, state, new_state, ins);
	}
	else if (ins.info.mnemonic == ZYDIS_MNEMONIC_PUSHFQ)
	{
		translate_pushfq(z3c, state, new_state, ins);
	}
	else if (ins.info.mnemonic == ZYDIS_MNEMONIC_POP)
	{
		translate_pop(z3c, state, new_state, ins);
	}
	else
	{
		std::cout << "instruction not implemented";
	}
	copy_changed_state(state, new_state);
}

void translate_mov(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins)
{
	if (ins.info.operand_count == 2)
	{
		auto& op1 = ins.operands[0];
		auto& op2 = ins.operands[1];

		z3::expr e2 = **get_val_expr(z3c, old_state, op2);
		z3::expr** dst = get_val_expr(z3c, new_state, op1);

		*dst = new z3::expr(z3c, e2);
	}
	else
		throw std::exception("bad operand count");
}

void translate_add(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins)
{
	if (ins.info.operand_count == 3)
	{
		int a;
		auto& op1 = ins.operands[0];
		auto& op2 = ins.operands[1];

		z3::expr e1 = **get_val_expr(z3c, old_state, op1);
		z3::expr e2 = **get_val_expr(z3c, old_state, op2);
		z3::expr** dst = get_val_expr(z3c, new_state, op1);

		
		*dst = new z3::expr(z3c, e1 + e2);

		new_state.cf = &((e1 + e2) < e1);
		new_state.of = &(((e1 ^ e2) & 0x7FFFFFFF) == 0 && ((e1 ^ **dst) & 0x7FFFFFFF) != 0);
		new_state.zf = &(**dst == 0);
		new_state.sf = &(**dst < 0);
	}
	else
		throw std::exception("bad operand count");
}

void translate_sub(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins)
{
	if (ins.info.operand_count == 3)
	{
		auto& op1 = ins.operands[0];
		auto& op2 = ins.operands[1];

		z3::expr e1 = **get_val_expr(z3c, old_state, op1);
		z3::expr e2 = **get_val_expr(z3c, old_state, op2);
		z3::expr** dst = get_val_expr(z3c, new_state, op1);

		*dst = new z3::expr(z3c, e1 - e2);

		new_state.cf = &((e1 - e2) > e1);
		new_state.of = &(((e1 ^ e2) & 0x7FFFFFFF) != 0 && ((e1 ^ **dst) & 0x7FFFFFFF) != 0);
		new_state.zf = &(**dst == 0);
		new_state.sf = &(**dst < 0);
	}
	else
		throw std::exception("bad operand count");
}

void translate_xor(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins)
{
	if (ins.info.operand_count == 3)
	{
		auto& op1 = ins.operands[0];
		auto& op2 = ins.operands[1];

		z3::expr e1 = **get_val_expr(z3c, old_state, op1);
		z3::expr e2 = **get_val_expr(z3c, old_state, op2);
		z3::expr** dst = get_val_expr(z3c, new_state, op1);

		*dst = new z3::expr(z3c, e1 ^ e2);

		new_state.zf = new z3::expr(**dst == 0);
		new_state.sf = new z3::expr(**dst < 0);
	}
	else
		throw std::exception("bad operand count");
}

void translate_lea(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins)
{
	if (ins.info.operand_count == 3)
	{
		auto& op1 = ins.operands[0];
		auto& op2 = ins.operands[1];

		z3::expr e2 = **get_val_expr(z3c, old_state, op2);
		z3::expr** dst = get_val_expr(z3c, new_state, op1);

		*dst = new z3::expr(e2);
	}
	else
		throw std::exception("bad operand count");
}


void translate_push(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins)
{
	if (ins.info.operand_count_visible == 1)
	{
		auto& op1 = ins.operands[0]; auto& op2 = ins.operands[1];

		z3::expr e1 = **get_val_expr(z3c, old_state, op1);

		//new_state.rsp = &(*old_state.rsp - op1.size / 8);
		
		new_state.rsp = &(*old_state.rsp - 8);
		z3::expr** dst = get_val_expr(z3c, new_state, op2);

		*dst = new z3::expr(z3c, e1);
	}
	else
		throw std::exception("bad operand count");
}

void translate_pop(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins)
{
	if (ins.info.operand_count_visible == 1)
	{
		auto& op1 = ins.operands[0];

		z3::expr** dst = get_val_expr(z3c, new_state, op1);

		*dst = new z3::expr(z3c, *old_state.rsp);

		//new_state.rsp = &(*old_state.rsp + op1.size / 8);
		new_state.rsp = &(*old_state.rsp + 8);
	}
	else
		throw std::exception("bad operand count");
}

void translate_popfq(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins)
{
	if (ins.info.operand_count_visible == 0)
	{
		auto& op1 = ins.operands[0];

		z3::expr** dst = get_val_expr(z3c, new_state, op1);

		*dst = new z3::expr(z3c, *old_state.rflags);

		new_state.rsp = &(*old_state.rsp + 8);
	}
	else
		throw std::exception("bad operand count");
}


void translate_pushfq(z3::context& z3c, x86_ctx& old_state, x86_ctx& new_state, ZydisDisassembledInstruction_ ins)
{
	if (ins.info.operand_count_visible == 0)
	{
		auto& op1 = ins.operands[0];

		new_state.rsp = &(*old_state.rsp - 8);
		z3::expr** dst = get_val_expr(z3c, new_state, op1);

		*dst = new z3::expr(z3c, *old_state.rflags);
	}
	else
		throw std::exception("bad operand count");
}

z3::expr** get_val_expr(z3::context& z3c, x86_ctx& state, ZydisDecodedOperand op)
{
	if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
	{
		z3::expr** ret;

		switch (op.reg.value)
		{
		case ZYDIS_REGISTER_RAX: return ret = &state.rax;
		case ZYDIS_REGISTER_EAX: return ret = &state.rax;
		case ZYDIS_REGISTER_AX: return ret = &state.rax;
		case ZYDIS_REGISTER_AH: return ret = &state.rax;
		case ZYDIS_REGISTER_AL: return ret = &state.rax;

		case ZYDIS_REGISTER_RBX: return ret = &state.rbx;
		case ZYDIS_REGISTER_EBX: return ret = &state.rbx;
		case ZYDIS_REGISTER_BX: return ret = &state.rbx;
		case ZYDIS_REGISTER_BH: return ret = &state.rbx;
		case ZYDIS_REGISTER_BL: return ret = &state.rbx;

		case ZYDIS_REGISTER_RCX: return ret = &state.rcx;
		case ZYDIS_REGISTER_ECX: return ret = &state.rcx;
		case ZYDIS_REGISTER_CX: return ret = &state.rcx;
		case ZYDIS_REGISTER_CH: return ret = &state.rcx;
		case ZYDIS_REGISTER_CL: return ret = &state.rcx;

		case ZYDIS_REGISTER_RDX: return ret = &state.rdx;
		case ZYDIS_REGISTER_EDX: return ret = &state.rdx;
		case ZYDIS_REGISTER_DX: return ret = &state.rdx;
		case ZYDIS_REGISTER_DH: return ret = &state.rdx;
		case ZYDIS_REGISTER_DL: return ret = &state.rdx;

		case ZYDIS_REGISTER_RBP: return ret = &state.rbp;
		case ZYDIS_REGISTER_EBP: return ret = &state.rbp;
		case ZYDIS_REGISTER_BP: return ret = &state.rbp;
		case ZYDIS_REGISTER_BPL: return ret = &state.rbp;

		case ZYDIS_REGISTER_RSP: return ret = &state.rsp;
		case ZYDIS_REGISTER_ESP: return ret = &state.rsp;
		case ZYDIS_REGISTER_SP: return ret = &state.rsp;
		case ZYDIS_REGISTER_SPL: return ret = &state.rsp;

		case ZYDIS_REGISTER_RSI: return ret = &state.rsi;
		case ZYDIS_REGISTER_ESI: return ret = &state.rsi;
		case ZYDIS_REGISTER_SI: return ret = &state.rsi;
		case ZYDIS_REGISTER_SIL: return ret = &state.rsi;

		case ZYDIS_REGISTER_RDI: return ret = &state.rdi;
		case ZYDIS_REGISTER_EDI: return ret = &state.rdi;
		case ZYDIS_REGISTER_DI: return ret = &state.rdi;
		case ZYDIS_REGISTER_DIL: return ret = &state.rdi;

		case ZYDIS_REGISTER_R8: return ret = &state.r8;
		case ZYDIS_REGISTER_R8D: return ret = &state.r8;
		case ZYDIS_REGISTER_R8W: return ret = &state.r8;
		case ZYDIS_REGISTER_R8B: return ret = &state.r8;

		case ZYDIS_REGISTER_R9: return ret = &state.r9;
		case ZYDIS_REGISTER_R9D: return ret = &state.r9;
		case ZYDIS_REGISTER_R9W: return ret = &state.r9;
		case ZYDIS_REGISTER_R9B: return ret = &state.r9;

		case ZYDIS_REGISTER_R10: return ret = &state.r10;
		case ZYDIS_REGISTER_R10D: return ret = &state.r10;
		case ZYDIS_REGISTER_R10W: return ret = &state.r10;
		case ZYDIS_REGISTER_R10B: return ret = &state.r10;

		case ZYDIS_REGISTER_R11: return ret = &state.r11;
		case ZYDIS_REGISTER_R11D: return ret = &state.r11;
		case ZYDIS_REGISTER_R11W: return ret = &state.r11;
		case ZYDIS_REGISTER_R11B: return ret = &state.r11;

		case ZYDIS_REGISTER_R12: return ret = &state.r12;
		case ZYDIS_REGISTER_R12D: return ret = &state.r12;
		case ZYDIS_REGISTER_R12W: return ret = &state.r12;
		case ZYDIS_REGISTER_R12B: return ret = &state.r12;

		case ZYDIS_REGISTER_R13: return ret = &state.r13;
		case ZYDIS_REGISTER_R13D: return ret = &state.r13;
		case ZYDIS_REGISTER_R13W: return ret = &state.r13;
		case ZYDIS_REGISTER_R13B: return ret = &state.r13;

		case ZYDIS_REGISTER_R14: return ret = &state.r14;
		case ZYDIS_REGISTER_R14D: return ret = &state.r14;
		case ZYDIS_REGISTER_R14W: return ret = &state.r14;
		case ZYDIS_REGISTER_R14B: return ret = &state.r14;

		case ZYDIS_REGISTER_R15: return ret = &state.r15;
		case ZYDIS_REGISTER_R15D: return ret = &state.r15;
		case ZYDIS_REGISTER_R15W: return ret = &state.r15;
		case ZYDIS_REGISTER_R15B: return ret = &state.r15;

		default:
			throw std::exception("bad register");
		}
	}
	else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
	{
		state.temp.push_back(new z3::expr(z3c.bv_val(static_cast<uint64_t>(op.imm.value.u), 64)));

		return &state.temp.back();
	}
	else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
	{
		z3::expr** ret;

		switch (op.mem.base)
		{
		case ZYDIS_REGISTER_RAX: ret = &state.rax; break;
		case ZYDIS_REGISTER_EAX: ret = &state.rax; break;
		case ZYDIS_REGISTER_AX: ret = &state.rax; break;
		case ZYDIS_REGISTER_AH: ret = &state.rax; break;
		case ZYDIS_REGISTER_AL: ret = &state.rax; break;

		case ZYDIS_REGISTER_RBX: ret = &state.rbx; break;
		case ZYDIS_REGISTER_EBX: ret = &state.rbx; break;
		case ZYDIS_REGISTER_BX: ret = &state.rbx; break;
		case ZYDIS_REGISTER_BH: ret = &state.rbx; break;
		case ZYDIS_REGISTER_BL: ret = &state.rbx; break;

		case ZYDIS_REGISTER_RCX: ret = &state.rcx; break;
		case ZYDIS_REGISTER_ECX: ret = &state.rcx; break;
		case ZYDIS_REGISTER_CX: ret = &state.rcx; break;
		case ZYDIS_REGISTER_CH: ret = &state.rcx; break;
		case ZYDIS_REGISTER_CL: ret = &state.rcx; break;

		case ZYDIS_REGISTER_RDX: ret = &state.rdx; break;
		case ZYDIS_REGISTER_EDX: ret = &state.rdx; break;
		case ZYDIS_REGISTER_DX: ret = &state.rdx; break;
		case ZYDIS_REGISTER_DH: ret = &state.rdx; break;
		case ZYDIS_REGISTER_DL: ret = &state.rdx; break;

		case ZYDIS_REGISTER_RBP: ret = &state.rbp; break;
		case ZYDIS_REGISTER_EBP: ret = &state.rbp; break;
		case ZYDIS_REGISTER_BP: ret = &state.rbp; break;
		case ZYDIS_REGISTER_BPL: ret = &state.rbp; break;

		case ZYDIS_REGISTER_RSP: ret = &state.rsp; break;
		case ZYDIS_REGISTER_ESP: ret = &state.rsp; break;
		case ZYDIS_REGISTER_SP: ret = &state.rsp; break;
		case ZYDIS_REGISTER_SPL: ret = &state.rsp; break;

		case ZYDIS_REGISTER_RSI: ret = &state.rsi; break;
		case ZYDIS_REGISTER_ESI: ret = &state.rsi; break;
		case ZYDIS_REGISTER_SI: ret = &state.rsi; break;
		case ZYDIS_REGISTER_SIL: ret = &state.rsi; break;

		case ZYDIS_REGISTER_RDI: ret = &state.rdi; break;
		case ZYDIS_REGISTER_EDI: ret = &state.rdi; break;
		case ZYDIS_REGISTER_DI: ret = &state.rdi; break;
		case ZYDIS_REGISTER_DIL: ret = &state.rdi; break;

		case ZYDIS_REGISTER_R8: ret = &state.r8; break;
		case ZYDIS_REGISTER_R8D: ret = &state.r8; break;
		case ZYDIS_REGISTER_R8W: ret = &state.r8; break;
		case ZYDIS_REGISTER_R8B: ret = &state.r8; break;

		case ZYDIS_REGISTER_R9: ret = &state.r9; break;
		case ZYDIS_REGISTER_R9D: ret = &state.r9; break;
		case ZYDIS_REGISTER_R9W: ret = &state.r9; break;
		case ZYDIS_REGISTER_R9B: ret = &state.r9; break;

		case ZYDIS_REGISTER_R10: ret = &state.r10; break;
		case ZYDIS_REGISTER_R10D: ret = &state.r10; break;
		case ZYDIS_REGISTER_R10W: ret = &state.r10; break;
		case ZYDIS_REGISTER_R10B: ret = &state.r10; break;

		case ZYDIS_REGISTER_R11: ret = &state.r11; break;
		case ZYDIS_REGISTER_R11D: ret = &state.r11; break;
		case ZYDIS_REGISTER_R11W: ret = &state.r11; break;
		case ZYDIS_REGISTER_R11B: ret = &state.r11; break;

		case ZYDIS_REGISTER_R12: ret = &state.r12; break;
		case ZYDIS_REGISTER_R12D: ret = &state.r12; break;
		case ZYDIS_REGISTER_R12W: ret = &state.r12; break;
		case ZYDIS_REGISTER_R12B: ret = &state.r12; break;

		case ZYDIS_REGISTER_R13: ret = &state.r13; break;
		case ZYDIS_REGISTER_R13D: ret = &state.r13; break;
		case ZYDIS_REGISTER_R13W: ret = &state.r13; break;
		case ZYDIS_REGISTER_R13B: ret = &state.r13; break;

		case ZYDIS_REGISTER_R14: ret = &state.r14; break;
		case ZYDIS_REGISTER_R14D: ret = &state.r14; break;
		case ZYDIS_REGISTER_R14W: ret = &state.r14; break;
		case ZYDIS_REGISTER_R14B: ret = &state.r14; break;

		case ZYDIS_REGISTER_R15: ret = &state.r15; break;
		case ZYDIS_REGISTER_R15D: ret = &state.r15; break;
		case ZYDIS_REGISTER_R15W: ret = &state.r15; break;
		case ZYDIS_REGISTER_R15B: ret = &state.r15; break;

		default:
			throw std::exception("bad register");
		}

		if (ret)
		{
			z3::expr* base_expr = *ret;
			z3::expr* index_expr = nullptr;
			z3::expr* disp_expr = nullptr;

			if (op.mem.index != ZYDIS_REGISTER_NONE)
			{
				switch (op.mem.index)
				{
				case ZYDIS_REGISTER_RAX: index_expr = state.rax; break;
				case ZYDIS_REGISTER_EAX: index_expr = state.rax; break;
				case ZYDIS_REGISTER_AX: index_expr = state.rax; break;
				case ZYDIS_REGISTER_AH: index_expr = state.rax; break;
				case ZYDIS_REGISTER_AL: index_expr = state.rax; break;

				case ZYDIS_REGISTER_RBX: index_expr = state.rbx; break;
				case ZYDIS_REGISTER_EBX: index_expr = state.rbx; break;
				case ZYDIS_REGISTER_BX: index_expr = state.rbx; break;
				case ZYDIS_REGISTER_BH: index_expr = state.rbx; break;
				case ZYDIS_REGISTER_BL: index_expr = state.rbx; break;

				case ZYDIS_REGISTER_RCX: index_expr = state.rcx; break;
				case ZYDIS_REGISTER_ECX: index_expr = state.rcx; break;
				case ZYDIS_REGISTER_CX: index_expr = state.rcx; break;
				case ZYDIS_REGISTER_CH: index_expr = state.rcx; break;
				case ZYDIS_REGISTER_CL: index_expr = state.rcx; break;

				case ZYDIS_REGISTER_RDX: index_expr = state.rdx; break;
				case ZYDIS_REGISTER_EDX: index_expr = state.rdx; break;
				case ZYDIS_REGISTER_DX: index_expr = state.rdx; break;
				case ZYDIS_REGISTER_DH: index_expr = state.rdx; break;
				case ZYDIS_REGISTER_DL: index_expr = state.rdx; break;

				case ZYDIS_REGISTER_RBP: index_expr = state.rbp; break;
				case ZYDIS_REGISTER_EBP: index_expr = state.rbp; break;
				case ZYDIS_REGISTER_BP: index_expr = state.rbp; break;
				case ZYDIS_REGISTER_BPL: index_expr = state.rbp; break;

				case ZYDIS_REGISTER_RSP: index_expr = state.rsp; break;
				case ZYDIS_REGISTER_ESP: index_expr = state.rsp; break;
				case ZYDIS_REGISTER_SP: index_expr = state.rsp; break;
				case ZYDIS_REGISTER_SPL: index_expr = state.rsp; break;

				case ZYDIS_REGISTER_RSI: index_expr = state.rsi; break;
				case ZYDIS_REGISTER_ESI: index_expr = state.rsi; break;
				case ZYDIS_REGISTER_SI: index_expr = state.rsi; break;
				case ZYDIS_REGISTER_SIL: index_expr = state.rsi; break; 

				case ZYDIS_REGISTER_RDI: index_expr = state.rdi; break;
				case ZYDIS_REGISTER_EDI: index_expr = state.rdi; break;
				case ZYDIS_REGISTER_DI: index_expr = state.rdi; break;
				case ZYDIS_REGISTER_DIL: index_expr = state.rdi; break;

				case ZYDIS_REGISTER_R8: index_expr = state.r8; break;
				case ZYDIS_REGISTER_R8D: index_expr = state.r8; break;
				case ZYDIS_REGISTER_R8W: index_expr = state.r8; break;
				case ZYDIS_REGISTER_R8B: index_expr = state.r8; break;

				case ZYDIS_REGISTER_R9: index_expr = state.r9; break;
				case ZYDIS_REGISTER_R9D: index_expr = state.r9; break;
				case ZYDIS_REGISTER_R9W: index_expr = state.r9; break;
				case ZYDIS_REGISTER_R9B: index_expr = state.r9; break;

				case ZYDIS_REGISTER_R10: index_expr = state.r10; break;
				case ZYDIS_REGISTER_R10D: index_expr = state.r10; break;
				case ZYDIS_REGISTER_R10W: index_expr = state.r10; break;
				case ZYDIS_REGISTER_R10B: index_expr = state.r10; break;

				case ZYDIS_REGISTER_R11: index_expr = state.r11; break;
				case ZYDIS_REGISTER_R11D: index_expr = state.r11; break;
				case ZYDIS_REGISTER_R11W: index_expr = state.r11; break;
				case ZYDIS_REGISTER_R11B: index_expr = state.r11; break;

				case ZYDIS_REGISTER_R12: index_expr = state.r12; break;
				case ZYDIS_REGISTER_R12D: index_expr = state.r12; break;
				case ZYDIS_REGISTER_R12W: index_expr = state.r12; break;
				case ZYDIS_REGISTER_R12B: index_expr = state.r12; break;

				case ZYDIS_REGISTER_R13: index_expr = state.r13; break;
				case ZYDIS_REGISTER_R13D: index_expr = state.r13; break;
				case ZYDIS_REGISTER_R13W: index_expr = state.r13; break;
				case ZYDIS_REGISTER_R13B: index_expr = state.r13; break;

				case ZYDIS_REGISTER_R14: index_expr = state.r14; break;
				case ZYDIS_REGISTER_R14D: index_expr = state.r14; break;
				case ZYDIS_REGISTER_R14W: index_expr = state.r14; break;
				case ZYDIS_REGISTER_R14B: index_expr = state.r14; break;

				case ZYDIS_REGISTER_R15: index_expr = state.r15; break;
				case ZYDIS_REGISTER_R15D: index_expr = state.r15; break;
				case ZYDIS_REGISTER_R15W: index_expr = state.r15; break;
				case ZYDIS_REGISTER_R15B: index_expr = state.r15; break;

				default:
					throw std::exception("bad register");
				}
			}

			if (op.mem.disp.has_displacement)
			{
				disp_expr = new z3::expr(z3c.bv_val(static_cast<uint64_t>(op.mem.disp.value), 64));
			}

			if (index_expr)
			{
				base_expr = *ret + *index_expr;
			}

			if (disp_expr)
			{

				base_expr += *disp_expr;
			}

			state.temp.push_back(base_expr);

			return &state.temp.back();
		}
		else
			throw std::exception("bad state");
	}
	else
		throw std::exception("bad operand type");
}

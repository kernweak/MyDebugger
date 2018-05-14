#include "stdafx.h"
#include"initSomeThing.h"
BOOL g_isUserTf = TRUE;
vector<BPNODE> g_HardBp = {};
vector<CCBPINFO> g_VecCCBp = {};
vector<CCBTPINFO> g_VecCONBp = {};
int g_eip = 0;
TheBeaClass::TheBeaClass()
{
}


TheBeaClass::~TheBeaClass()
{
}

void TheBeaClass::UseBea(char*opcode, DISASM disAsm)
{
	UInt32  nOpcodeSize = 0x64;
	int nCount = 0; // 用于记录在循环当中，反汇编了多少个字节
	int nLen = 0; // 用于记录当前的汇编指令的字节数

				  // 调用Disasm（）进行反汇编， 
	while (nCount < nOpcodeSize - 16)
	{
		nLen = Disasm(&disAsm); // 每次只反汇编一条汇编指令， 并且返回当前得到的汇编指令的长度
		if (nLen == -1)
		{
			return;
		}

		printf("\t%08X  ", disAsm.VirtualAddr);
	//	int temlen = nLen;
	//	disAsm.EIP
	//	while (temlen>=0) {
	//		disAsm.EIP
	//		printf("%X", disAsm.Instruction.Opcode);
	//		temlen -= 1;
	//	}
	//	//printf("%08X  ", disAsm.Instruction.Opcode);
		printf("%s", disAsm.CompleteInstr);
		printf("\n");
		//printOpcode((const unsigned char*)disAsm.EIP, nLen); // 打印opcode

		nCount += nLen; // 累加已经反汇编的字节数
		disAsm.EIP += nLen; // 定位到下一条汇编指令
		disAsm.VirtualAddr += nLen; // 设置到下一条汇编指令的地址
	}

}

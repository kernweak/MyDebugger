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
	int nCount = 0; // ���ڼ�¼��ѭ�����У�������˶��ٸ��ֽ�
	int nLen = 0; // ���ڼ�¼��ǰ�Ļ��ָ����ֽ���

				  // ����Disasm�������з���࣬ 
	while (nCount < nOpcodeSize - 16)
	{
		nLen = Disasm(&disAsm); // ÿ��ֻ�����һ�����ָ� ���ҷ��ص�ǰ�õ��Ļ��ָ��ĳ���
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
		//printOpcode((const unsigned char*)disAsm.EIP, nLen); // ��ӡopcode

		nCount += nLen; // �ۼ��Ѿ��������ֽ���
		disAsm.EIP += nLen; // ��λ����һ�����ָ��
		disAsm.VirtualAddr += nLen; // ���õ���һ�����ָ��ĵ�ַ
	}

}

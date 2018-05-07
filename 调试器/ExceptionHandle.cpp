#include "stdafx.h"
#include "ExceptionHandle.h"


CExceptionHandle::CExceptionHandle()
{
}
//����������Ĺ��캯��
CExceptionHandle::CExceptionHandle(DEBUG_EVENT dbgEvent)
:m_dbgEvent(dbgEvent)
{
}


CExceptionHandle::~CExceptionHandle()
{
}

//************************************
// Method:    OnException
// FullName:  CExceptionHandle::OnException
// Description:�����쳣����
// Access:    public 
// Returns:   DWORD
// Qualifier:
// Parameter: DEBUG_EVENT & dbgEvent
// Date: 2018/5/7 10:35
// Author : RuiQiYang
//************************************
DWORD CExceptionHandle::OnException(DEBUG_EVENT & dbgEvent)
{
	m_dbgEvent = dbgEvent;
	GetThreadContext(m_ProInfo.hThread, &TheContext);


	EXCEPTION_RECORD& er = m_dbgEvent.u.Exception.ExceptionRecord;

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		m_dbgEvent.dwProcessId);

	HANDLE hThrad = OpenThread(THREAD_ALL_ACCESS,
		FALSE,
		m_dbgEvent.dwThreadId);
	//�쳣�¼�����ϵͳ�ϵ�
	printf("\t�쳣���룺%08X\n", er.ExceptionCode);
	printf("\t�쳣��ַ��%08X\n", er.ExceptionAddress);

	switch (m_dbgEvent.u.Exception.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT://�����ϵ�ʱ�������쳣��
							  //  �Ƿ��������ϵ�         ��ʱ�ϵ�(F8 ����)
		ResetDelAllPoint();;//�������жϵ�
		Print((SIZE_T)m_dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);//��ӡ�����
		TheContext.Eip--;
		SetThreadContext(m_ProInfo.hThread, &TheContext);
		//�ȴ��û�����  
		//  ִ�г��� �������F7   F5  ��F8        
		//      �û�����F7  ����TF ��־λ  ���жϵ㲻��Ҫ�ָ� 
		//      �û����� F5 ���жϵ�Ҳ����Ҫ�ָ�
		WaitUserInput();
		break;
		break;
	case EXCEPTION_ACCESS_VIOLATION://�ڴ�����쳣
		break;
	case EXCEPTION_SINGLE_STEP:
		break;
	default:

		break;
	}

	CloseHandle(hThrad);
	CloseHandle(hProc);
	if (flag == FALSE) {
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	else {
		return DBG_CONTINUE;
	}
	return 0;
}

//************************************
// Method:    getDbgEvent
// FullName:  CExceptionHandle::getDbgEvent
// Description:���봦������¼�
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: DEBUG_EVENT dbgEvent
// Date: 2018/5/7 10:40
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::getDbgEvent(DEBUG_EVENT dbgEvent)
{
	m_dbgEvent = dbgEvent;
	return TRUE;
}

//************************************
// Method:    getProcessInfo
// FullName:  CExceptionHandle::getProcessInfo
// Description:�����Խ�����Ϣ���ݸ��쳣��
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: PROCESS_INFORMATION mProInfo
// Date: 2018/5/7 14:08
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::getProcessInfo(PROCESS_INFORMATION mProInfo)
{
	m_ProInfo = mProInfo;
	return TRUE;
}

//************************************
// Method:    ResetDelAllPoint
// FullName:  CExceptionHandle::ResetDelAllPoint
// Description:����ɾ�����жϵ�
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Date: 2018/5/7 14:33
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::ResetDelAllPoint()
{
	BYTE Int3 = 0xcc;
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;
	for (auto i : g_VecCCBp) {
		oldbyte = i.OldCode;
		VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)i.dwAddress, 1, PAGE_READWRITE, &oldProtect);
		if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)i.dwAddress, &oldbyte, 1, &len)) return FALSE;
		VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)i.dwAddress, 1, oldProtect, &oldProtect);
	}
	return TRUE;
}

//************************************
// Method:    ResetSetAllPoint
// FullName:  CExceptionHandle::ResetSetAllPoint
// Description:���¼������жϵ�
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Date: 2018/5/7 17:56
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::ResetSetAllPoint()
{
	BYTE Int3 = 0xcc;
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;
	for (auto i : g_VecCCBp)
	{

		oldbyte = i.OldCode;
		VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)i.dwAddress, 1, PAGE_READWRITE, &oldProtect);
		if (!ReadProcessMemory(m_ProInfo.hProcess, (LPVOID)i.dwAddress, &oldbyte, 1, &len)) return FALSE;
		if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)i.dwAddress, &Int3, 1, &len)) return FALSE;
		VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)i.dwAddress, 1, oldProtect, &oldProtect);
	}
	return TRUE;
}

//************************************
// Method:    Print
// FullName:  CExceptionHandle::Print
// Description:��ӡ�����
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: SIZE_T dwAddress
// Date: 2018/5/7 15:02
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::Print(SIZE_T dwAddress)
{
	char buf[0x66];
	DWORD numsize=0;
	DISASM disAsm = {};
	disAsm.EIP = (UIntPtr)buf;// ����opcode�Ļ������׵�ַ
	disAsm.VirtualAddr = dwAddress; // opcode ָ��ĵ�ַ
	disAsm.Archi = 0; // 0 => 32 , 1 => 64
	disAsm.Options = 0x000; // masm ���ָ���ʽ
	ReadProcessMemory(m_ProInfo.hProcess, (char*)dwAddress, buf, 0x64, &numsize);
	m_BEA.UseBea(buf, disAsm);
	return 0;
}

//************************************
// Method:    WaitUserInput
// FullName:  CExceptionHandle::WaitUserInput
// Description:�ȴ��û�����
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Date: 2018/5/7 15:39
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::WaitUserInput()
{
	while (1)
	{
		CMyDebuggerFramWork temFramWork;
		temFramWork.m_ProInfo = m_ProInfo;
		char buffer[20] = {};
		char *CmdBuf = nullptr;
		char *NumBuf = nullptr;
		DWORD addr = 0;
		printf("�����룺");
		gets_s(buffer, 20);
		CmdBuf = strtok_s(buffer, " ", &NumBuf);
		sscanf_s(NumBuf, "%x", &addr);
		//����
		if (strcmp("t", CmdBuf) == 0)//DOF7
		{
			ResetDelAllPoint();
			PEFLAGS  eflag = (PEFLAGS)&TheContext.EFlags;
			eflag->TF = 1;
			SetThreadContext(m_ProInfo.hThread, &TheContext);
			//��� ִ�е��� ����cc �ϵ�   
			//��� ִ�е��� ���� �ڴ�ϵ�
			//��� ִ�е��� ���� Ӳ���ϵ�
			return 0;
		}

		//���öϵ�
		if (strcmp("bp", CmdBuf) == 0)
		{
			temFramWork.SetCcPoint(addr, 0);
		}

		if (strcmp("g", CmdBuf) == 0)
		{
			ResetSetAllPoint();
			//�����ǰEIP �ڶϵ��б�����ԭԭ���Ĵ��� �ó���������
			temFramWork.ResetDelCcPoint(TheContext.Eip);
			////�ж� ����ôͣ������
			//// ������������    eip==�쳣��ַ
			////�ϵ�������       eip==�쳣��ַ-1
			//if ((DWORD)mDebEv.u.Exception.ExceptionRecord.ExceptionAddress == TheContext.Eip)
			//	return 0;

			//�������жϵ�
			//����
			return 0;
		}
		if (strcmp("u", CmdBuf) == 0)//�鿴�����
		{
			Print(addr);
		}
		if (strcmp("h", CmdBuf) == 0|| strcmp("help", CmdBuf) == 0)//�鿴�����ĵ�
		{
			PrintCommandHelp(0);
		}
		if (strcmp("r", CmdBuf) == 0)//�鿴���޸ļĴ���
		{
			if (2 == GetParamCount(buffer))
			{
				//EditRegisterValue(buffer);
			}
			PrintContext();
		}

	}
	return 0;
}

//************************************
// Method:    PrintCommandHelp
// FullName:  CExceptionHandle::PrintCommandHelp
// Description:�鿴����
// Access:    public 
// Returns:   void
// Qualifier:
// Date: 2018/5/7 19:31
// Author : RuiQiYang
//************************************
void CExceptionHandle::PrintCommandHelp(char ch)
{
	if ('b' == ch || 0 == ch)
	{
		printf("ba (���һ��Ӳ���ϵ�)            �ϵ��ַ ���� Ȩ��\r\n");
		printf("bp (int3�ϵ�)                    �ϵ��ַ\r\n");
		printf("bl (��ʾ���жϵ���Ϣ)\r\n");
		printf("bc (�������int3��Ӳ���ϵ���Ϣ)\r\n");
		printf("be (����һ���ϵ�)                �ϵ��ַ\r\n");
		printf("bd (����һ���ϵ�)                �ϵ��ַ\r\n");
		printf("br (�Ƴ�һ��int3�ϵ��Ӳ���ϵ�)  �ϵ��ַ\r\n");
		printf("bm (���һ���ڴ�ϵ�)            �ϵ��ַ ���� Ȩ��\r\n");
		printf("by (�Ƴ�һ���ڴ�ϵ�)            �ϵ��ַ\r\n");
	}

	if (0 == ch)
	{
		printf("t                                ��������\r\n");
		printf("p                                ��������\r\n");
		printf("r                                �鿴�޸ļĴ���\r\n");
		printf("u [Ŀ���ַ]                     �����\r\n");
		printf("? ��  h                          �鿴����\r\n");
		printf("g [Ŀ���ַ]                     ִ�е�Ŀ���ַ��\r\n");
		printf("\t�������ָ����ַ���м�Ķϵ㽫ȫ��ʧЧ\r\n");
		printf("l                                ��ʾPE��Ϣ\r\n");
		printf("d [Ŀ����ʼ��ַ] [Ŀ����ַ��ַ]/[����] �鿴�ڴ�\r\n");
		printf("e [Ŀ����ʼ��ַ]                 �޸��ڴ�\r\n");
		printf("q                                �˳�\r\n");
		printf("s ��¼��Χ��ʼ��ַ ��¼��Χ��ֹ��ַ [�����ļ���]\r\n");
		printf("o [�ű�·����]                   ���нű�\r\n");

		printf("��չ����:\r\n");
		printf(".kill                            ���������Խ���\r\n");
		printf(".restart                         ���¼��ر����Խ���(����)\r\n");
		printf(".show                            ��ʾ�Ѽ���ģ��\r\n");
	}
	printf("\r\n");
	return;
}

//************************************
// Method:    PrintContext
// FullName:  CExceptionHandle::PrintContext
// Description:��ӡ��������Ϣ
// Access:    public 
// Returns:   void
// Qualifier:
// Date: 2018/5/7 21:19
// Author : RuiQiYang
//************************************
void CExceptionHandle::PrintContext()
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

	if (FALSE == GetCurrentThreadContext(&context))
	{
		return;
	}

	printf("EAX=%p  ", context.Eax);
	printf("EBX=%p  ", context.Ebx);
	printf("ECX=%p  ", context.Ecx);
	printf("EDX=%p\r\n", context.Edx);

	printf("ESI=%p  ", context.Esi);
	printf("EDI=%p  ", context.Edi);

	printf("ESP=%p  ", context.Esp);
	printf("EBP=%p\r\n", context.Ebp);


	printf("EIP=%p  ", context.Eip);
	printf("iopl=%2d  ", context.EFlags & 0x3000);

	printf("    %3s", (context.EFlags & 0x800) ? "ov" : "nv");
	printf("%3s", (context.EFlags & 0x400) ? "dn" : "up");
	printf("%3s", (context.EFlags & 0x200) ? "ei" : "di");
	printf("%3s", (context.EFlags & 0x80) ? "ng" : "pl");
	printf("%3s", (context.EFlags & 0x40) ? "zr" : "nz");
	printf("%3s", (context.EFlags & 0x10) ? "ac" : "nc");
	printf("%3s", (context.EFlags & 0x4) ? "pe" : "po");
	printf("%3s\r\n", (context.EFlags & 0x1) ? "cy" : "nc");
	//cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000
	printf("cs=%04X  ss=%04X  ds=%04X  es=%04X  fs=%04X  gs=%04X\r\n",
		context.SegCs, context.SegSs, context.SegDs, context.SegEs,
		context.SegFs, context.SegGs);
}

//************************************
// Method:    GetCurrentThreadContext
// FullName:  CExceptionHandle::GetCurrentThreadContext
// Description:��ȡ��ǰ�߳�������
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: OUT CONTEXT * pContext
// Date: 2018/5/7 21:28
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::GetCurrentThreadContext(OUT CONTEXT * pContext)
{
	if (NULL == pContext)
	{
		OutputDebugString(L"Context����ָ��Ϊ��!\r\n");
		return FALSE;
	}

	if (0 == m_dbgEvent.dwThreadId)
	{
		OutputDebugString(L"�߳�id��Ч\r\n");
		return FALSE;
	}

	m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dbgEvent.dwThreadId);

	if (NULL == m_hThread)
	{
		return FALSE;
	}

	if (FALSE == GetThreadContext(m_hThread, pContext))
	{
		CloseHandle(m_hThread);
		m_hThread = NULL;
		return FALSE;
	}

	CloseHandle(m_hThread);
	m_hThread = NULL;
	return TRUE;
}

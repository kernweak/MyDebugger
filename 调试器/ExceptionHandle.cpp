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
// Method:    ShowMemoryData
// FullName:  CExceptionHandle::ShowMemoryData
// Description:��ӡ�ڴ���Ϣ
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: SIZE_T dwAddress
// Date: 2018/5/8 18:13
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::ShowMemoryData(char* pszCmd)
{
	if (NULL == pszCmd)
	{
		OutputDebugString(L"����ָ��Ϊ��!\r\n");
		return 0;
	}

	int nParamCount = GetParamCount(pszCmd);
	LPVOID dwEip = 0;
	int nLen = 0x80;

	if (1 == nParamCount)
	{
		dwEip = (LPVOID)GetCurrentEip(m_dbgEvent.dwThreadId);
	}

	else if (2 == nParamCount)
	{
		sscanf_s(pszCmd, "%s%x", stderr,100, &dwEip);
	}

	else if (3 == nParamCount)
	{
		sscanf_s(pszCmd, "%s%x%x", stderr,100, &dwEip, &nLen);
	}

	DisplayDestProcessMemory(dwEip, nLen);
	return TRUE;
}

//************************************
// Method:    EditMemoryData
// FullName:  CExceptionHandle::EditMemoryData
// Description:�޸��ڴ���Ϣ
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Date: 2018/5/8 20:51
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::EditMemoryData()
{
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;
	printf("������Ҫ�޸ĵĵ�ַ��");
	DWORD dwAddress = 0;
	scanf_s("%X", &dwAddress);
	char bData[1024] = { 0 };
	SIZE_T write = 0;
	printf("������Ҫ���ݣ�");
	scanf_s("%s", bData, 1024);
	int tem = strlen(bData);
	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, tem+1, PAGE_READWRITE, &oldProtect);
	// ������д���ڴ�
	if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)dwAddress, &bData, tem, &write))
	{
		printf("д���ڴ�ʧ��");
		VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, tem + 1, oldProtect, &oldProtect);
		return FALSE;
	}
	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, tem + 1, oldProtect, &oldProtect);
	return TRUE;

}

//************************************
// Method:    DisplayDestProcessMemory
// FullName:  CExceptionHandle::DisplayDestProcessMemory
// Description:��ʾ���Խ���Ŀ���ڴ�����
// Access:    public 
// Returns:   int
// Qualifier:
// Parameter: LPVOID pAddr
// Parameter: int nLen
// Date: 2018/5/8 18:37
// Author : RuiQiYang
//************************************
int CExceptionHandle::DisplayDestProcessMemory(LPVOID pAddr, int nLen)
{
	int nPageID = 0;
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	// �жϵ�ַ�Ƿ����
	if (0 == IsEffectiveAddress(pAddr, &mbi))
	{
		OutputDebugString(L"�ڴ��ַ��Ч!\r\n");
		return 0;
	}

	char *pBuf = new char[nLen + sizeof(char)];
	//memset(pBuf, 0, nLen + sizeof(char));

	if (NULL == pBuf)
	{
		OutputDebugString(L"�����ڴ�ʧЧ!\r\n");
		return 0;
	}

	if (nLen <= 0)
	{
		OutputDebugString(L"���ȳ���!\r\n");
		return 0;
	}

	if (nLen > (int)pAddr)
	{
		nLen -= (int)pAddr;
		++nLen;
	}

	DWORD dwProtect = 0;

	// ��ֹ�����ڴ�ϵ㣬Ŀ���ڴ�ҳû�ж������ԣ��Ƚ��������Լ���ȥ
	if (FALSE == VirtualProtectEx(m_ProInfo.hProcess, pAddr, BUFFER_MAX,
		PAGE_EXECUTE_READWRITE, &dwProtect))
	{
		OutputDebugString(L"DisplayDestProcessMemory VirtualProtectEx����!\r\n");
		return 0;

	}

	DWORD dwNothing = 0;

	if (FALSE == ReadProcessMemory(m_ProInfo.hProcess, pAddr, pBuf,
		sizeof(char)*nLen, &dwNothing))
	{
		OutputDebugString(L"��Ŀ����̳���!\r\n");
		return 0;
	}
	// �����Ի�ԭ
	VirtualProtectEx(m_ProInfo.hProcess, pAddr, BUFFER_MAX,
		dwProtect, &dwProtect);
	int nCount = 0;
	for (int i = nCount; i < nLen;)
	{
		// ���ǰ��ĵ�ַ
		if (0 == (i & 0xf))
		{
			printf("%p  ", pAddr);
			pAddr = (LPVOID)((DWORD)pAddr + 0x10);
		}

		// �������16����
		int nIndex(0);
		for (; nIndex < 0x10 && i < nLen; ++i, ++nIndex)
		{
			if (0 == (i % 8) && 0 != (i & 0xf))
			{
				printf("- ");
			}
			printf("%02X ", (BYTE)(pBuf[i]));
		}

		if (nIndex <= 8)
		{
			printf("  ");
		}

		// �������0x10���Ļ�������
		for (int k = 0x10 - nIndex; k >= 0; --k)
		{
			printf("   ");
		}

		for (; nCount < i; ++nCount)
		{
			byte ch = (byte)pBuf[nCount];

			// isgraph �Ƿ��ǿ���ʾ�ַ�
			if (isgraph(ch))
				printf("%c", ch);
			else
				printf(".");
			//printf("%c", (isgraph(ch)) ? ch : '.');
		}
		printf("\r\n");
	}

	if (NULL != pBuf)
	{
		delete[] pBuf;
		pBuf = NULL;
	}

	return 1;
}

//************************************
// Method:    IsEffectiveAddress
// FullName:  CExceptionHandle::IsEffectiveAddress
// Description:�ж��Ƿ�����Ч��ַ//ͨ����С�����ж�
// Access:    public 
// Returns:   int
// Qualifier:
// Parameter: IN LPVOID lpAddr
// Parameter: IN PMEMORY_BASIC_INFORMATION pMbi
// Date: 2018/5/8 18:35
// Author : RuiQiYang
//************************************
int CExceptionHandle::IsEffectiveAddress(IN LPVOID lpAddr, IN PMEMORY_BASIC_INFORMATION pMbi)
{
	if (NULL == pMbi)
	{
		return 0;
	}
	if (sizeof(MEMORY_BASIC_INFORMATION)
		!= VirtualQueryEx(m_ProInfo.hProcess, lpAddr, pMbi,
			sizeof(MEMORY_BASIC_INFORMATION)))
	{
		return 0;
	}

	if (MEM_COMMIT == pMbi->State)
	{
		return 1;
	}
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
		fflush(stdin);
		CMyDebuggerFramWork temFramWork;
		temFramWork.m_ProInfo = m_ProInfo;
		char buffer[20] = {};
		char *CmdBuf = nullptr;
		char *NumBuf = nullptr;
		
		DWORD addr = 0;
		printf("�����룺");
		gets_s(buffer, 20);
		//printf("�����bufferΪ��%s\n", buffer);
		char buffer1[20] = {};
		memcpy(buffer1, buffer, sizeof(buffer));
		char* tempBuf = buffer;
		CmdBuf = strtok_s(buffer, " ", &NumBuf);
		sscanf_s(NumBuf, "%x", &addr);
		//����
		if(CmdBuf==NULL)continue;
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
		if (strcmp("d", CmdBuf) == 0)//�鿴�ڴ�
		{
			ShowMemoryData(buffer1);
		}

		if (strcmp("editasm", CmdBuf) == 0)//�޸Ļ��
		{
			Editasm(addr);
		}
		if (strcmp("e", CmdBuf) == 0)//�޸��ڴ�
		{
			EditMemoryData();
		}
		if (strcmp(".show", CmdBuf) == 0)//�鿴ջ��Ϣ
		{
			ShowMod();
		}
		if (strcmp("stack", CmdBuf) == 0)//�鿴ջ��Ϣ
		{
			PrintStack();
		}
		if (strcmp("h", CmdBuf) == 0|| strcmp("help", CmdBuf) == 0)//�鿴�����ĵ�
		{
			PrintCommandHelp(0);
		}
		if (strcmp("r", CmdBuf) == 0)//�鿴���޸ļĴ���
		{
			if (2 == GetParamCount(buffer1))
			{
				EditRegisterValue(buffer1);
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
		printf("editasm [Ŀ���ַ]               �޸Ļ�����\r\n");
		printf("? ��  h                          �鿴����\r\n");
		printf("g [Ŀ���ַ]                     ִ�е�Ŀ���ַ��\r\n");
		printf("stack                            �鿴ջ��Ϣ\r\n");
		printf("\t�������ָ����ַ���м�Ķϵ㽫ȫ��ʧЧ\r\n");
		printf("l                                ��ʾPE��Ϣ\r\n");
		printf("d [Ŀ����ʼ��ַ] [Ŀ����ַ��ַ]/[����] �鿴�ڴ�\r\n");
		printf("e                                �޸��ڴ�\r\n");
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
// Method:    PrintStack
// FullName:  CExceptionHandle::PrintStack
// Description:�鿴ջ��Ϣ
// Access:    public 
// Returns:   void
// Qualifier:
// Date: 2018/5/8 10:49
// Author : RuiQiYang
//************************************
void CExceptionHandle::PrintStack()
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

	if (FALSE == GetCurrentThreadContext(&context))
	{
		return;
	}
	DWORD buff[5];
	SIZE_T read = 0;
	if (!ReadProcessMemory(m_ProInfo.hProcess, (LPVOID)context.Esp, buff, 20, &read)) {
		DBGPRINT("��ȡ�����ڴ�ʧ��");
	}
	for (int i = 0;i < 5;++i) {
		printf("\t%08X|%08X\n", context.Esp + i * 4,buff[i]);
	}
	printf("EAX=%p  \n", context.Esp);
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
BOOL CExceptionHandle::GetCurrentThreadContext(CONTEXT * pContext)
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

//************************************
// Method:    SetCurrentThreadContext
// FullName:  CExceptionHandle::SetCurrentThreadContext
// Description:���õ�ǰ�߳�������
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: IN CONTEXT * pContext
// Date: 2018/5/8 9:03
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::SetCurrentThreadContext(CONTEXT * pContext)
{

	if (NULL == pContext)
	{
		return FALSE;
	}

	if (0 == m_dbgEvent.dwThreadId)
	{
		return FALSE;
	}

	m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dbgEvent.dwThreadId);

	if (NULL == m_hThread)
	{
		return FALSE;
	}

	if (FALSE == SetThreadContext(m_hThread, pContext))
	{
		CloseHandle(m_hThread);
		m_hThread = NULL;
		return FALSE;
	}

	CloseHandle(m_hThread);
	m_hThread = NULL;
	return TRUE;
}

//************************************
// Method:    EditRegisterValue
// FullName:  CExceptionHandle::EditRegisterValue
// Description:�޸ļĴ�����ֵ,ͨ��16���ư�ȫ�����ų��˼Ĵ������֣�ֻʣ16������
// Access:    public 
// Returns:   int
// Qualifier:
// Parameter: char * pszCmd
// Date: 2018/5/8 8:27
// Author : RuiQiYang
//************************************
int CExceptionHandle::EditRegisterValue(char * pszCmd)
{

	{
		if (NULL == pszCmd)
		{
			return 0;
		}


		


		char szRegister[BUFFER_MAX] = { 0 };
		unsigned int nRegisterValue = 0;
		
		//char *regBuf = nullptr;
		//char *NumBuf = nullptr;
		//regBuf = strtok_s(pszCmd, " ", &NumBuf);

		sscanf_s(pszCmd, "%s%s", stderr,20, szRegister,20);
		CONTEXT context;
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;

		if (FALSE == GetCurrentThreadContext(&context))
		{
			return 0;
		}

		if (NULL != strstr(szRegister, "eax"))
		{
			printf("EAX: %p\r\nEAX: ", context.Eax);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);//��֮ǰ�����16��������nRegisterValue
			context.Eax = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "ax"))
		{
			printf("AX: %p\r\nAX: ", 0xffff & context.Eax);

			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);

			context.Eax = (context.Eax >> 16 << 16);
			context.Eax |= (nRegisterValue & 0xffff);
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "ebx"))
		{
			printf("EBX: %p\r\nEBX: ", context.Ebx);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Ebx = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "bx"))
		{
			printf("BX: %p\r\nBX: ", 0xffff & context.Ebx);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Ebx = (context.Ebx >> 16 << 16);
			context.Ebx |= (nRegisterValue & 0xffff);
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "ecx"))
		{
			printf("ECX: %p\r\nECX: ", context.Ecx);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Ecx = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "cx"))
		{
			printf("CX: %p\r\nCX: ", 0xffff & context.Ecx);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Ecx = (context.Ecx >> 16 << 16);
			context.Ecx |= (nRegisterValue & 0xffff);
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "edx"))
		{
			printf("EDX: %p\r\nEDX: ", context.Edx);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Edx = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "dx"))
		{
			printf("DX: %p\r\nDX: ", 0xffff & context.Edx);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Edx = (context.Edx >> 16 << 16);
			context.Edx |= (nRegisterValue & 0xffff);
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "esi"))
		{
			printf("ESI: %p\r\nESI: ", context.Esi);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Esi = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "edi"))
		{
			printf("EDI: %p\r\nEDI: ", context.Edi);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Edi = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "eip"))
		{
			printf("EIP: %p\r\nEIP: ", context.Eip);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Eip = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "esp"))
		{
			printf("ESP: %p\r\nESP: ", context.Esp);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Esp = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "ebp"))
		{
			printf("EBP: %p\r\nEBP: ", context.Ebp);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.Ebp = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "cs"))
		{
			printf("CS: %p\r\nCS: ", context.SegCs);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.SegCs = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "ss"))
		{
			printf("SS: %p\r\nSS: ", context.SegSs);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.SegSs = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "ds"))
		{
			printf("DS: %p\r\nDS: ", context.SegDs);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.SegDs = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "es"))
		{
			printf("ES: %p\r\nES: ", context.SegEs);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.SegEs = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "fs"))
		{
			printf("FS: %p\r\nFS: ", context.SegFs);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.SegFs = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		else if (NULL != strstr(szRegister, "gs"))
		{
			printf("GS: %p\r\nGS: ", context.SegGs);
			if (0 == SafeHexInput(szRegister, BUFFER_MAX))
			{
				return 0;
			}
			sscanf_s(szRegister, "%x", &nRegisterValue);
			context.SegGs = nRegisterValue;
			if (FALSE == SetCurrentThreadContext(&context))
			{
				return 0;
			}
			return 1;
		}
		return 0;
	}
}

//************************************
// Method:    Editasm
// FullName:  CExceptionHandle::Editasm
// Description:�޸Ļ������
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: SIZE_T dwAddress
// Date: 2018/5/8 14:16
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::Editasm(SIZE_T dwAddress)
{
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;


	XEDPARSE xed = { 0 };
	printf("��ַ��");

	// ��������opcode�ĵĳ�ʼ��ַ
	xed.cip = dwAddress;
	// ����ָ��
	printf("ָ�");
	gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);

	// xed.cip, ��������תƫ�Ƶ�ָ��ʱ,��Ҫ��������ֶ�
	if (XEDPARSE_OK != XEDParseAssemble(&xed))
	{
		printf("ָ�����%s\n", xed.error);
	}

	// ��ӡ���ָ�������ɵ�opcode
	printf("%08X : ", xed.cip);
	printOpcode(xed.dest, xed.dest_size);
	printf("ָ���С%d\n", xed.dest_size);
	printf("\n");
	SIZE_T dwRead = 0;
	int te = strlen(opcode);
	bool bo1 = VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, te + 1, PAGE_READWRITE, &oldProtect);
	SIZE_T write = 0;
	if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)xed.cip, &xed.dest, xed.dest_size, &write))
	{
		DBGPRINT("д���ڴ�ʧ��");
		return FALSE;
	}
	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, te + 1, oldProtect, &oldProtect);

	return TRUE;
}

//************************************
// Method:    GetCurrentEip
// FullName:  CExceptionHandle::GetCurrentEip
// Description:��ȡEip
// Access:    public 
// Returns:   int
// Qualifier:
// Parameter: DWORD dwThreadId
// Date: 2018/5/8 18:26
// Author : RuiQiYang
//************************************
int CExceptionHandle::GetCurrentEip(DWORD dwThreadId)
{
	if (0 == dwThreadId)
	{
		return 0;
	}

	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

	if (FALSE == GetCurrentThreadContext(&context))
	{
		return 0;
	}

	return context.Eip;
}

//************************************
// Method:    GetCurrentModules
// FullName:  CExceptionHandle::GetCurrentModules
// Description:��ȡ��ǰ��������ģ��
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: list<DLLNODE> & DllList
// Parameter: HANDLE hProcess
// Parameter: LPDEBUG_EVENT lpDebugEvent
// Date: 2018/5/9 0:43
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::GetCurrentModules(list<DLLNODE>& DllList, HANDLE hProcess, DEBUG_EVENT DebugEvent)
{
	DLLNODE DllNode;
	PDWORD	pdwOldProtect = NULL;
	byte	*pBuffer = NULL;
	DWORD	dwPagCount = 0;
	int		i = 0;
	DWORD	dwTmp = 0;
	PIMAGE_DOS_HEADER pPeDos = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_OPTIONAL_HEADER pOptional = NULL;

	//win7
	DWORD dwOldProtect;

	//�ͷ�֮ǰ������Դ
	DllList.clear();

	//��������ģ��
	HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, DebugEvent.dwProcessId);
	if (hmodule == INVALID_HANDLE_VALUE)
	{
		printf("ģ�����ʧ��");
		goto ERROR_EXIT;
	}
	MODULEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hmodule, &me))
	{
		do
		{
			
			
			//DllNode.dwModBase = (DWORD)me.modBaseAddr;
			//DllNode.dwModSize = me.modBaseSize;
			//DllNode.szModName = me.szModule;
			//DllNode.szModPath = me.szExePath;
			//����pe�ṹ����ڵ�
			//ע�Ͳ���Ϊxpϵͳ��������win7ϵͳ��ȡntdll��ʧ�ܣ�һ��pe pOptionalλ��ǰ1Kλ�ú������text��
			//win7���ö�ȡǰ1K���ݷ�����ڵ�λ��
			pBuffer = new byte[0x1000];
			if (pBuffer == NULL)
			{
				printf("ģ�����ʧ��2");
				goto ERROR_EXIT;
			}
			VirtualProtectEx(hProcess, me.modBaseAddr, 1, PAGE_READWRITE, &dwOldProtect);
			if (!ReadProcessMemory(hProcess, me.modBaseAddr, pBuffer, 0x1000, &dwTmp))
			{
				printf("ģ�����ʧ��3");
				goto ERROR_EXIT;
			}
			if (dwTmp != 0x1000)
			{
				goto ERROR_EXIT;
			}
			//win7��ԭ����
			VirtualProtectEx(hProcess, me.modBaseAddr, 1, dwOldProtect, &dwTmp);
			//pe������ȡ��ڵ�
			pPeDos = (PIMAGE_DOS_HEADER)pBuffer;
			if (pPeDos->e_lfanew >= 0x1000)
			{
				//��ȡ���Ȳ����޷�������ڵ�
				goto ERROR_EXIT;
			}
			pNtHeaders = (PIMAGE_NT_HEADERS)(pPeDos->e_lfanew + (UINT)pBuffer);
			pOptional = &(pNtHeaders->OptionalHeader);
			if ((UINT)pOptional - (UINT)pBuffer > 0x1000)
			{
				//��ȡ���Ȳ����޷�������ڵ�
				goto ERROR_EXIT;
			}
			DWORD *pEntryPoint = &(pOptional->AddressOfEntryPoint);
			if ((UINT)pEntryPoint - (UINT)pBuffer > 0x1000)
			{
				//��ȡ���Ȳ����޷�������ڵ�
				goto ERROR_EXIT;
			}

			DllNode.dwModEntry = pOptional->AddressOfEntryPoint + (DWORD)me.modBaseAddr;

			delete[] pBuffer;
			pBuffer = NULL;
			//���ģ����Ϣ��ģ������
			m_DllList.push_back(DllNode);
			printf("%p  %p  %p  ", (DWORD)me.modBaseAddr, me.modBaseSize, DllNode.dwModEntry);
			wprintf(L"%-18s",me.szModule);
			wprintf(me.szExePath);
			printf("\r\n");
		} while (::Module32Next(hmodule, &me));
	}
	CloseHandle(hmodule);
	hmodule = INVALID_HANDLE_VALUE;

	return TRUE;

ERROR_EXIT:
	if (pdwOldProtect)
	{
		for (int j = 0; j < i; j++)
		{
			VirtualProtectEx(hProcess, me.modBaseAddr + i * 0x1000, 1, pdwOldProtect[i], &dwTmp);
		}
		delete[] pdwOldProtect;
	}
	if (pBuffer)
	{
		delete[] pBuffer;
	}
	if (hmodule != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hmodule);
	}

	//win7��ԭ����
	VirtualProtectEx(hProcess, me.modBaseAddr, 1, dwOldProtect, &dwTmp);

	return FALSE;
}

//************************************
// Method:    ShowMod
// FullName:  CExceptionHandle::ShowMod
// Description:��ʾģ��
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Date: 2018/5/9 0:50
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::ShowMod()
{
	//��ʾģ����Ϣ
	printf("Base      Size      Entry     Name          Path    \r\n");
	if (GetCurrentModules(m_DllList, m_ProInfo.hProcess, m_dbgEvent) == FALSE)
	{
		return FALSE;
	}
	
//	list<DLLNODE>::iterator itDll;
//	for (itDll = m_DllList.begin(); itDll != m_DllList.end(); itDll++)
//	{
//		PDLLNODE pDllNode = &(*itDll);
//		printf("%p  %p  %p  ", pDllNode->dwModBase, pDllNode->dwModSize, pDllNode->dwModEntry);
//		printf("%-14s", pDllNode->szModName);
//		//printf(" ");
//		WCHAR*temp = pDllNode->szModPath;
//		//printf(pDllNode->szModPath);
//		wprintf(temp);
//		printf("\r\n");
//	}
	printf("\r\n");
	return TRUE;
}

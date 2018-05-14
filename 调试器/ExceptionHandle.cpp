#include "stdafx.h"
#include "ExceptionHandle.h"


CExceptionHandle::CExceptionHandle()
:m_nIsTCommand(0)
{
}
//����������Ĺ��캯��
CExceptionHandle::CExceptionHandle(DEBUG_EVENT dbgEvent)
:m_dbgEvent(dbgEvent),
 m_nIsTCommand(0)
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
	lpBaseOfImage = m_dbgEvent.u.CreateProcessInfo.lpBaseOfImage;

	EXCEPTION_RECORD& er = m_dbgEvent.u.Exception.ExceptionRecord;

	hProc = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		m_dbgEvent.dwProcessId);

	theThread = OpenThread(THREAD_ALL_ACCESS,
		FALSE,
		m_dbgEvent.dwThreadId);
	//�쳣�¼�����ϵͳ�ϵ�
	printf("\t�쳣���룺%08X\n", er.ExceptionCode);
	printf("\t�쳣��ַ��%08X\n", er.ExceptionAddress);
	//���ҵ�
	auto inter = this->Memorymap.find(er.ExceptionAddress);
	switch (m_dbgEvent.u.Exception.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT://�����ϵ�ʱ�������쳣��
							  //  �Ƿ��������ϵ�         ��ʱ�ϵ�(F8 ����)
	{ResetDelAllPoint();//�������жϵ�
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(theThread, &ct)) {
		DBGPRINT("��ȡ�̻߳���ʧ��");
	}
	Print((SIZE_T)m_dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);//��ӡ�����
	TheContext.Eip--;
	SetThreadContext(m_ProInfo.hThread, &TheContext);
	//�ȴ��û�����  
	//  ִ�г��� �������F7   F5  ��F8        
	//      �û�����F7  ����TF ��־λ  ���жϵ㲻��Ҫ�ָ� 
	//      �û����� F5 ���жϵ�Ҳ����Ҫ�ָ�
	WaitUserInput();
	break;
	}
	case EXCEPTION_ACCESS_VIOLATION://�ڴ�����쳣
		//MessageBox(0, "�ڴ�����쳣"��0,0);
		//MessageBox(0, TEXT("�ڴ�����쳣"),0, 0);
		//��ȡ�����жϵ�
		//����ڱ��������
		//	MessageBox(0, ("�ڴ�����쳣��"), 0, 0);
		if (inter != Memorymap.end()) {
			MessageBox(0, (L"�ڴ�����У�"), 0, 0);
			huanyabread(er.ExceptionAddress);
			//dumpasm2(this->hThread);
			//�����ڴ�ϵ�
			setAllBreakpointOther(this->hProc);
			//�ȴ��û�����
			WaitUserInput();

			break;
		}
		else {
			huanyabread(er.ExceptionAddress);
			setAllBreakpointOther(this->hProc);

			break;
		}
		break;
	case EXCEPTION_SINGLE_STEP:
		if (er.ExceptionAddress == this->myfun) {

		  MessageBox(0, _T("hook"), 0, 0);
		}
		ParseSingleSetp();
		//WaitUserInput();
		break;
	default:

		break;
	}

	CloseHandle(theThread);
	CloseHandle(hProc);


	return DBG_CONTINUE;
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
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	HANDLE temhThread = GetCurrentThread();
	GetThreadContext(theThread, &ct);
	DBG_REG7* pD7 = (DBG_REG7*)&ct.Dr7;
	for (auto i : g_HardBp) {
		VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)i.lpBpAddr, 1, PAGE_READWRITE, &oldProtect);
		switch (i.dwBpOrder)
		{
		case 0:
			pD7->L0 = 0;
			break;
		case 1:
			pD7->L1 = 0;
			break;
		case 2:
			pD7->L2 = 0;
			break;
		case 3:
			pD7->L3 = 0;
			break;
		default:
			break;
		}
		i.isActive = FALSE;
	//	if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)i.lpBpAddr, &oldbyte, 1, &len)) return FALSE;
		VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)i.lpBpAddr, 1, oldProtect, &oldProtect);
	}
	SetThreadContext(theThread, &ct);
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


	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
	HANDLE temhThread = GetCurrentThread();
	GetThreadContext(theThread, &ct);
	DBG_REG7* pD7 = (DBG_REG7*)&ct.Dr7;
	for (auto i : g_HardBp) {
		//VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)i.lpBpAddr, 1, PAGE_READWRITE, &oldProtect);
		switch (i.dwBpOrder)
		{
		case 0:
			pD7->L0 = 1;
			//���� �� dr6 ��ֵ 
			//������ж�
			m_pDR6 = (DWORD)ct.Dr6;
			break;
		case 1:
			pD7->L1 = 1;
			m_pDR6 = (DWORD)ct.Dr6;
			break;
		case 2:
			pD7->L2 = 1;
			m_pDR6 = (DWORD)ct.Dr6;
			break;
		case 3:
			pD7->L3 = 1;
			m_pDR6 = (DWORD)ct.Dr6;
			break;
		default:
			break;
		}
		i.isActive = TRUE;
	//	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)i.lpBpAddr, 1, oldProtect, &oldProtect);
		
	}
	SetThreadContext(theThread, &ct);
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
	BOOL  bFlag = TRUE;
	BOOL  isUCommand = FALSE;//�Ƿ���U����
	while (bFlag)
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
			DWORD dwEip = 0;
			dwEip = GetCurrentEip(m_dbgEvent.dwThreadId);
			PrintInstruction(dwEip, 0, 1);


			isUCommand = FALSE;
			m_nIsTCommand = TRUE;// ֮ǰ�Ƿ���T����
			ResetDelAllPoint();
			TheContext.EFlags |= 0x100;
			//PEFLAGS  eflag = (PEFLAGS)&TheContext.EFlags;
			//eflag->TF = 1;
			SetThreadContext(m_ProInfo.hThread, &TheContext);
			//��� ִ�е��� ����cc �ϵ�   
			//��� ִ�е��� ���� �ڴ�ϵ�
			//��� ִ�е��� ���� Ӳ���ϵ�
			return 0;
		}

		//����
		if (strcmp("p", CmdBuf) == 0)//DOF7
		{
			LPBYTE opcode[50];
			SIZE_T read = 0;
			//�Ȼ�ȡ��ǰ��eip
			CONTEXT ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(theThread, &ct)) {
				DBGPRINT("��ȡ�̻߳���ʧ��");
			}
			//1.��ǰָ���Ƿ�Ϊcall
			bool bol2 = ReadProcessMemory(hProc, (DWORD*)ct.Eip, opcode, sizeof(opcode), &read);
			DISASM disAsm = { 0 };
			disAsm.EIP = (UIntPtr)opcode;    //��ǰeip
			disAsm.VirtualAddr = (UInt64)ct.Eip;   //�쳣��ַ��һ����ָ����һ����
			disAsm.Archi = 0;// x86���
			int nLen = 0;
			//������һ�����س���
			nLen = Disasm(&disAsm);
			string str(disAsm.CompleteInstr);
			//������û��call
			string::size_type idx = str.find("call");
			//����һ��ָ���¶ϵ�
			if (idx != string::npos) {
				DWORD temp = ct.Eip + nLen;
				CCBPINFO bp;
				//bp.count = -1;
				//bp.Reg = 0;
				bp.bOnce = FALSE;
				bp.dwAddress = temp;
				DWORD lpflOldProtect;
				DWORD lpflOldProtect2;
				SIZE_T  lpNumberOfBytesRead;
				BYTE nowdata = 0;
				//���޸�ҳ����
				bool bo = VirtualProtectEx(hProc, (LPVOID)temp, 1000, 0x40, &lpflOldProtect);
				if (!ReadProcessMemory(hProc, (LPVOID)temp, &nowdata, 1, &lpNumberOfBytesRead)) {
					DBGPRINT("��ȡ�����ڴ�ʧ��");
					//�����û�ȥ
					bool bo2 = VirtualProtectEx(hProc, (LPVOID)temp, 1000, lpflOldProtect, &lpflOldProtect2);
					return false;
				}
				bp.OldCode = nowdata;
				//����oep�ϵ�
				//SetCcPoint(hProc, (DWORD*)temp, &bp);
				temFramWork.SetCcPoint(temp, false);
				//��������
				g_VecCCBp.push_back(bp);
			}
			//�µ���
			else {
				DWORD dwEip = 0;
				dwEip = GetCurrentEip(m_dbgEvent.dwThreadId);
				PrintInstruction(dwEip, 0, 1);


				isUCommand = FALSE;
				m_nIsTCommand = TRUE;// ֮ǰ�Ƿ���T����
				ResetDelAllPoint();
				PEFLAGS  eflag = (PEFLAGS)&TheContext.EFlags;
				eflag->TF = 1;
				SetThreadContext(m_ProInfo.hThread, &TheContext);
			}

			//ֱ�ӷ���
			return 0;
		}


		//���öϵ�
		if ('b' == CmdBuf[0]) { // ����B������������bp, ba, bd
			isUCommand = FALSE;
			ParseBCommand(buffer1);
		}
		
	if (strcmp("pe", CmdBuf) == 0) {

				 // ����B������������bp, ba, bd
		static bool bo = true;
		if (bo) {
			//��������ģ�鱣������
			EnummyModule(GetProcessId(this->hProc));
			bo = false;
		}
		LPVOID temp;

		cout << "������Ҫ�鿴��ģ��Ļ�ַ��";
		scanf_s("%x", &temp);
		auto inter = this->importTableMap.find(temp);
		if (inter != importTableMap.end()) {
			string str = importTableMap[temp];
			const char* ch = str.c_str();
			this->myPE(ch);
		}
		//this->userInput(this->hProc, this->hThread);
		WaitUserInput();
		break;
		}
	//dump
		if (strcmp("dump", CmdBuf) == 0) { // dump
			isUCommand = FALSE;
			char str[MAX_PATH];
			cout << "·����";
			gets_s(str, MAX_PATH);
			dump(str);
		}

		if (strcmp("g", CmdBuf) == 0)
		{
			ResetDelAllPoint();
			CONTEXT context = {};
			context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
			GetThreadContext(m_ProInfo.hThread,&context);
			PEFLAGS  eflag = (PEFLAGS)&context.EFlags;
			eflag->TF = 1;
			SetThreadContext(m_ProInfo.hThread, &context);

			isGo = true;
			//�����ǰEIP �ڶϵ��б�����ԭԭ���Ĵ��� �ó���������
			//temFramWork.ResetDelCcPoint(TemContext.Eip);
			////�ж� ����ôͣ������
			//DWORD dwEip = 0;
			//dwEip = GetCurrentEip(m_dbgEvent.dwThreadId);
			//// ������������    eip==�쳣��ַ
			//if (m_nIsTCommand) {
			//	return true;
			//}
			////�ϵ�������       eip==�쳣��ַ-1
			//else {
			//	CONTEXT context;
			//	context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
			//	context.Eip = dwEip - 1;
			//	SetCurrentThreadContext(&context);
			//}
			//if ((DWORD)mDebEv.u.Exception.ExceptionRecord.ExceptionAddress == TheContext.Eip)
			//	return 0;

			//�������жϵ�
			//ResetSetAllPoint();
			//����
			return TRUE;
		}

		if (strcmp("u", CmdBuf) == 0)//�鿴�����
		{
			
				Ucommand(buffer1, isUCommand);
			
			//Print(addr);
		}
		if (strcmp("d", CmdBuf) == 0)//�鿴�ڴ�
		{
			ShowMemoryData(buffer1);
		}

		if (strcmp("editasm", CmdBuf) == 0)//�޸Ļ��
		{
			Editasm(addr);
		}
		if (strcmp("peb", CmdBuf) == 0)//peb
		{
			AADebug(hProc);
		}

		if (strcmp("hook", CmdBuf) == 0)//hook
		{
			//hook������
			cout << "Ҫhook�ĺ�������";
			string str;
			cin >> str;
			const char* ch = str.c_str();
			HINSTANCE hDLL;
			hDLL = LoadLibrary(L"kernel32.dll");
			//test
			 myfun = (FARPROC)GetProcAddress(hDLL, "OpenProcessToken");
			//FARPROC myfun = (FARPROC)GetProcAddress(hDLL, ch);
			//�¸�Ӳ���ϵ�
			//SetDrBreakPoint(4, (unsigned int)myfun, 0, 0);
		   setBreakpoint_hardRW(theThread,(ULONG_PTR)myfun,0,0);
			WaitUserInput();
			break;

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
			isUCommand = FALSE;
			if (2 == GetParamCount(buffer1))
			{
				EditRegisterValue(buffer1);
			}
			PrintContext();
		}
		if (strcmp("q", CmdBuf) == 0)//�Ƿ����˳�
		{
			ExitProcess(0);
			bFlag = FALSE;
			return 0;
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
		printf("bt (���һ�������ϵ�)            �ϵ��ַ �Ĵ��� ֵ\r\n");
		printf("bm (���һ���ڴ�ϵ�)            �ϵ��ַ ���� Ȩ��\r\n");
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
		printf("PEB                              ����PEB\r\n");
		printf("HOOK                             HOOK\r\n");
		printf("d [Ŀ����ʼ��ַ] [Ŀ����ַ��ַ]/[����] �鿴�ڴ�\r\n");
		printf("e                                �޸��ڴ�\r\n");
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
			
			
			DllNode.dwModBase = (DWORD)me.modBaseAddr;
			DllNode.dwModSize = me.modBaseSize;
			DllNode.szModName = new WCHAR[sizeof(me.szModule) + 1]{};
			memcpy(DllNode.szModName, me.szModule, sizeof(me.szModule));
			DllNode.szModPath = new WCHAR[sizeof(me.szExePath) + 1]{};
			memcpy(DllNode.szModPath, me.szExePath, sizeof(me.szExePath));
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
		//	printf("%p  %p  %p  ", (DWORD)me.modBaseAddr, me.modBaseSize, DllNode.dwModEntry);
		//	wprintf(L"%-18s",me.szModule);
		//	wprintf(me.szExePath);
		//	printf("\r\n");
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
	
	list<DLLNODE>::iterator itDll;
	for (itDll = m_DllList.begin(); itDll != m_DllList.end(); itDll++)
	{
		PDLLNODE pDllNode = &(*itDll);
		printf("%p  %p  %p  ", pDllNode->dwModBase, pDllNode->dwModSize, pDllNode->dwModEntry);
		wprintf(L"%-18s", pDllNode->szModName);
		printf(" ");
		wprintf(pDllNode->szModPath);
		printf("\r\n");
	}
	printf("\r\n");
	return TRUE;
}

//************************************
// Method:    ParseSingleSetp
// FullName:  CExceptionHandle::ParseSingleSetp
// Description:������
// Access:    public 
// Returns:   int
// Qualifier:
// Date: 2018/5/9 18:49
// Author : RuiQiYang
//************************************
int CExceptionHandle::ParseSingleSetp()
{

	//Thect
	ResetSetAllPoint();
	DBG_REG6* pDR6 =(DBG_REG6*) &m_pDR6;
	//�ж��ǲ���Ӳ���ϵ�
	//ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
	//GetThreadContext(theThread, &ct);
	
	if (pDR6->B0 == 1 || pDR6->B1 == 1 || pDR6->B2 == 1) {
	//	ResetSetAllPoint();
		printf("Ӳ���ϵ����\n");
		WaitUserInput();
	}

	if (isGo)
	{
		/*CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
		GetThreadContext(theThread, &ct);
		DBG_REG7* pD7 = (DBG_REG7*)&ct.Dr7;

		pD7->RW0 = 0;
		pD7->LEN0 = 0;
		pD7->L0 = 1;

		SetThreadContext(theThread, &ct);*/
		return 0;
	}

	if (m_nIsTCommand) {
		
		ResetSetAllPoint();
		WaitUserInput();
	}
	

	return 0;
}

//************************************
// Method:    PrintInstruction
// FullName:  CExceptionHandle::PrintInstruction
// Description:���ָ��
// Access:    public 
// Returns:   int
// Qualifier:
// Parameter: IN int Eip
// Parameter: IN BOOL bIsContimue
// Parameter: IN int nItem
// Date: 2018/5/9 18:16
// Author : RuiQiYang
//************************************
VOID CExceptionHandle::PrintInstruction(int Eip,BOOL bContinue, int nItem)
{
	if (INVALID_HANDLE_VALUE == m_ProInfo.hProcess)
	{
		OutputDebugString(_T("PrintDebugInfo���̾����Ч\n"));
		return;
	}
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	if (FALSE == GetCurrentThreadContext(&context))
		return;
	DWORD dwTempEip = context.Eip;
	DWORD dwProtect = 0;
	if (0 != Eip)
	{
		if (FALSE == VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)Eip, MAX_PATH,
			PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			return;
		}
	}
	else
	{
		if (FALSE == VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwTempEip, MAX_PATH,
			PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			return;
		}
	}
	//���þ�̬�������ڼ�������ָ��
	static DWORD dwEip = 0;
	if (FALSE == bContinue)
	{
		dwEip = Eip;
	}
	ResetDelAllPoint();
	char szBuf[MAX_PATH] = { 0 };
	DWORD dwNumOfBytesRead = 0;
	if (FALSE == ReadProcessMemory(m_ProInfo.hProcess, (PVOID)dwEip, szBuf, MAX_PATH, &dwNumOfBytesRead))
	{
		OutputDebugString(_T("Eip��ȡʧ��\n"));
		return;
	}
	DISASM disAsm = { 0 };
	int		 nLen = 0;		//ָ���
	disAsm.EIP = (UIntPtr)szBuf;
	disAsm.VirtualAddr = (UInt64)dwEip;
	disAsm.Archi = 0; //x86���
	//for (int i = 0;i < dwCount;++i)
	for (int i = 0;i < nItem;++i)
	{
		nLen = Disasm(&disAsm);
		if (nLen == -1)//�����ʧ�ܻ᷵��1
			break;
		//printf("%p\t%0X\t%s\n",disAsm.EIP,disAsm.Instruction,disAsm.CompleteInstr);
		printf("%08X  ", disAsm.VirtualAddr);
		printf("%s", disAsm.CompleteInstr);
		printf("\n");
		disAsm.EIP += nLen;
		disAsm.VirtualAddr += nLen;
		dwEip += nLen;
	}

	ResetSetAllPoint();
	if (0 != Eip)
	{
		if (FALSE == VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)Eip, MAX_PATH,
			dwProtect, &dwProtect))
		{
			return;
		}
	}
	else
	{
		if (FALSE == VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwTempEip, MAX_PATH,
			dwProtect, &dwProtect))
		{
			return;
		}
	}
}


//************************************
// Method:    Ucommand
// FullName:  CExceptionHandle::Ucommand
// Description:����U����
// Access:    public 
// Returns:   int
// Qualifier:
// Parameter: char * pszCmd
// Date: 2018/5/9 17:59
// Author : RuiQiYang
//************************************
int CExceptionHandle::Ucommand(char *pszCmd, BOOL bISContinue)
{
	DWORD dwEip = 0;
	if (FALSE == bISContinue)
	{
		dwEip = GetCurrentEip(m_dbgEvent.dwThreadId);
	}

	int nStrLen = strlen(pszCmd);
	if (1 == nStrLen || nStrLen >= BUFFER_MAX)
	{
		PrintInstruction(dwEip, bISContinue, 8);
		return 1;
	}

	int nArgc = GetParamCount(pszCmd);

	// ���ֻ�ж�������
	// ����Ϊ�˷����Ժ���չ���ܣ�ͬʱ���򵥵İ�ȫ���
	if (2 == nArgc)
	{
		sscanf_s(pszCmd, "%s%x", stderr,100, &dwEip);

		/*
		// �����жϵ�ַ�Ƿ�Ϸ�
		if ((dwEip & 0x80000000) || (dwEip <= 0x4096))
		{
		return 0 ;
		}
		*/
		// �����ж�һ�µ�ַ�Ƿ�����Ч���ڴ��ҳ����
		int nPage = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (0 == IsEffectiveAddress((LPVOID)dwEip, &mbi))
		{
			printf("Ŀ���ַ������!\r\n");
			return 0;
		}
		PrintInstruction(dwEip, FALSE, 8);
	}
	return 1;
}

//************************************
// Method:    ParseBCommand
// FullName:  CExceptionHandle::ParseBCommand
// Description:�ϵ��������
// Access:    public 
// Returns:   int
// Qualifier:
// Parameter: char * pszCmd
// Date: 2018/5/9 19:53
// Author : RuiQiYang
//************************************
int CExceptionHandle::ParseBCommand(char * pszCmd)
{
	char *CmdBuf = nullptr;
	char *NumBuf = nullptr;
	char * pszCmd1 = pszCmd;
	//CmdBuf = strtok_s(pszCmd, " ", &NumBuf);
	if (NULL == pszCmd)
	{
		return 0;
	}
	CMyDebuggerFramWork temp;
	temp.m_ProInfo = m_ProInfo;
	switch (pszCmd[1])
	{
	case 'p':
	case 'P':
		if (2 == GetParamCount(pszCmd1))
		{
			unsigned int nAddr = 0;
			sscanf_s(pszCmd, "%s%x", stderr,100, &nAddr);
			if (1 == temp.SetCcPoint(nAddr, FALSE)){
				printf("��Ӷϵ�ɹ�\r\n");
			}
			else
			{
				printf("��Ӷϵ�ʧ��\r\n");
			}
		}
		else
		{
			printf("^Error\r\n");
		}
		return 1;
	case 'a':
		if (4 == GetParamCount(pszCmd1))
		{
			unsigned int nAddr = 0;
			int nLen = 0;
			char szPurview[MAXBYTE];
			int nPurview = 0;
			// ����Ҫ�ģ��Ժ���ܻ����overflow������
			sscanf_s(pszCmd1, "%s%x%x%s", stderr,100, &nAddr, &nLen, szPurview,100);

			if (FALSE == setBreakpoint_hardRW(theThread, nAddr, nPurview, nLen))
			{
				
						printf("���Ӳ���ϵ�ʧ��!\r\n");
				
			}
			else
			{
				printf("���Ӳ���ϵ�ɹ�!\r\n");
			}
		}
		else
		{
			printf("��������\r\n,����������:��ַ ���� Ȩ��\r\n");
		}


		return 1;

		//�����ڴ�ϵ�
	case 'm':
		Setmm();
		return 1;
		//���������ϵ�


	case 't':
		if (4 == GetParamCount(pszCmd1))
		{
			unsigned int nAddr = 0;
			int nLen = 0;
			char szPurview[MAXBYTE];
			int nPurview = 0;
			sscanf_s(pszCmd1, "%s%x%x%d", stderr, 100, &nAddr, &nPurview, &nLen);

			
			if (FALSE==setConditPoint( theThread, nAddr, nPurview, nLen))
			{

				printf("��������ϵ�ʧ��!\r\n");

			}
			else
			{
				printf("��������ϵ�ɹ�!\r\n");
			}
		}
		else
		{
			printf("��������\r\n,����������: �ϵ��ַ �Ĵ��� ֵ\r\n");
		}

		return 1;
	}
}

//************************************
// Method:    setBreakpoint_hardExec
// FullName:  CExceptionHandle::setBreakpoint_hardExec
// Description:����Ӳ��ִ�жϵ�
// Access:    public 
// Returns:   bool
// Qualifier:
// Parameter: HANDLE hThread
// Parameter: ULONG_PTR uAddress
// Date: 2018/5/9 22:21
// Author : RuiQiYang
//************************************
bool CExceptionHandle::setBreakpoint_hardExec(HANDLE hThread, ULONG_PTR uAddress)
{
	DWORD temp1 = -1;
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);//��ȡ�̻߳�����
	DBG_REG7* pD7 = (DBG_REG7*)&ct.Dr7;
	if (pD7->L0 == 0) {//DR0û�б�ʹ��
		temp1 = 0;
		ct.Dr0 = uAddress;
		pD7->RW0 = 0;
		pD7->LEN0 = 0;//����������Ϊ0
	}
	else if (pD7->L1 == 0) {//DR1û�б�ʹ��
		temp1 = 1;
		ct.Dr1 = uAddress;
		pD7->RW1 = 0;
		pD7->LEN1 = 0;//����������Ϊ0
	}
	else if (pD7->L2 == 0) {//DR2û�б�ʹ��
		temp1 = 2;
		ct.Dr2 = uAddress;
		pD7->RW2 = 0;
		pD7->LEN2 = 0;//����������Ϊ0
	}
	else if (pD7->L3 == 0) {//DR2û�б�ʹ��
		temp1 = 3;
		ct.Dr3 = uAddress;
		pD7->RW3 = 0;
		pD7->LEN3 = 0;//����������Ϊ0
	}
	else {
		return FALSE;
	}
	DWORD temp2= uAddress;
	BPNODE tempB;
	tempB.dwBpOrder = temp1;
	tempB.isActive = TRUE;
	tempB.isResume = FALSE;
	tempB.lpBpAddr = temp2;
	tempB.enuBpRWE = 0;
	tempB.dwBpLen = 1;
	g_HardBp.push_back(tempB);
	SetThreadContext(hThread, &ct);
	return TRUE;
}

//************************************
// Method:    setBreakpoint_hardRW
// FullName:  CExceptionHandle::setBreakpoint_hardRW
// Description:����Ӳ����д�ϵ�
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: HANDLE hThread
// Parameter: ULONG_PTR uAddress
// Parameter: BP_RWE type
// Parameter: DWORD dwLen
// Date: 2018/5/10 0:42
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::setBreakpoint_hardRW(HANDLE hThread, ULONG_PTR uAddress, int type, DWORD dwLen)
{
	DWORD temp1 = -1;
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS| CONTEXT_FULL;
	GetThreadContext(theThread, &ct);
	//�Ե�ַ�ͳ��Ƚ��ж�����������ȡ����
	if (dwLen == 1) {//2^1�ֽڶ�������
		uAddress = uAddress - uAddress % 2;
	}
	else if (dwLen == 3) {//2^1�ֽڶ�������
		uAddress = uAddress - uAddress % 4;
	}
	else if (dwLen > 3)
		return FALSE;
	//�ж���Щ�Ĵ���û�б�ʹ��
	DBG_REG7* pD7 = (DBG_REG7*)&ct.Dr7;
	if (pD7->L0 == 0) {//DR0û�б�ʹ��
		temp1 = 0;
		ct.Dr0 = uAddress;
		pD7->RW0 = type;
		pD7->LEN0 = dwLen;//����������Ϊ0
		pD7->L0 = 1;
	}
	else if (pD7->L1 == 0) {//DR1û�б�ʹ��
		temp1 = 1;
		ct.Dr1 = uAddress;
		pD7->RW1 = type;
		pD7->LEN1 = dwLen;//����������Ϊ0
		pD7->L1 = 1;
	}
	else if (pD7->L2 == 0) {//DR2û�б�ʹ��
		temp1 = 2;
		ct.Dr2 = uAddress;
		pD7->RW2 = type;
		pD7->LEN2 = dwLen;//����������Ϊ0
		pD7->L2 = 1;
	}
	else if (pD7->L3 == 0) {//DR2û�б�ʹ��
		temp1 = 3;
		ct.Dr3 = uAddress;
		pD7->RW3 = type;
		pD7->LEN3 = dwLen;//����������Ϊ0
		pD7->L3= 1;
	}
	else {
		return FALSE;
	}
	DWORD temp2 = uAddress;
	BPNODE tempB;
	tempB.dwBpOrder = temp1;
	tempB.isActive = TRUE;
	tempB.isResume = FALSE;
	tempB.lpBpAddr = temp2;
	tempB.enuBpRWE = type;
	tempB.dwBpLen = dwLen;
	g_HardBp.push_back(tempB);
	SetThreadContext(theThread, &ct);
	return TRUE;
}

//************************************
// Method:    setConditPoint
// FullName:  CExceptionHandle::setConditPoint
// Description:���������ϵ�ϵ�
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: HANDLE hThread
// Parameter: ULONG_PTR uAddress
// Parameter: int type
// Parameter: DWORD dwLen
// Date: 2018/5/10 16:29
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::setConditPoint(HANDLE hThread, ULONG_PTR uAddress, int type, DWORD dwLen)
{
	BYTE Int3 = 0xcc;
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;
	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)uAddress, 1, PAGE_READWRITE, &oldProtect);//�ı����ں˵ı������ԡ�

	if (!ReadProcessMemory(m_ProInfo.hProcess, (LPVOID)uAddress, &oldbyte, 1, &len)) {//��ȡ�ڴ���Ϣ����ԭ������д��oldbyte
		DBGPRINT("��ȡ�����ڴ�ʧ��");
		return FALSE;
	}
	if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)uAddress, &Int3, 1, &len)) {//д���ڴ���Ϣ����ԭ��λ��д��0xCc
		DBGPRINT("д������ڴ�ʧ��");
		return false;
	}

	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)uAddress, 1, oldProtect, &oldProtect);

	//g_VecCONBp.push_back({ uAddress ,FALSE,oldbyte ,type ,dwLen });
	return TRUE;
}

int CExceptionHandle::AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview)
{
	//�����̾��
	if (NULL == hProc)
	{
		return 0;
	}
	// ������
	if (NULL == nAddr)
	{
		return 0;
	}
	//����ڴ�ϵ��Ƿ��Ѿ�������
	//if (dwPurview==beinset(nAddr, dwPurview))
	//{
	//	printf("�Ѿ�����\n");
	//	return 0;
	//}

	/*
	#define PAGE_NOACCESS          0x01
	#define PAGE_READONLY          0x02
	#define PAGE_READWRITE         0x04
	*/
	//if (dwPurview < 1 || dwPurview > 4)
	//{
	//	return 0;
	//}
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	SIZE_T size = 100;
	//�Ȼ�ȡ����
	VirtualQueryEx(this->hProc, nAddr, &mbi, sizeof(mbi));
	if (mbi.Type == dwPurview) {
		printf("���������Ǹ����ԣ�����");
		return 0;
	}
	/*VirtualProtectEx(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);*/
	DWORD lpflOldProtect;
	//��������
	if (!VirtualProtectEx(this->hProc, nAddr, nLen, dwPurview, &lpflOldProtect)) {
		printf("����ʧ�ܣ�����\n");
		return 0;
	}
	DWORD dw;//����
	MemoryBreakType temptype{ dwPurview, lpflOldProtect ,nLen ,true };  //new  old
	this->Memorymap.insert(pair <LPVOID, MemoryBreakType>(nAddr, temptype));
	printf("���óɹ�������\n");
	return 1;
}

int CExceptionHandle::RemoveMemoryBreak(LPVOID nAddr)
{
	//���ҵ�
	auto inter = this->Memorymap.find(nAddr);
	if (inter != Memorymap.end()) {  //����ҵ���
		MessageBox(0, L"�ڴ�ϵ㴥����", 0, 0);
		MemoryBreakType temptype = Memorymap[nAddr];
		DWORD tempdw = temptype.oldType;
		DWORD lpflOldProtect;
		//��������
		if (VirtualProtectEx(this->hProc, nAddr, temptype.nLen, tempdw, &lpflOldProtect)) {
			printf("����ʧ�ܣ�����\n");
			return 0;
		}
		//�������h��
		Memorymap.erase(inter);
		printf("���óɹ�������\n");
		return 1;
	}
	printf("����û�У������Լ����õģ�����\n");
	return 0;
}

DWORD CExceptionHandle::beinset(LPVOID addr, DWORD dw)
{
	if (dw > 0x11 && dw < 0x00) {
		printf("����:%x", dw);
		return 0x12;
	}
	//���ҵ�
	auto inter = this->Memorymap.find(addr);
	if (inter != Memorymap.end()) {  //����ҵ���
		MemoryBreakType temptype = Memorymap[addr];
		if (temptype.newType == dw) { //������
			return 0x10;
		}
		else {
			switch (temptype.newType)
			{
				//#define PAGE_NOACCESS          0x01     
				//#define PAGE_READONLY          0x02     
				//#define PAGE_READWRITE         0x04     
				//#define PAGE_WRITECOPY         0x08  
			case 0x01:
			{
				return 0x01;
			}
			case 0x02:
			{
				return 0x02;
			}
			case 0x04:
			{
				return 0x04;
			}
			case 0x08:
			{
				return 0x08;
			}
			default:
				return 0x00;
			}
		}
	}
	return 0x00;
}
//�����ڴ�ϵ�
void CExceptionHandle::Setmm()
{
	////�����ڴ�ϵ�
	//int AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview);
	////�Ƴ��ڴ�ϵ�
	//int RemoveMemoryBreak(LPVOID nAddr);
	printf("��ʼ��ַ��");
	LPVOID nAddr = 0;
	//��ʼ��ַ
	scanf_s("%x", &nAddr);
	getchar();
	//#define PAGE_NOACCESS          0x01
	//#define PAGE_READONLY          0x02
	//#define PAGE_READWRITE         0x04
	DWORD dw;

	printf("Ȩ�ޱ�����  0x01��ֹ���� 0x02 ֻ�� \n");
	printf("ʲôȨ�޵Ķϵ㣺");
	scanf_s("%x", &dw);
	getchar();
	int len;
	printf("���ȣ�");
	scanf_s("%d", &len);
	AppendMemoryBreak((LPVOID)nAddr, len, dw);
}

void CExceptionHandle::huanyabread(LPVOID lpAddr)
{
	DWORD lpflOldProtect;
	//�����ÿ���ִ����������

	
	//д����
	VirtualProtectEx(this->hProc, lpAddr, 100, 0x20, &lpflOldProtect);
	//����û�ԭeip
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(theThread, &ct)) {
		DBGPRINT("��ȡ�߳�������ʧ��");
		return;
	}
	++ct.Eip;
	if (!SetThreadContext(theThread, &ct)) {
		DBGPRINT("�����߳�������ʧ��");
		return;
	}
}
//�������жϵ�
void CExceptionHandle::setAllBreakpoint(HANDLE hProc)
{
	////��� 
	//for (auto&i : g_bps) {
	//	if (i.dwType == EXCEPTION_BREAKPOINT) {
	//		setBreakpoint_cc(hProc, i.address, &i);
	//	}
	//	else if (i.dwType == EXCEPTION_SINGLE_STEP) {
	//		//setBreakpoint_hard();
	//	}
	//}
	map<LPVOID, MemoryBreakType>::iterator it;

	it = Memorymap.begin();
	//�ڴ�
	while (it != Memorymap.end())
	{
		//it->first;
		//it->second;
		AppendMemoryBreak(it->first, 1, it->second.newType);
		it++;
	}
}

//���ó��˵�ǰ������жϵ�
void CExceptionHandle::setAllBreakpointOther(HANDLE hProc)
{
	EXCEPTION_RECORD& er = m_dbgEvent.u.Exception.ExceptionRecord;

	map<LPVOID, MemoryBreakType>::iterator it;

	it = Memorymap.begin();
	//�ڴ�
	while (it != Memorymap.end())
	{
		//it->first;
		//it->second;
		//�ϵ��Ƿ�Ϊ��ǰeip
		if (er.ExceptionAddress != it->first) {
			AppendMemoryBreak(it->first, 1, it->second.newType);
		}
		it++;
	}
	//Ӳ��
//	//Ӳ��
//	for (auto temp : DrVector) {
//		if (er.ExceptionAddress != temp.address) {
//			this->SetDrBreakPoint(temp.dr, (unsigned int)temp.address, temp.nLen, temp.nPurview);
//		}
//	}
}

void CExceptionHandle::AADebug(HANDLE hDebugProcess)
{

	typedef NTSTATUS(WINAPI*pfnNtQueryInformationProcess)
		(HANDLE ProcessHandle, ULONG ProcessInformationClass,
			PVOID ProcessInformation, UINT32 ProcessInformationLength,
			UINT32* ReturnLength);

	typedef struct _MY_PEB {               // Size: 0x1D8
		UCHAR           InheritedAddressSpace;
		UCHAR           ReadImageFileExecOptions;
		UCHAR           BeingDebugged;              //Debug���б�־
		UCHAR           SpareBool;
		HANDLE          Mutant;
		HINSTANCE       ImageBaseAddress;           //������صĻ���ַ
		struct _PEB_LDR_DATA    *Ldr;                //Ptr32 _PEB_LDR_DATA
		struct _RTL_USER_PROCESS_PARAMETERS  *ProcessParameters;
		ULONG           SubSystemData;
		HANDLE         ProcessHeap;
		KSPIN_LOCK      FastPebLock;
		ULONG           FastPebLockRoutine;
		ULONG           FastPebUnlockRoutine;
		ULONG           EnvironmentUpdateCount;
		ULONG           KernelCallbackTable;
		LARGE_INTEGER   SystemReserved;
		struct _PEB_FREE_BLOCK  *FreeList;
		ULONG           TlsExpansionCounter;
		ULONG           TlsBitmap;
		LARGE_INTEGER   TlsBitmapBits;
		ULONG           ReadOnlySharedMemoryBase;
		ULONG           ReadOnlySharedMemoryHeap;
		ULONG           ReadOnlyStaticServerData;
		ULONG           AnsiCodePageData;
		ULONG           OemCodePageData;
		ULONG           UnicodeCaseTableData;
		ULONG           NumberOfProcessors;
		LARGE_INTEGER   NtGlobalFlag;               // Address of a local copy
		LARGE_INTEGER   CriticalSectionTimeout;
		ULONG           HeapSegmentReserve;
		ULONG           HeapSegmentCommit;
		ULONG           HeapDeCommitTotalFreeThreshold;
		ULONG           HeapDeCommitFreeBlockThreshold;
		ULONG           NumberOfHeaps;
		ULONG           MaximumNumberOfHeaps;
		ULONG           ProcessHeaps;
		ULONG           GdiSharedHandleTable;
		ULONG           ProcessStarterHelper;
		ULONG           GdiDCAttributeList;
		KSPIN_LOCK      LoaderLock;
		ULONG           OSMajorVersion;
		ULONG           OSMinorVersion;
		USHORT          OSBuildNumber;
		USHORT          OSCSDVersion;
		ULONG           OSPlatformId;
		ULONG           ImageSubsystem;
		ULONG           ImageSubsystemMajorVersion;
		ULONG           ImageSubsystemMinorVersion;
		ULONG           ImageProcessAffinityMask;
		ULONG           GdiHandleBuffer[0x22];
		ULONG           PostProcessInitRoutine;
		ULONG           TlsExpansionBitmap;
		UCHAR           TlsExpansionBitmapBits[0x80];
		ULONG           SessionId;
	} MY_PEB, *PMY_PEB;


	HMODULE NtdllModule = GetModuleHandle(L"ntdll.dll");
	pfnNtQueryInformationProcess NtQueryInformationProcess =
		(pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION  pbi = { 0 };
	UINT32  ReturnLength = 0;
	NTSTATUS Status = NtQueryInformationProcess(hDebugProcess,
		ProcessBasicInformation, &pbi, (UINT32)sizeof(pbi), (UINT32*)&ReturnLength);
	if (NT_SUCCESS(Status))
	{
		MY_PEB* Peb = (MY_PEB*)malloc(sizeof(MY_PEB));
		ReadProcessMemory(hDebugProcess, (PVOID)pbi.PebBaseAddress, Peb, sizeof(MY_PEB), NULL);

		Peb->BeingDebugged = 0;
		Peb->NtGlobalFlag.u.HighPart = 0;

		WriteProcessMemory(hDebugProcess, (PVOID)pbi.PebBaseAddress, Peb, sizeof(MY_PEB), NULL);

	}
}


void CExceptionHandle::dump(char* str)
{
	//dumpǰ��ԭ���жϵ�
	ResetDelAllPoint();

	HANDLE hFile = CreateFileA(str, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("�����ļ�ʧ��,\n");
		if (GetLastError() == 0x00000050) {
			cout << "�ļ��Ѵ��ڣ�����" << endl;
		}
		return;
	}
	IMAGE_DOS_HEADER dos;//dosͷ

	IMAGE_NT_HEADERS nt;
	//��dosͷ
	if (ReadProcessMemory(m_hProc, m_lpBaseOfImage, &dos, sizeof(IMAGE_DOS_HEADER), NULL) == FALSE)
		return;


	//��ntͷ
	if (ReadProcessMemory(m_hProc, (BYTE *)m_lpBaseOfImage + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS32), NULL) == FALSE)
	{
		return;
	}


	//��ȡ���������������С
	DWORD secNum = nt.FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Sections = new IMAGE_SECTION_HEADER[secNum];
	//��ȡ����
	if (ReadProcessMemory(m_hProc,
		(BYTE *)m_lpBaseOfImage + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS),
		Sections,
		secNum * sizeof(IMAGE_SECTION_HEADER),
		NULL) == FALSE)
	{
		return;
	}

	//�������н����Ĵ�С
	DWORD allsecSize = 0;
	DWORD maxSec;//���Ľ���

	maxSec = 0;

	for (int i = 0; i < secNum; ++i)
	{
		allsecSize += Sections[i].SizeOfRawData;

	}

	//dos
	//nt
	//�����ܴ�С
	DWORD topsize = secNum * sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_NT_HEADERS) + dos.e_lfanew;

	//ʹͷ��С�����ļ�����
	if ((topsize&nt.OptionalHeader.FileAlignment) != topsize)
	{
		topsize &= nt.OptionalHeader.FileAlignment;
		topsize += nt.OptionalHeader.FileAlignment;
	}

	DWORD ftsize = topsize + allsecSize;
	//�����ļ�ӳ��
	HANDLE hMap = CreateFileMapping(hFile,
		NULL, PAGE_READWRITE,
		0,
		ftsize,
		0);

	if (hMap == NULL)
	{
		printf("�����ļ�ӳ��ʧ��\n");
		return;
	}

	//������ͼ
	LPVOID lpmem = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

	if (lpmem == NULL)
	{
		delete[] Sections;
		CloseHandle(hMap);
		printf("������ͼʧ��\n");
		return;
	}
	PBYTE bpMem = (PBYTE)lpmem;
	memcpy(lpmem, &dos, sizeof(IMAGE_DOS_HEADER));
	//����dossub ��С

	DWORD subSize = dos.e_lfanew - sizeof(IMAGE_DOS_HEADER);

	if (ReadProcessMemory(m_hProc, (BYTE *)m_lpBaseOfImage + sizeof(IMAGE_DOS_HEADER), bpMem + sizeof(IMAGE_DOS_HEADER), subSize, NULL) == FALSE)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		return;
	}

	nt.OptionalHeader.ImageBase = (DWORD)lpBaseOfImage;
	//����NTͷ
	memcpy(bpMem + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS));

	//�������
	memcpy(bpMem + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS), Sections, secNum * sizeof(IMAGE_SECTION_HEADER));

	for (int i = 0; i < secNum; ++i)
	{
		if (ReadProcessMemory(
			m_hProc, (BYTE *)m_lpBaseOfImage + Sections[i].VirtualAddress,
			bpMem + Sections[i].PointerToRawData,
			Sections[i].SizeOfRawData,
			NULL) == FALSE)
		{
			delete[] Sections;
			CloseHandle(hMap);
			UnmapViewOfFile(lpmem);
			return;
		}
	}
	if (FlushViewOfFile(lpmem, 0) == false)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		printf("���浽�ļ�ʧ��\n");
		return;
	}
	delete[] Sections;
	CloseHandle(hMap);
	UnmapViewOfFile(lpmem);
	MessageBox(0, L"ok", 0, 0);
	return;
}
bool CExceptionHandle::EnummyModule(DWORD dwPID) {
	// 1. �ȴ�������
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);

	// 2. ��ʼ��������
	MODULEENTRY32W mi = { sizeof(MODULEENTRY32W) };
	BOOL bRet = Module32First(hTool32, (LPMODULEENTRY32)&mi);
	if (!bRet)
	{
		printf("Module32First error!\n");
		return false;
	}
	int i = 0;
	do
	{
		char ch[1000] = { 0 };
		sprintf_s(ch, "%S", mi.szExePath,100);
		string str(ch);
		//����ģ��
		this->importTableMap.insert(make_pair(mi.modBaseAddr, str));
	} while (Module32NextW(hTool32, &mi));
	return true;
}
//����pe
void CExceptionHandle::myPE(const char* str)
{
	string st = str;
	DWORD dwFileSize;
	BYTE* g_pFileImageBase = 0;
	//PIMAGE_NT_HEADERS g_pNt = 0;

	DWORD RVAtoFOA(DWORD dwRVA);
	OPENFILENAME stOF;
	HANDLE hFile, hMapFile;
	DWORD totalSize;        //�ļ���С
	LPVOID lpMemory;        //�ڴ�ӳ���ļ����ڴ����ʼλ��
	char szFileName[MAX_PATH] = { 0 };  //Ҫ�򿪵��ļ�·����������
	char bufTemp1[10];                  //ÿ���ַ���ʮ�������ֽ���
	char bufTemp2[20];                  //��һ��
	char lpServicesBuffer[100];     //һ�е���������
	char bufDisplay[50];                //������ASCII���ַ�
	DWORD dwCount;                      //��������16�����¼�
	DWORD dwCount1;                     //��ַ˳��
	DWORD dwBlanks;                     //���һ�пո���
	hFile = CreateFileA(str, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
	//�������Ч�ľ��
	if (hFile == INVALID_HANDLE_VALUE) {
		
		printf("��ģ��ʧ��\n");
		return;
	}
	//��ȡ�ļ���С
	dwFileSize = GetFileSize(hFile, NULL);
	g_pFileImageBase = new BYTE[dwFileSize]{};
	DWORD dwRead;
	//���ļ���ȡ���ڴ���
	bool bRet = ReadFile(hFile, g_pFileImageBase, dwFileSize, &dwRead, NULL);
	//�����ȡʧ�ܾͷ���
	if (!bRet)
	{
		delete[] g_pFileImageBase;
	}
	//�رվ��
	CloseHandle(hFile);

	//ʹ��PIMAGE_DOS_HEADER��ռ64�ֽڣ�����ǰ64���ֽ�
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_pFileImageBase;
	//�ж�PE�ļ��ı�ʶ�Ƿ���ȷ����һ�����ԣ���ô���Ͳ���PE�ļ�
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)//0x5A4D('MZ')
	{
		return;
	}


	g_pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + g_pFileImageBase);
	if (g_pNt->Signature != IMAGE_NT_SIGNATURE)//0x00004550('PE')
	{
		return;
	}
	(g_pNt->FileHeader);

	PIMAGE_OPTIONAL_HEADER32 myoption = &(g_pNt->OptionalHeader);

	int nCountOfSection = g_pNt->FileHeader.NumberOfSections;
	//ȡ��һ������ͷ
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(g_pNt);

	//	
	DWORD dwExportRVA = g_pNt->OptionalHeader.DataDirectory[0].VirtualAddress;
	//	//��ȡ���ļ��е�λ��
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(this->RVAtoFOA(dwExportRVA) + g_pFileImageBase);
	//	//ģ������
	char* pName = (char*)(this->RVAtoFOA(pExport->Name) + g_pFileImageBase);
	printf("%s\n", pName);
	//��ַ���еĸ���
	DWORD dwCountOfFuntions = pExport->NumberOfFunctions;
	//���Ʊ��еĸ���
	DWORD dwCountOfNames = pExport->NumberOfNames;
	//��ַ���ַ
	PDWORD pAddrOfFuntion = (PDWORD)(this->RVAtoFOA(pExport->AddressOfFunctions) + g_pFileImageBase);
	//���Ʊ��ַ
	PDWORD pAddrOfName = (PDWORD)(this->RVAtoFOA(pExport->AddressOfNames) + g_pFileImageBase);
	//��ű��ַ
	PWORD pAddrOfOrdial = (PWORD)(this->RVAtoFOA(pExport->AddressOfNameOrdinals) + g_pFileImageBase);
	//	//baseֵ
	DWORD dwBase = pExport->Base;
	//	//������ַ���е�Ԫ��
	//	cout << "-----------------------------------------�������еĵ��������뵼�����-------------------------------------------------- " << endl;
	cout << "�������еĵ��������뵼�����" << endl;
	if (dwExportRVA == 0) {

		printf("û�е�����\n");

		//return;
	}
	else {
		for (int i = 0; i < dwCountOfFuntions;i++)
		{
			//��ַ���п��ܴ������õ�ֵ������Ϊ0��ֵ��
			if (pAddrOfFuntion[i] == 0)
			{
				continue;
			}
			//������ű����Ƿ���ֵ����ַ����±�ֵ����
			//���ж��Ƿ������Ƶ���
			bool bRet = false;
			for (int j = 0; j < dwCountOfNames;j++)
			{
				//iΪ��ַ���±�jΪ��ű���±ֵ꣨Ϊ��ַ���±꣩
				//�ж��Ƿ�����ű���
				if (i == pAddrOfOrdial[j])
				{
					//��Ϊ��ű������Ʊ��λ��һһ��Ӧ
					//ȡ�����Ʊ��е����Ƶ�ַRVA
					DWORD dwNameRVA = pAddrOfName[j];
					char* pFunName = (char*)(this->RVAtoFOA(dwNameRVA) + g_pFileImageBase);
					printf("%04d  ", i + dwBase);
					printf("%s  ", pFunName);

					printf("0x%08x\n", pAddrOfFuntion[i]);
					bRet = true;
					break;
				}
			}
			if (!bRet)
			{
				//��ű���û�У�˵��������ŵ�����
				printf("%04d          ", i + dwBase);
				//��ű���û�У�˵��������ŵ�����
				printf("%08X\n", pAddrOfFuntion[i]);
			}

		}
	}
	//	
	//	cout << "-----------------------------------------������еĵ��뺯���뵼��ģ��-------------------------------------------------- " << endl;

	//�ҵ������  Ҳ���ǵڶ����±�Ϊ1
	DWORD dwImpotRVA = g_pNt->OptionalHeader.DataDirectory[1].VirtualAddress;
	//���ļ��е�λ��
	DWORD dwImportInFile = (DWORD)(this->RVAtoFOA(dwImpotRVA) + g_pFileImageBase);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)dwImportInFile;
	//����ÿһ�������  ͨ�����һ��Ϊ0��Ϊ�ж�����
	if (dwImpotRVA == 0) {
		printf("û�е����\n");

		return;
	}
	else {
		while (pImport->Name)
		{
			//�������Ƶ�ַ
			PIMAGE_THUNK_DATA pFirsThunk =
				(PIMAGE_THUNK_DATA)(this->RVAtoFOA(pImport->FirstThunk) + g_pFileImageBase);
			//ģ����
			char* pName = (char*)(this->RVAtoFOA(pImport->Name) + g_pFileImageBase);

			printf("����ģ������%s\n", pName);
			//Ҳ��ͨ�����һ��Ϊ0��Ϊ�ж�����
			while (pFirsThunk->u1.AddressOfData)
			{
				//�жϵ��뷽ʽ
				if (IMAGE_SNAP_BY_ORDINAL32(pFirsThunk->u1.AddressOfData))
				{
					//˵������ŵ���(��16λ�������)
					printf("\t\t%04X \n", pFirsThunk->u1.Ordinal & 0xFFFF);
				}
				else
				{
					//���Ƶ���
					PIMAGE_IMPORT_BY_NAME pImportName =
						(PIMAGE_IMPORT_BY_NAME)(this->RVAtoFOA(pFirsThunk->u1.AddressOfData) + g_pFileImageBase);

					printf("\t\t%04X", pImportName->Hint);

					printf("%s \n", pImportName->Name);
				}
				//
				pFirsThunk++;
			}
			pImport++;
		}
	}
	return;
}
//void _openFile();
DWORD CExceptionHandle::RVAtoFOA(DWORD dwRVA)
{
	//��RVA�����ĸ�������
	//�ҵ��������κ�
	//��ȥ�������ε���ʼλ�ã��������ļ��е���ʼλ��
	//���ļ�ͷ����������
	int nCountOfSection = g_pNt->FileHeader.NumberOfSections;
	//���α�ͷ
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(g_pNt);
	//����չͷ���ҵ��������
	DWORD dwSecAligment = g_pNt->OptionalHeader.SectionAlignment;
	//ѭ��
	for (int i = 0; i < nCountOfSection; i++)
	{
		//�����ڴ��е���ʵ��С
		//Misc.VirtualSize % dwSecAligment�����0����պö��������ȶ��루��0�����棩
		//Misc.VirtualSize / dwSecAligment * dwSecAligment   + dwSecAligment     //�����������Ķ���
		DWORD dwRealVirSize = pSec->Misc.VirtualSize % dwSecAligment ?
			pSec->Misc.VirtualSize / dwSecAligment * dwSecAligment + dwSecAligment
			: pSec->Misc.VirtualSize;
		//�����е���������ַת�ļ�ƫ��  ˼·�� ��Ҫת���ĵ�ַ�������
		//����ʼ��ַ���Ƚ��������һ�������У�������ʼ��ַС����ʼ��ַ���������ƫ�ƺͣ���
		//����Ҫת������������ַ��ȥ���ε���ʼ��ַ����������ַ��
		//�õ��������ַ����������ƫ�ƣ����õõ������ƫ�Ƽ����������ļ��е�ƫ�Ƶ���ʼλ��
		//��pointerToRawData�ֶ�)���������ļ��е��ļ�ƫ��
		if (dwRVA >= pSec->VirtualAddress &&
			dwRVA < pSec->VirtualAddress + dwRealVirSize)
		{
			//FOA = RVA - �ڴ������ε���ʼλ�� + ���ļ������ε���ʼλ�� 
			return dwRVA - pSec->VirtualAddress + pSec->PointerToRawData;
		}
		//��һ�����ε�ַ
		pSec++;
	}
}
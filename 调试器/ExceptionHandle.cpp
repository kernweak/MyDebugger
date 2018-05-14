#include "stdafx.h"
#include "ExceptionHandle.h"


CExceptionHandle::CExceptionHandle()
:m_nIsTCommand(0)
{
}
//带传入参数的构造函数
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
// Description:处理异常函数
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
	//异常事件就是系统断点
	printf("\t异常代码：%08X\n", er.ExceptionCode);
	printf("\t异常地址：%08X\n", er.ExceptionAddress);
	//先找到
	auto inter = this->Memorymap.find(er.ExceptionAddress);
	switch (m_dbgEvent.u.Exception.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT://触发断点时引发的异常。
							  //  是否有条件断点         临时断点(F8 步过)
	{ResetDelAllPoint();//重置所有断点
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(theThread, &ct)) {
		DBGPRINT("获取线程环境失败");
	}
	Print((SIZE_T)m_dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);//打印反汇编
	TheContext.Eip--;
	SetThreadContext(m_ProInfo.hThread, &TheContext);
	//等待用户输入  
	//  执行程序 三种情况F7   F5  和F8        
	//      用户输入F7  设置TF 标志位  所有断点不需要恢复 
	//      用户输入 F5 所有断点也不需要恢复
	WaitUserInput();
	break;
	}
	case EXCEPTION_ACCESS_VIOLATION://内存访问异常
		//MessageBox(0, "内存访问异常"，0,0);
		//MessageBox(0, TEXT("内存访问异常"),0, 0);
		//先取消所有断点
		//如果在保存的里面
		//	MessageBox(0, ("内存访问异常！"), 0, 0);
		if (inter != Memorymap.end()) {
			MessageBox(0, (L"内存断命中！"), 0, 0);
			huanyabread(er.ExceptionAddress);
			//dumpasm2(this->hThread);
			//设置内存断点
			setAllBreakpointOther(this->hProc);
			//等待用户输入
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
// Description:传入处理调试事件
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
// Description:将调试进程信息传递给异常类
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
// Description:重置删除所有断点
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
// Description:重新加上所有断点
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
			//保存 下 dr6 的值 
			//外边做判断
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
// Description:打印反汇编
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
	disAsm.EIP = (UIntPtr)buf;// 保存opcode的缓冲区首地址
	disAsm.VirtualAddr = dwAddress; // opcode 指令的地址
	disAsm.Archi = 0; // 0 => 32 , 1 => 64
	disAsm.Options = 0x000; // masm 汇编指令格式
	ReadProcessMemory(m_ProInfo.hProcess, (char*)dwAddress, buf, 0x64, &numsize);
	m_BEA.UseBea(buf, disAsm);
	return 0;
}

//************************************
// Method:    ShowMemoryData
// FullName:  CExceptionHandle::ShowMemoryData
// Description:打印内存信息
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
		OutputDebugString(L"参数指针为空!\r\n");
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
// Description:修改内存信息
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
	printf("请输入要修改的地址：");
	DWORD dwAddress = 0;
	scanf_s("%X", &dwAddress);
	char bData[1024] = { 0 };
	SIZE_T write = 0;
	printf("请输入要内容：");
	scanf_s("%s", bData, 1024);
	int tem = strlen(bData);
	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, tem+1, PAGE_READWRITE, &oldProtect);
	// 将内容写入内存
	if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)dwAddress, &bData, tem, &write))
	{
		printf("写入内存失败");
		VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, tem + 1, oldProtect, &oldProtect);
		return FALSE;
	}
	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, tem + 1, oldProtect, &oldProtect);
	return TRUE;

}

//************************************
// Method:    DisplayDestProcessMemory
// FullName:  CExceptionHandle::DisplayDestProcessMemory
// Description:显示调试进程目标内存数据
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

	// 判断地址是否存在
	if (0 == IsEffectiveAddress(pAddr, &mbi))
	{
		OutputDebugString(L"内存地址无效!\r\n");
		return 0;
	}

	char *pBuf = new char[nLen + sizeof(char)];
	//memset(pBuf, 0, nLen + sizeof(char));

	if (NULL == pBuf)
	{
		OutputDebugString(L"申请内存失效!\r\n");
		return 0;
	}

	if (nLen <= 0)
	{
		OutputDebugString(L"长度出错!\r\n");
		return 0;
	}

	if (nLen > (int)pAddr)
	{
		nLen -= (int)pAddr;
		++nLen;
	}

	DWORD dwProtect = 0;

	// 防止下了内存断点，目标内存页没有读的属性，先将读的属性加上去
	if (FALSE == VirtualProtectEx(m_ProInfo.hProcess, pAddr, BUFFER_MAX,
		PAGE_EXECUTE_READWRITE, &dwProtect))
	{
		OutputDebugString(L"DisplayDestProcessMemory VirtualProtectEx出错!\r\n");
		return 0;

	}

	DWORD dwNothing = 0;

	if (FALSE == ReadProcessMemory(m_ProInfo.hProcess, pAddr, pBuf,
		sizeof(char)*nLen, &dwNothing))
	{
		OutputDebugString(L"读目标进程出错!\r\n");
		return 0;
	}
	// 将属性还原
	VirtualProtectEx(m_ProInfo.hProcess, pAddr, BUFFER_MAX,
		dwProtect, &dwProtect);
	int nCount = 0;
	for (int i = nCount; i < nLen;)
	{
		// 输出前面的地址
		if (0 == (i & 0xf))
		{
			printf("%p  ", pAddr);
			pAddr = (LPVOID)((DWORD)pAddr + 0x10);
		}

		// 输出数据16进制
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

		// 如果不足0x10个的话，补足
		for (int k = 0x10 - nIndex; k >= 0; --k)
		{
			printf("   ");
		}

		for (; nCount < i; ++nCount)
		{
			byte ch = (byte)pBuf[nCount];

			// isgraph 是否是可显示字符
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
// Description:判断是否是有效地址//通过大小进行判断
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
// Description:等待用户输入
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Date: 2018/5/7 15:39
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::WaitUserInput()
{
	BOOL  bFlag = TRUE;
	BOOL  isUCommand = FALSE;//是否是U命令
	while (bFlag)
	{
		fflush(stdin);
		CMyDebuggerFramWork temFramWork;
		temFramWork.m_ProInfo = m_ProInfo;
		char buffer[20] = {};
		char *CmdBuf = nullptr;
		char *NumBuf = nullptr;
		
		DWORD addr = 0;
		printf("请输入：");
		gets_s(buffer, 20);
		//printf("输入的buffer为：%s\n", buffer);
		char buffer1[20] = {};
		memcpy(buffer1, buffer, sizeof(buffer));
		char* tempBuf = buffer;
		CmdBuf = strtok_s(buffer, " ", &NumBuf);
		sscanf_s(NumBuf, "%x", &addr);
		//单步
		if(CmdBuf==NULL)continue;
		if (strcmp("t", CmdBuf) == 0)//DOF7
		{
			DWORD dwEip = 0;
			dwEip = GetCurrentEip(m_dbgEvent.dwThreadId);
			PrintInstruction(dwEip, 0, 1);


			isUCommand = FALSE;
			m_nIsTCommand = TRUE;// 之前是否是T命令
			ResetDelAllPoint();
			TheContext.EFlags |= 0x100;
			//PEFLAGS  eflag = (PEFLAGS)&TheContext.EFlags;
			//eflag->TF = 1;
			SetThreadContext(m_ProInfo.hThread, &TheContext);
			//如果 执行单步 遇到cc 断点   
			//如果 执行单步 遇到 内存断点
			//如果 执行单步 遇到 硬件断点
			return 0;
		}

		//步过
		if (strcmp("p", CmdBuf) == 0)//DOF7
		{
			LPBYTE opcode[50];
			SIZE_T read = 0;
			//先获取当前的eip
			CONTEXT ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(theThread, &ct)) {
				DBGPRINT("获取线程环境失败");
			}
			//1.当前指令是否为call
			bool bol2 = ReadProcessMemory(hProc, (DWORD*)ct.Eip, opcode, sizeof(opcode), &read);
			DISASM disAsm = { 0 };
			disAsm.EIP = (UIntPtr)opcode;    //当前eip
			disAsm.VirtualAddr = (UInt64)ct.Eip;   //异常地址（一般是指向下一条）
			disAsm.Archi = 0;// x86汇编
			int nLen = 0;
			//反汇编出一条返回长度
			nLen = Disasm(&disAsm);
			string str(disAsm.CompleteInstr);
			//查找有没有call
			string::size_type idx = str.find("call");
			//在下一条指令下断点
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
				//先修改页属性
				bool bo = VirtualProtectEx(hProc, (LPVOID)temp, 1000, 0x40, &lpflOldProtect);
				if (!ReadProcessMemory(hProc, (LPVOID)temp, &nowdata, 1, &lpNumberOfBytesRead)) {
					DBGPRINT("读取进程内存失败");
					//先设置回去
					bool bo2 = VirtualProtectEx(hProc, (LPVOID)temp, 1000, lpflOldProtect, &lpflOldProtect2);
					return false;
				}
				bp.OldCode = nowdata;
				//设置oep断点
				//SetCcPoint(hProc, (DWORD*)temp, &bp);
				temFramWork.SetCcPoint(temp, false);
				//保存起来
				g_VecCCBp.push_back(bp);
			}
			//下单步
			else {
				DWORD dwEip = 0;
				dwEip = GetCurrentEip(m_dbgEvent.dwThreadId);
				PrintInstruction(dwEip, 0, 1);


				isUCommand = FALSE;
				m_nIsTCommand = TRUE;// 之前是否是T命令
				ResetDelAllPoint();
				PEFLAGS  eflag = (PEFLAGS)&TheContext.EFlags;
				eflag->TF = 1;
				SetThreadContext(m_ProInfo.hThread, &TheContext);
			}

			//直接返回
			return 0;
		}


		//设置断点
		if ('b' == CmdBuf[0]) { // 处理B命令的命令，比如bp, ba, bd
			isUCommand = FALSE;
			ParseBCommand(buffer1);
		}
		
	if (strcmp("pe", CmdBuf) == 0) {

				 // 处理B命令的命令，比如bp, ba, bd
		static bool bo = true;
		if (bo) {
			//遍历所有模块保存起来
			EnummyModule(GetProcessId(this->hProc));
			bo = false;
		}
		LPVOID temp;

		cout << "请输入要查看的模块的基址：";
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
			cout << "路径：";
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
			//如果当前EIP 在断点列表中则还原原来的代码 让程序跑起来
			//temFramWork.ResetDelCcPoint(TemContext.Eip);
			////判断 是怎么停下来的
			//DWORD dwEip = 0;
			//dwEip = GetCurrentEip(m_dbgEvent.dwThreadId);
			//// 单步走下来的    eip==异常地址
			//if (m_nIsTCommand) {
			//	return true;
			//}
			////断点下来的       eip==异常地址-1
			//else {
			//	CONTEXT context;
			//	context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
			//	context.Eip = dwEip - 1;
			//	SetCurrentThreadContext(&context);
			//}
			//if ((DWORD)mDebEv.u.Exception.ExceptionRecord.ExceptionAddress == TheContext.Eip)
			//	return 0;

			//设置所有断点
			//ResetSetAllPoint();
			//返回
			return TRUE;
		}

		if (strcmp("u", CmdBuf) == 0)//查看反汇编
		{
			
				Ucommand(buffer1, isUCommand);
			
			//Print(addr);
		}
		if (strcmp("d", CmdBuf) == 0)//查看内存
		{
			ShowMemoryData(buffer1);
		}

		if (strcmp("editasm", CmdBuf) == 0)//修改汇编
		{
			Editasm(addr);
		}
		if (strcmp("peb", CmdBuf) == 0)//peb
		{
			AADebug(hProc);
		}

		if (strcmp("hook", CmdBuf) == 0)//hook
		{
			//hook函数名
			cout << "要hook的函数名：";
			string str;
			cin >> str;
			const char* ch = str.c_str();
			HINSTANCE hDLL;
			hDLL = LoadLibrary(L"kernel32.dll");
			//test
			 myfun = (FARPROC)GetProcAddress(hDLL, "OpenProcessToken");
			//FARPROC myfun = (FARPROC)GetProcAddress(hDLL, ch);
			//下个硬件断点
			//SetDrBreakPoint(4, (unsigned int)myfun, 0, 0);
		   setBreakpoint_hardRW(theThread,(ULONG_PTR)myfun,0,0);
			WaitUserInput();
			break;

		}


		if (strcmp("e", CmdBuf) == 0)//修改内存
		{
			EditMemoryData();
		}
		if (strcmp(".show", CmdBuf) == 0)//查看栈信息
		{
			ShowMod();
		}
		if (strcmp("stack", CmdBuf) == 0)//查看栈信息
		{
			PrintStack();
		}
		if (strcmp("h", CmdBuf) == 0|| strcmp("help", CmdBuf) == 0)//查看帮助文档
		{
			PrintCommandHelp(0);
		}
		if (strcmp("r", CmdBuf) == 0)//查看和修改寄存器
		{
			isUCommand = FALSE;
			if (2 == GetParamCount(buffer1))
			{
				EditRegisterValue(buffer1);
			}
			PrintContext();
		}
		if (strcmp("q", CmdBuf) == 0)//是否是退出
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
// Description:查看帮助
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
		printf("ba (添加一个硬件断点)            断点地址 长度 权限\r\n");
		printf("bp (int3断点)                    断点地址\r\n");
		printf("bt (添加一个条件断点)            断点地址 寄存器 值\r\n");
		printf("bm (添加一个内存断点)            断点地址 长度 权限\r\n");
	}

	if (0 == ch)
	{
		printf("t                                单步进入\r\n");
		printf("p                                单步步过\r\n");
		printf("r                                查看修改寄存器\r\n");
		printf("u [目标地址]                     反汇编\r\n");
		printf("editasm [目标地址]               修改汇编代码\r\n");
		printf("? 或  h                          查看帮助\r\n");
		printf("g [目标地址]                     执行到目标地址处\r\n");
		printf("stack                            查看栈信息\r\n");
		printf("PEB                              隐藏PEB\r\n");
		printf("HOOK                             HOOK\r\n");
		printf("d [目标起始地址] [目标终址地址]/[长度] 查看内存\r\n");
		printf("e                                修改内存\r\n");
		printf(".show                            显示已加载模块\r\n");
	}
	printf("\r\n");
	return;
}

//************************************
// Method:    PrintContext
// FullName:  CExceptionHandle::PrintContext
// Description:打印上下文信息
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
// Description:查看栈信息
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
		DBGPRINT("读取进程内存失败");
	}
	for (int i = 0;i < 5;++i) {
		printf("\t%08X|%08X\n", context.Esp + i * 4,buff[i]);
	}
	printf("EAX=%p  \n", context.Esp);
}

//************************************
// Method:    GetCurrentThreadContext
// FullName:  CExceptionHandle::GetCurrentThreadContext
// Description:获取当前线程上下文
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
		OutputDebugString(L"Context数组指针为空!\r\n");
		return FALSE;
	}

	if (0 == m_dbgEvent.dwThreadId)
	{
		OutputDebugString(L"线程id无效\r\n");
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
// Description:设置当前线程上下文
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
// Description:修改寄存器的值,通过16进制安全输入排除了寄存器名字，只剩16进制数
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
			sscanf_s(szRegister, "%x", &nRegisterValue);//将之前输入的16进制数给nRegisterValue
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
// Description:修改汇编数据
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
	printf("地址：");

	// 接受生成opcode的的初始地址
	xed.cip = dwAddress;
	// 接收指令
	printf("指令：");
	gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);

	// xed.cip, 汇编带有跳转偏移的指令时,需要配置这个字段
	if (XEDPARSE_OK != XEDParseAssemble(&xed))
	{
		printf("指令错误：%s\n", xed.error);
	}

	// 打印汇编指令所生成的opcode
	printf("%08X : ", xed.cip);
	printOpcode(xed.dest, xed.dest_size);
	printf("指令大小%d\n", xed.dest_size);
	printf("\n");
	SIZE_T dwRead = 0;
	int te = strlen(opcode);
	bool bo1 = VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, te + 1, PAGE_READWRITE, &oldProtect);
	SIZE_T write = 0;
	if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)xed.cip, &xed.dest, xed.dest_size, &write))
	{
		DBGPRINT("写入内存失败");
		return FALSE;
	}
	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, te + 1, oldProtect, &oldProtect);

	return TRUE;
}

//************************************
// Method:    GetCurrentEip
// FullName:  CExceptionHandle::GetCurrentEip
// Description:获取Eip
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
// Description:获取当前程序所有模块
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

	//释放之前链表资源
	DllList.clear();

	//遍历加载模块
	HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, DebugEvent.dwProcessId);
	if (hmodule == INVALID_HANDLE_VALUE)
	{
		printf("模块加载失败");
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
			//解析pe结构拿入口点
			//注释部分为xp系统的做法，win7系统读取ntdll会失败，一般pe pOptional位于前1K位置后面紧跟text段
			//win7采用读取前1K数据分析入口点位置
			pBuffer = new byte[0x1000];
			if (pBuffer == NULL)
			{
				printf("模块加载失败2");
				goto ERROR_EXIT;
			}
			VirtualProtectEx(hProcess, me.modBaseAddr, 1, PAGE_READWRITE, &dwOldProtect);
			if (!ReadProcessMemory(hProcess, me.modBaseAddr, pBuffer, 0x1000, &dwTmp))
			{
				printf("模块加载失败3");
				goto ERROR_EXIT;
			}
			if (dwTmp != 0x1000)
			{
				goto ERROR_EXIT;
			}
			//win7还原属性
			VirtualProtectEx(hProcess, me.modBaseAddr, 1, dwOldProtect, &dwTmp);
			//pe分析获取入口点
			pPeDos = (PIMAGE_DOS_HEADER)pBuffer;
			if (pPeDos->e_lfanew >= 0x1000)
			{
				//读取长度不够无法解析入口点
				goto ERROR_EXIT;
			}
			pNtHeaders = (PIMAGE_NT_HEADERS)(pPeDos->e_lfanew + (UINT)pBuffer);
			pOptional = &(pNtHeaders->OptionalHeader);
			if ((UINT)pOptional - (UINT)pBuffer > 0x1000)
			{
				//读取长度不够无法解析入口点
				goto ERROR_EXIT;
			}
			DWORD *pEntryPoint = &(pOptional->AddressOfEntryPoint);
			if ((UINT)pEntryPoint - (UINT)pBuffer > 0x1000)
			{
				//读取长度不够无法解析入口点
				goto ERROR_EXIT;
			}

			DllNode.dwModEntry = pOptional->AddressOfEntryPoint + (DWORD)me.modBaseAddr;

			delete[] pBuffer;
			pBuffer = NULL;
			//添加模块信息到模块链表
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

	//win7还原属性
	VirtualProtectEx(hProcess, me.modBaseAddr, 1, dwOldProtect, &dwTmp);

	return FALSE;
}

//************************************
// Method:    ShowMod
// FullName:  CExceptionHandle::ShowMod
// Description:显示模块
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Date: 2018/5/9 0:50
// Author : RuiQiYang
//************************************
BOOL CExceptionHandle::ShowMod()
{
	//显示模块信息
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
// Description:处理单步
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
	//判断是不是硬件断点
	//ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
	//GetThreadContext(theThread, &ct);
	
	if (pDR6->B0 == 1 || pDR6->B1 == 1 || pDR6->B2 == 1) {
	//	ResetSetAllPoint();
		printf("硬件断点断下\n");
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
// Description:输出指令
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
		OutputDebugString(_T("PrintDebugInfo进程句柄无效\n"));
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
	//设置静态变量用于继续下轮指令
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
		OutputDebugString(_T("Eip读取失败\n"));
		return;
	}
	DISASM disAsm = { 0 };
	int		 nLen = 0;		//指令长度
	disAsm.EIP = (UIntPtr)szBuf;
	disAsm.VirtualAddr = (UInt64)dwEip;
	disAsm.Archi = 0; //x86汇编
	//for (int i = 0;i < dwCount;++i)
	for (int i = 0;i < nItem;++i)
	{
		nLen = Disasm(&disAsm);
		if (nLen == -1)//反汇编失败会返回1
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
// Description:处理U命令
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

	// 如果只有二个参数
	// 这里为了方便以后扩展功能，同时做简单的安全检查
	if (2 == nArgc)
	{
		sscanf_s(pszCmd, "%s%x", stderr,100, &dwEip);

		/*
		// 这里判断地址是否合法
		if ((dwEip & 0x80000000) || (dwEip <= 0x4096))
		{
		return 0 ;
		}
		*/
		// 这里判断一下地址是否处于有效的内存分页当中
		int nPage = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (0 == IsEffectiveAddress((LPVOID)dwEip, &mbi))
		{
			printf("目标地址不存在!\r\n");
			return 0;
		}
		PrintInstruction(dwEip, FALSE, 8);
	}
	return 1;
}

//************************************
// Method:    ParseBCommand
// FullName:  CExceptionHandle::ParseBCommand
// Description:断点相关命令
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
				printf("添加断点成功\r\n");
			}
			else
			{
				printf("添加断点失败\r\n");
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
			// 这里要改，以后可能会存在overflow的问题
			sscanf_s(pszCmd1, "%s%x%x%s", stderr,100, &nAddr, &nLen, szPurview,100);

			if (FALSE == setBreakpoint_hardRW(theThread, nAddr, nPurview, nLen))
			{
				
						printf("添加硬件断点失败!\r\n");
				
			}
			else
			{
				printf("添加硬件断点成功!\r\n");
			}
		}
		else
		{
			printf("参数错误\r\n,带三个参数:地址 长度 权限\r\n");
		}


		return 1;

		//设置内存断点
	case 'm':
		Setmm();
		return 1;
		//设置条件断点


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

				printf("添加条件断点失败!\r\n");

			}
			else
			{
				printf("添加条件断点成功!\r\n");
			}
		}
		else
		{
			printf("参数错误\r\n,带三个参数: 断点地址 寄存器 值\r\n");
		}

		return 1;
	}
}

//************************************
// Method:    setBreakpoint_hardExec
// FullName:  CExceptionHandle::setBreakpoint_hardExec
// Description:设置硬件执行断点
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
	GetThreadContext(hThread, &ct);//获取线程环境块
	DBG_REG7* pD7 = (DBG_REG7*)&ct.Dr7;
	if (pD7->L0 == 0) {//DR0没有被使用
		temp1 = 0;
		ct.Dr0 = uAddress;
		pD7->RW0 = 0;
		pD7->LEN0 = 0;//长度域设置为0
	}
	else if (pD7->L1 == 0) {//DR1没有被使用
		temp1 = 1;
		ct.Dr1 = uAddress;
		pD7->RW1 = 0;
		pD7->LEN1 = 0;//长度域设置为0
	}
	else if (pD7->L2 == 0) {//DR2没有被使用
		temp1 = 2;
		ct.Dr2 = uAddress;
		pD7->RW2 = 0;
		pD7->LEN2 = 0;//长度域设置为0
	}
	else if (pD7->L3 == 0) {//DR2没有被使用
		temp1 = 3;
		ct.Dr3 = uAddress;
		pD7->RW3 = 0;
		pD7->LEN3 = 0;//长度域设置为0
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
// Description:设置硬件读写断点
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
	//对地址和长度进行对齐整理（向上取整）
	if (dwLen == 1) {//2^1字节对齐粒度
		uAddress = uAddress - uAddress % 2;
	}
	else if (dwLen == 3) {//2^1字节对齐粒度
		uAddress = uAddress - uAddress % 4;
	}
	else if (dwLen > 3)
		return FALSE;
	//判断哪些寄存器没有被使用
	DBG_REG7* pD7 = (DBG_REG7*)&ct.Dr7;
	if (pD7->L0 == 0) {//DR0没有被使用
		temp1 = 0;
		ct.Dr0 = uAddress;
		pD7->RW0 = type;
		pD7->LEN0 = dwLen;//长度域设置为0
		pD7->L0 = 1;
	}
	else if (pD7->L1 == 0) {//DR1没有被使用
		temp1 = 1;
		ct.Dr1 = uAddress;
		pD7->RW1 = type;
		pD7->LEN1 = dwLen;//长度域设置为0
		pD7->L1 = 1;
	}
	else if (pD7->L2 == 0) {//DR2没有被使用
		temp1 = 2;
		ct.Dr2 = uAddress;
		pD7->RW2 = type;
		pD7->LEN2 = dwLen;//长度域设置为0
		pD7->L2 = 1;
	}
	else if (pD7->L3 == 0) {//DR2没有被使用
		temp1 = 3;
		ct.Dr3 = uAddress;
		pD7->RW3 = type;
		pD7->LEN3 = dwLen;//长度域设置为0
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
// Description:设置条件断点断点
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
	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)uAddress, 1, PAGE_READWRITE, &oldProtect);//改变在内核的保护属性。

	if (!ReadProcessMemory(m_ProInfo.hProcess, (LPVOID)uAddress, &oldbyte, 1, &len)) {//读取内存信息，将原有数据写入oldbyte
		DBGPRINT("读取进程内存失败");
		return FALSE;
	}
	if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)uAddress, &Int3, 1, &len)) {//写入内存信息，将原有位置写入0xCc
		DBGPRINT("写入进程内存失败");
		return false;
	}

	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)uAddress, 1, oldProtect, &oldProtect);

	//g_VecCONBp.push_back({ uAddress ,FALSE,oldbyte ,type ,dwLen });
	return TRUE;
}

int CExceptionHandle::AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview)
{
	//检查进程句柄
	if (NULL == hProc)
	{
		return 0;
	}
	// 检查参数
	if (NULL == nAddr)
	{
		return 0;
	}
	//检查内存断点是否已经设置了
	//if (dwPurview==beinset(nAddr, dwPurview))
	//{
	//	printf("已经存在\n");
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
	//先获取属性
	VirtualQueryEx(this->hProc, nAddr, &mbi, sizeof(mbi));
	if (mbi.Type == dwPurview) {
		printf("本来就是那个属性！！！");
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
	//设置属性
	if (!VirtualProtectEx(this->hProc, nAddr, nLen, dwPurview, &lpflOldProtect)) {
		printf("设置失败！！！\n");
		return 0;
	}
	DWORD dw;//属性
	MemoryBreakType temptype{ dwPurview, lpflOldProtect ,nLen ,true };  //new  old
	this->Memorymap.insert(pair <LPVOID, MemoryBreakType>(nAddr, temptype));
	printf("设置成功！！！\n");
	return 1;
}

int CExceptionHandle::RemoveMemoryBreak(LPVOID nAddr)
{
	//先找到
	auto inter = this->Memorymap.find(nAddr);
	if (inter != Memorymap.end()) {  //如果找到了
		MessageBox(0, L"内存断点触发！", 0, 0);
		MemoryBreakType temptype = Memorymap[nAddr];
		DWORD tempdw = temptype.oldType;
		DWORD lpflOldProtect;
		//设置属性
		if (VirtualProtectEx(this->hProc, nAddr, temptype.nLen, tempdw, &lpflOldProtect)) {
			printf("设置失败！！！\n");
			return 0;
		}
		//迭代器刪除
		Memorymap.erase(inter);
		printf("设置成功！！！\n");
		return 1;
	}
	printf("库里没有，不是自己设置的！！！\n");
	return 0;
}

DWORD CExceptionHandle::beinset(LPVOID addr, DWORD dw)
{
	if (dw > 0x11 && dw < 0x00) {
		printf("错误:%x", dw);
		return 0x12;
	}
	//先找到
	auto inter = this->Memorymap.find(addr);
	if (inter != Memorymap.end()) {  //如果找到了
		MemoryBreakType temptype = Memorymap[addr];
		if (temptype.newType == dw) { //如果相等
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
//设置内存断点
void CExceptionHandle::Setmm()
{
	////设置内存断点
	//int AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview);
	////移除内存断点
	//int RemoveMemoryBreak(LPVOID nAddr);
	printf("起始地址：");
	LPVOID nAddr = 0;
	//初始地址
	scanf_s("%x", &nAddr);
	getchar();
	//#define PAGE_NOACCESS          0x01
	//#define PAGE_READONLY          0x02
	//#define PAGE_READWRITE         0x04
	DWORD dw;

	printf("权限保护：  0x01禁止所有 0x02 只读 \n");
	printf("什么权限的断点：");
	scanf_s("%x", &dw);
	getchar();
	int len;
	printf("长度：");
	scanf_s("%d", &len);
	AppendMemoryBreak((LPVOID)nAddr, len, dw);
}

void CExceptionHandle::huanyabread(LPVOID lpAddr)
{
	DWORD lpflOldProtect;
	//先设置可以执行先让他过

	
	//写死了
	VirtualProtectEx(this->hProc, lpAddr, 100, 0x20, &lpflOldProtect);
	//必须得还原eip
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(theThread, &ct)) {
		DBGPRINT("获取线程上下文失败");
		return;
	}
	++ct.Eip;
	if (!SetThreadContext(theThread, &ct)) {
		DBGPRINT("设置线程上下文失败");
		return;
	}
}
//设置所有断点
void CExceptionHandle::setAllBreakpoint(HANDLE hProc)
{
	////软件 
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
	//内存
	while (it != Memorymap.end())
	{
		//it->first;
		//it->second;
		AppendMemoryBreak(it->first, 1, it->second.newType);
		it++;
	}
}

//设置除了当前外的所有断点
void CExceptionHandle::setAllBreakpointOther(HANDLE hProc)
{
	EXCEPTION_RECORD& er = m_dbgEvent.u.Exception.ExceptionRecord;

	map<LPVOID, MemoryBreakType>::iterator it;

	it = Memorymap.begin();
	//内存
	while (it != Memorymap.end())
	{
		//it->first;
		//it->second;
		//断点是否为当前eip
		if (er.ExceptionAddress != it->first) {
			AppendMemoryBreak(it->first, 1, it->second.newType);
		}
		it++;
	}
	//硬件
//	//硬件
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
		UCHAR           BeingDebugged;              //Debug运行标志
		UCHAR           SpareBool;
		HANDLE          Mutant;
		HINSTANCE       ImageBaseAddress;           //程序加载的基地址
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
	//dump前还原所有断点
	ResetDelAllPoint();

	HANDLE hFile = CreateFileA(str, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("创建文件失败,\n");
		if (GetLastError() == 0x00000050) {
			cout << "文件已存在！！！" << endl;
		}
		return;
	}
	IMAGE_DOS_HEADER dos;//dos头

	IMAGE_NT_HEADERS nt;
	//读dos头
	if (ReadProcessMemory(m_hProc, m_lpBaseOfImage, &dos, sizeof(IMAGE_DOS_HEADER), NULL) == FALSE)
		return;


	//读nt头
	if (ReadProcessMemory(m_hProc, (BYTE *)m_lpBaseOfImage + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS32), NULL) == FALSE)
	{
		return;
	}


	//读取节区并计算节区大小
	DWORD secNum = nt.FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Sections = new IMAGE_SECTION_HEADER[secNum];
	//读取节区
	if (ReadProcessMemory(m_hProc,
		(BYTE *)m_lpBaseOfImage + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS),
		Sections,
		secNum * sizeof(IMAGE_SECTION_HEADER),
		NULL) == FALSE)
	{
		return;
	}

	//计算所有节区的大小
	DWORD allsecSize = 0;
	DWORD maxSec;//最大的节区

	maxSec = 0;

	for (int i = 0; i < secNum; ++i)
	{
		allsecSize += Sections[i].SizeOfRawData;

	}

	//dos
	//nt
	//节区总大小
	DWORD topsize = secNum * sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_NT_HEADERS) + dos.e_lfanew;

	//使头大小按照文件对齐
	if ((topsize&nt.OptionalHeader.FileAlignment) != topsize)
	{
		topsize &= nt.OptionalHeader.FileAlignment;
		topsize += nt.OptionalHeader.FileAlignment;
	}

	DWORD ftsize = topsize + allsecSize;
	//创建文件映射
	HANDLE hMap = CreateFileMapping(hFile,
		NULL, PAGE_READWRITE,
		0,
		ftsize,
		0);

	if (hMap == NULL)
	{
		printf("创建文件映射失败\n");
		return;
	}

	//创建视图
	LPVOID lpmem = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

	if (lpmem == NULL)
	{
		delete[] Sections;
		CloseHandle(hMap);
		printf("创建视图失败\n");
		return;
	}
	PBYTE bpMem = (PBYTE)lpmem;
	memcpy(lpmem, &dos, sizeof(IMAGE_DOS_HEADER));
	//计算dossub 大小

	DWORD subSize = dos.e_lfanew - sizeof(IMAGE_DOS_HEADER);

	if (ReadProcessMemory(m_hProc, (BYTE *)m_lpBaseOfImage + sizeof(IMAGE_DOS_HEADER), bpMem + sizeof(IMAGE_DOS_HEADER), subSize, NULL) == FALSE)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		return;
	}

	nt.OptionalHeader.ImageBase = (DWORD)lpBaseOfImage;
	//保存NT头
	memcpy(bpMem + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS));

	//保存节区
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
		printf("保存到文件失败\n");
		return;
	}
	delete[] Sections;
	CloseHandle(hMap);
	UnmapViewOfFile(lpmem);
	MessageBox(0, L"ok", 0, 0);
	return;
}
bool CExceptionHandle::EnummyModule(DWORD dwPID) {
	// 1. 先创建快照
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);

	// 2. 开始遍历进程
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
		//插入模块
		this->importTableMap.insert(make_pair(mi.modBaseAddr, str));
	} while (Module32NextW(hTool32, &mi));
	return true;
}
//解析pe
void CExceptionHandle::myPE(const char* str)
{
	string st = str;
	DWORD dwFileSize;
	BYTE* g_pFileImageBase = 0;
	//PIMAGE_NT_HEADERS g_pNt = 0;

	DWORD RVAtoFOA(DWORD dwRVA);
	OPENFILENAME stOF;
	HANDLE hFile, hMapFile;
	DWORD totalSize;        //文件大小
	LPVOID lpMemory;        //内存映像文件在内存的起始位置
	char szFileName[MAX_PATH] = { 0 };  //要打开的文件路径及名称名
	char bufTemp1[10];                  //每个字符的十六进制字节码
	char bufTemp2[20];                  //第一列
	char lpServicesBuffer[100];     //一行的所有内容
	char bufDisplay[50];                //第三列ASCII码字符
	DWORD dwCount;                      //计数，逢16则重新计
	DWORD dwCount1;                     //地址顺号
	DWORD dwBlanks;                     //最后一行空格数
	hFile = CreateFileA(str, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
	//如果是无效的句柄
	if (hFile == INVALID_HANDLE_VALUE) {
		
		printf("打开模块失败\n");
		return;
	}
	//获取文件大小
	dwFileSize = GetFileSize(hFile, NULL);
	g_pFileImageBase = new BYTE[dwFileSize]{};
	DWORD dwRead;
	//将文件读取到内存中
	bool bRet = ReadFile(hFile, g_pFileImageBase, dwFileSize, &dwRead, NULL);
	//如果读取失败就返回
	if (!bRet)
	{
		delete[] g_pFileImageBase;
	}
	//关闭句柄
	CloseHandle(hFile);

	//使用PIMAGE_DOS_HEADER（占64字节）解释前64个字节
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_pFileImageBase;
	//判断PE文件的标识是否正确，有一个不对，那么它就不是PE文件
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
	//取第一个区表头
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(g_pNt);

	//	
	DWORD dwExportRVA = g_pNt->OptionalHeader.DataDirectory[0].VirtualAddress;
	//	//获取在文件中的位置
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(this->RVAtoFOA(dwExportRVA) + g_pFileImageBase);
	//	//模块名字
	char* pName = (char*)(this->RVAtoFOA(pExport->Name) + g_pFileImageBase);
	printf("%s\n", pName);
	//地址表中的个数
	DWORD dwCountOfFuntions = pExport->NumberOfFunctions;
	//名称表中的个数
	DWORD dwCountOfNames = pExport->NumberOfNames;
	//地址表地址
	PDWORD pAddrOfFuntion = (PDWORD)(this->RVAtoFOA(pExport->AddressOfFunctions) + g_pFileImageBase);
	//名称表地址
	PDWORD pAddrOfName = (PDWORD)(this->RVAtoFOA(pExport->AddressOfNames) + g_pFileImageBase);
	//序号表地址
	PWORD pAddrOfOrdial = (PWORD)(this->RVAtoFOA(pExport->AddressOfNameOrdinals) + g_pFileImageBase);
	//	//base值
	DWORD dwBase = pExport->Base;
	//	//遍历地址表中的元素
	//	cout << "-----------------------------------------导出表中的导出函数与导出序号-------------------------------------------------- " << endl;
	cout << "导出表中的导出函数与导出序号" << endl;
	if (dwExportRVA == 0) {

		printf("没有导出表\n");

		//return;
	}
	else {
		for (int i = 0; i < dwCountOfFuntions;i++)
		{
			//地址表中可能存在无用的值（就是为0的值）
			if (pAddrOfFuntion[i] == 0)
			{
				continue;
			}
			//根据序号表中是否有值（地址表的下标值），
			//来判断是否是名称导出
			bool bRet = false;
			for (int j = 0; j < dwCountOfNames;j++)
			{
				//i为地址表下标j为序号表的下标（值为地址表下标）
				//判断是否在序号表中
				if (i == pAddrOfOrdial[j])
				{
					//因为序号表与名称表的位置一一对应
					//取出名称表中的名称地址RVA
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
				//序号表中没有，说明是以序号导出的
				printf("%04d          ", i + dwBase);
				//序号表中没有，说明是以序号导出的
				printf("%08X\n", pAddrOfFuntion[i]);
			}

		}
	}
	//	
	//	cout << "-----------------------------------------导入表中的导入函数与导入模块-------------------------------------------------- " << endl;

	//找到导入表  也就是第二个下标为1
	DWORD dwImpotRVA = g_pNt->OptionalHeader.DataDirectory[1].VirtualAddress;
	//在文件中的位置
	DWORD dwImportInFile = (DWORD)(this->RVAtoFOA(dwImpotRVA) + g_pFileImageBase);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)dwImportInFile;
	//遍历每一个导入表  通过最后一个为0作为判断条件
	if (dwImpotRVA == 0) {
		printf("没有导入表\n");

		return;
	}
	else {
		while (pImport->Name)
		{
			//函数名称地址
			PIMAGE_THUNK_DATA pFirsThunk =
				(PIMAGE_THUNK_DATA)(this->RVAtoFOA(pImport->FirstThunk) + g_pFileImageBase);
			//模块名
			char* pName = (char*)(this->RVAtoFOA(pImport->Name) + g_pFileImageBase);

			printf("导入模块名字%s\n", pName);
			//也是通过最后一个为0作为判断条件
			while (pFirsThunk->u1.AddressOfData)
			{
				//判断导入方式
				if (IMAGE_SNAP_BY_ORDINAL32(pFirsThunk->u1.AddressOfData))
				{
					//说明是序号导入(低16位是其序号)
					printf("\t\t%04X \n", pFirsThunk->u1.Ordinal & 0xFFFF);
				}
				else
				{
					//名称导入
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
	//此RVA落在哪个区段中
	//找到所在区段后，
	//减去所在区段的起始位置，加上在文件中的起始位置
	//大文件头中找区段数
	int nCountOfSection = g_pNt->FileHeader.NumberOfSections;
	//区段表头
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(g_pNt);
	//在扩展头中找到块对齐数
	DWORD dwSecAligment = g_pNt->OptionalHeader.SectionAlignment;
	//循环
	for (int i = 0; i < nCountOfSection; i++)
	{
		//求在内存中的真实大小
		//Misc.VirtualSize % dwSecAligment如果是0代表刚好对齐否则就先对齐（非0就是真）
		//Misc.VirtualSize / dwSecAligment * dwSecAligment   + dwSecAligment     //最后加上余数的对齐
		DWORD dwRealVirSize = pSec->Misc.VirtualSize % dwSecAligment ?
			pSec->Misc.VirtualSize / dwSecAligment * dwSecAligment + dwSecAligment
			: pSec->Misc.VirtualSize;
		//区段中的相对虚拟地址转文件偏移  思路是 用要转换的地址与各个区
		//段起始地址做比较如果落在一个区段中（大于起始地址小于起始地址加区段最大偏移和），
		//就用要转换的相对虚拟地址减去区段的起始地址的相对虚拟地址，
		//得到了这个地址相对这个区段偏移，再用得到的这个偏移加上区段在文件中的偏移的起始位置
		//（pointerToRawData字段)就是他在文件中的文件偏移
		if (dwRVA >= pSec->VirtualAddress &&
			dwRVA < pSec->VirtualAddress + dwRealVirSize)
		{
			//FOA = RVA - 内存中区段的起始位置 + 在文件中区段的起始位置 
			return dwRVA - pSec->VirtualAddress + pSec->PointerToRawData;
		}
		//下一个区段地址
		pSec++;
	}
}
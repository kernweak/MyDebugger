#include "stdafx.h"
#include "ExceptionHandle.h"


CExceptionHandle::CExceptionHandle()
{
}
//带传入参数的构造函数
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


	EXCEPTION_RECORD& er = m_dbgEvent.u.Exception.ExceptionRecord;

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		m_dbgEvent.dwProcessId);

	HANDLE hThrad = OpenThread(THREAD_ALL_ACCESS,
		FALSE,
		m_dbgEvent.dwThreadId);
	//异常事件就是系统断点
	printf("\t异常代码：%08X\n", er.ExceptionCode);
	printf("\t异常地址：%08X\n", er.ExceptionAddress);

	switch (m_dbgEvent.u.Exception.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT://触发断点时引发的异常。
							  //  是否有条件断点         临时断点(F8 步过)
		ResetDelAllPoint();;//重置所有断点
		Print((SIZE_T)m_dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);//打印反汇编
		TheContext.Eip--;
		SetThreadContext(m_ProInfo.hThread, &TheContext);
		//等待用户输入  
		//  执行程序 三种情况F7   F5  和F8        
		//      用户输入F7  设置TF 标志位  所有断点不需要恢复 
		//      用户输入 F5 所有断点也不需要恢复
		WaitUserInput();
		break;
		break;
	case EXCEPTION_ACCESS_VIOLATION://内存访问异常
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
	while (1)
	{
		CMyDebuggerFramWork temFramWork;
		temFramWork.m_ProInfo = m_ProInfo;
		char buffer[20] = {};
		char *CmdBuf = nullptr;
		char *NumBuf = nullptr;
		DWORD addr = 0;
		printf("请输入：");
		gets_s(buffer, 20);
		CmdBuf = strtok_s(buffer, " ", &NumBuf);
		sscanf_s(NumBuf, "%x", &addr);
		//单步
		if (strcmp("t", CmdBuf) == 0)//DOF7
		{
			ResetDelAllPoint();
			PEFLAGS  eflag = (PEFLAGS)&TheContext.EFlags;
			eflag->TF = 1;
			SetThreadContext(m_ProInfo.hThread, &TheContext);
			//如果 执行单步 遇到cc 断点   
			//如果 执行单步 遇到 内存断点
			//如果 执行单步 遇到 硬件断点
			return 0;
		}

		//设置断点
		if (strcmp("bp", CmdBuf) == 0)
		{
			temFramWork.SetCcPoint(addr, 0);
		}

		if (strcmp("g", CmdBuf) == 0)
		{
			ResetSetAllPoint();
			//如果当前EIP 在断点列表中则还原原来的代码 让程序跑起来
			temFramWork.ResetDelCcPoint(TheContext.Eip);
			////判断 是怎么停下来的
			//// 单步走下来的    eip==异常地址
			////断点下来的       eip==异常地址-1
			//if ((DWORD)mDebEv.u.Exception.ExceptionRecord.ExceptionAddress == TheContext.Eip)
			//	return 0;

			//设置所有断点
			//返回
			return 0;
		}
		if (strcmp("u", CmdBuf) == 0)//查看反汇编
		{
			Print(addr);
		}
		if (strcmp("h", CmdBuf) == 0|| strcmp("help", CmdBuf) == 0)//查看帮助文档
		{
			PrintCommandHelp(0);
		}
		if (strcmp("r", CmdBuf) == 0)//查看和修改寄存器
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
		printf("bl (显示所有断点信息)\r\n");
		printf("bc (清除所有int3和硬件断点信息)\r\n");
		printf("be (激活一个断点)                断点地址\r\n");
		printf("bd (禁用一个断点)                断点地址\r\n");
		printf("br (移除一个int3断点或硬件断点)  断点地址\r\n");
		printf("bm (添加一个内存断点)            断点地址 长度 权限\r\n");
		printf("by (移除一个内存断点)            断点地址\r\n");
	}

	if (0 == ch)
	{
		printf("t                                单步进入\r\n");
		printf("p                                单步步过\r\n");
		printf("r                                查看修改寄存器\r\n");
		printf("u [目标地址]                     反汇编\r\n");
		printf("? 或  h                          查看帮助\r\n");
		printf("g [目标地址]                     执行到目标地址处\r\n");
		printf("\t如果后面指定地址，中间的断点将全部失效\r\n");
		printf("l                                显示PE信息\r\n");
		printf("d [目标起始地址] [目标终址地址]/[长度] 查看内存\r\n");
		printf("e [目标起始地址]                 修改内存\r\n");
		printf("q                                退出\r\n");
		printf("s 记录范围起始地址 记录范围终止地址 [保存文件名]\r\n");
		printf("o [脚本路径名]                   运行脚本\r\n");

		printf("扩展命令:\r\n");
		printf(".kill                            结束被调试进程\r\n");
		printf(".restart                         重新加载被调试进程(测试)\r\n");
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
BOOL CExceptionHandle::GetCurrentThreadContext(OUT CONTEXT * pContext)
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

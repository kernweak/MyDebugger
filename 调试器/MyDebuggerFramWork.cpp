#include "stdafx.h"
#include "MyDebuggerFramWork.h"
#include"ExceptionHandle.h"


CMyDebuggerFramWork::CMyDebuggerFramWork()
{
}


CMyDebuggerFramWork::~CMyDebuggerFramWork()
{
}


//************************************
// Method:    OpenDebugProcess
// FullName:  CMyDebuggerFramWork::OpenDebugProcess
// Description:创建调试进程
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: TCHAR * pszFile
// Date: 2018/5/7 10:58
// Author : RuiQiYang
//************************************
BOOL CMyDebuggerFramWork::OpenDebugProcess(TCHAR * pszFile)
{
	if (pszFile == nullptr) {
		return FALSE;
	}
	STARTUPINFO stcStartupInfo = { sizeof(STARTUPINFO) };//STARTUPINFO用于指定新进程的主窗口特性的一个结构
											/*创建调试进程*/
	BOOL bRet = FALSE;
	bRet = CreateProcess(pszFile,		//可执行模块的路径
		NULL,			//命令行
		NULL,			//安全描述符
		NULL,			//线程属性是否可继承
		FALSE,			//是否继承了句柄
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,//以调试方式启动
		NULL,			//新进程的环境块
		NULL,			//新进程的当前工作路径（当前目录）
		&stcStartupInfo,//指定主窗口特性
		&m_ProInfo);	//进程信息
	if (bRet)
		return TRUE;
	else
		return FALSE;
}

//************************************
// Method:    StartDebug
// FullName:  CMyDebuggerFramWork::StartDebug
// Description:
// Access:    public 
// Returns:   void
// Qualifier:
// Parameter: TCHAR * pszFile
// Date: 2018/5/7 9:55
// Author : RuiQiYang
//************************************
void CMyDebuggerFramWork::StartDebug()
{
	BOOL isSystemPoint = 0;
	/*建立调试循环*/

	DWORD code = 0;
	CExceptionHandle MyExcept;
	MyExcept.getProcessInfo(m_ProInfo);
	while (1) {
		// 如果被调试进程产生了调试事件， 函数就会
		// 将对应的信息输出到结构体变量中，并从
		// 函数中返回。如果被调试进程没有调试事件，
		// 函数会处于阻塞状态。
		WaitForDebugEvent(&m_dbgEvent, -1);
		code = DBG_CONTINUE;		
		switch (m_dbgEvent.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			if (isSystemPoint) {
				printf("异常事件\n");
				MyExcept.m_hProc = m_hProc;
				MyExcept.m_lpBaseOfImage = m_lpBaseOfImage;
				MyExcept.getDbgEvent(m_dbgEvent);
				code = MyExcept.OnException(m_dbgEvent);
			}
			isSystemPoint = 1;
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			printf("进程创建事件\n");
			printf("\n加载基址：%08X,OEP:%08X\n",
				m_dbgEvent.u.CreateProcessInfo.lpBaseOfImage,
				m_dbgEvent.u.CreateProcessInfo.lpStartAddress);
			m_hProc = m_dbgEvent.u.CreateProcessInfo.hProcess;
			m_lpBaseOfImage = m_dbgEvent.u.CreateProcessInfo.lpBaseOfImage;
			SetOepBreak();
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			printf("线程创建事件\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			printf("进程退出事件\n");
			//goto _EXIT;

		case EXIT_THREAD_DEBUG_EVENT:
			printf("线程退出事件\n");
			break;
		case LOAD_DLL_DEBUG_EVENT:
			printf("DLL加载事件\n");
			printf("\t加载基址：%08X\n",
				m_dbgEvent.u.LoadDll.lpBaseOfDll);
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			printf("DLL卸载事件\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			printf("调试字符串输出事件\n");
			break;
		case RIP_EVENT:
			printf("RIP事件，已经不使用了\n");
			break;
		}
		// 2.1 输出调试信息
		// 2.2 接受用户控制

		// 3. 回复调试子系统
		// 被调试进程产生调试事件之后，会被系统挂起
		// 在调试器回复调试子系统之后，被调试进程才
		// 会运行（回复DBG_CONTINUE才能运行），如果
		// 回复了DBG_CONTINUE，那么被调试的进程的异常
		// 处理机制将无法处理异常。
		// 如果回复了DBG_EXCEPTION_HANDLED： 在异常
		// 分发中，如果是第一次异常处理，异常就被转发到
		// 用户的异常处理机制去处理。如果是第二次，程序
		// 就被结束掉。
		// 一般情况下，处理异常事件之外，都回复DBG_CONTINUE
		// 在异常事件下，根据需求进行不同的回复，原则是：
		// 1. 如果异常是被调试进程自身产生的，那么调试器必须
		//    回复DBG_EXCEPTION_HANDLED，这样做是为了让
		//    被调试进程的异常处理机制处理掉异常。
		// 2. 如果异常是调试器主动制造的(下断点)，那么调试器
		//    需要在去掉异常之后回复DBG_CONTINUE。
		ContinueDebugEvent(m_dbgEvent.dwProcessId,//这是继续执行挂起线程的函数
			m_dbgEvent.dwThreadId,
			code);
	}

}

//************************************
// Method:    SetOepBreak
// FullName:  CMyDebuggerFramWork::SetOepBreak
// Description:在OEP上设置软件断点
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Date: 2018/5/7 11:11
// Author : RuiQiYang
//************************************
BOOL CMyDebuggerFramWork::SetOepBreak()
{
	SetCcPoint((SIZE_T)m_dbgEvent.u.CreateProcessInfo.lpStartAddress, FALSE);
	return 0;
}

//************************************
// Method:    SetCcPoint
// FullName:  CMyDebuggerFramWork::SetCcPoint
// Description:设置软件断点
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: SIZE_T dwAddress
// Parameter: BOOL TempCC
// Date: 2018/5/7 11:13
// Author : RuiQiYang
//************************************
BOOL CMyDebuggerFramWork::SetCcPoint(SIZE_T dwAddress, BOOL TempCC)
{
	BYTE Int3 = 0xcc;
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;
	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, PAGE_READWRITE, &oldProtect);//改变在内核的保护属性。

	if (!ReadProcessMemory(m_ProInfo.hProcess, (LPVOID)dwAddress, &oldbyte, 1, &len)) {//读取内存信息，将原有数据写入oldbyte
		DBGPRINT("读取进程内存失败");
		return FALSE;
	}
	if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)dwAddress, &Int3, 1, &len)){//写入内存信息，将原有位置写入0xCc
		DBGPRINT("写入进程内存失败");
	return false;
}

	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, oldProtect, &oldProtect);

	g_VecCCBp.push_back({ dwAddress ,TempCC,oldbyte});
	return TRUE;
}

//************************************
// Method:    ResetDelCcPoint
// FullName:  CMyDebuggerFramWork::ResetDelCcPoint
// Description:去除CC断点
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: SIZE_T dwAddress
// Date: 2018/5/9 10:25
// Author : RuiQiYang
//************************************
BOOL CMyDebuggerFramWork::ResetDelCcPoint(SIZE_T dwAddress)
{
	BYTE Int3 = 0xcc;
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;
	for (int i = 0; i < g_VecCCBp.size(); i++)
	{
		if (g_VecCCBp[i].dwAddress == dwAddress)
		{
			byte code = g_VecCCBp[i].OldCode;
			VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, PAGE_READWRITE, &oldProtect);

			if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)dwAddress, &code, 1, &len)) return FALSE;

			VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, oldProtect, &oldProtect);

		}
	}
	return 0;
}

//************************************
// Method:    DelCcPoint
// FullName:  CMyDebuggerFramWork::DelCcPoint
// Description:删除CC断点
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: SIZE_T dwAddress
// Parameter: BOOL TempCC
// Date: 2018/5/7 19:22
// Author : RuiQiYang
//************************************
BOOL CMyDebuggerFramWork::DelCcPoint(SIZE_T dwAddress, BOOL TempCC)
{
	BYTE Int3 = 0xcc;
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;
	for (int i = 0;i < g_VecCCBp.size();i++)
	{
		if (g_VecCCBp[i].dwAddress == dwAddress)
		{
			byte code = g_VecCCBp[i].OldCode;
			VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, PAGE_READWRITE, &oldProtect);

			if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)dwAddress, &code, 1, &len)) return FALSE;

			VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, oldProtect, &oldProtect);
			g_VecCCBp.erase(g_VecCCBp.begin() + i);
		}
	}
	return TRUE;
}

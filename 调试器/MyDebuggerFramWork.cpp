#include "stdafx.h"
#include "MyDebuggerFramWork.h"


CMyDebuggerFramWork::CMyDebuggerFramWork()
{
}


CMyDebuggerFramWork::~CMyDebuggerFramWork()
{
}

void CMyDebuggerFramWork::StartDebug(TCHAR * pszFile)
{
	if (pszFile == nullptr) {
		return;
	}
	STARTUPINFO stcStartupInfo = { sizeof(STARTUPINFO) };//STARTUPINFO用于指定新进程的主窗口特性的一个结构
	PROCESS_INFORMATION stcProcInfo = { 0 };//进程信息
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
		&stcProcInfo);
	/*建立调试循环*/
	DEBUG_EVENT dbgEvent = { 0 };
	DWORD code = 0;
	while (1) {
		// 如果被调试进程产生了调试事件， 函数就会
		// 将对应的信息输出到结构体变量中，并从
		// 函数中返回。如果被调试进程没有调试事件，
		// 函数会处于阻塞状态。
		WaitForDebugEvent(&dbgEvent, -1);
		code = DBG_CONTINUE;
		switch (dbgEvent.dwDebugEventCode) {
			
		}
	}

}

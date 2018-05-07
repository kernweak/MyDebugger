#pragma once
#include"initSomeThing.h"
#include "MyDebuggerFramWork.h"
class CExceptionHandle
{
public:
	TheBeaClass m_BEA;
	CExceptionHandle();
	CExceptionHandle(DEBUG_EVENT dbgEvent);
	virtual ~CExceptionHandle();																																																																																																																																																																
	DWORD OnException(DEBUG_EVENT& dbgEvent);
	BOOL getDbgEvent(DEBUG_EVENT dbgEvent);
	BOOL getProcessInfo(PROCESS_INFORMATION mProInfo);//获取进程信息
	BOOL ResetDelAllPoint();//重置所有断点
	BOOL ResetSetAllPoint();//重新加上所有断点
	BOOL Print(SIZE_T dwAddress);//打印反汇编
	BOOL WaitUserInput();//等待用户输入
	void PrintCommandHelp(char ch);//查看帮助
	void PrintContext();//打印信息
	BOOL GetCurrentThreadContext(OUT CONTEXT *pContext);//获取当前线程上下文
private:
	DEBUG_EVENT m_dbgEvent;
	CONTEXT TheContext = { CONTEXT_ALL };
	PROCESS_INFORMATION m_ProInfo;
	BOOL flag = FALSE;// 检查异常是否是调试器安装的断点引发的
	HANDLE m_hThread;
};


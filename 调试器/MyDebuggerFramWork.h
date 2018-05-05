#pragma once
#include"initSomeThing.h"
class CMyDebuggerFramWork
{
public:
	CMyDebuggerFramWork();
	virtual ~CMyDebuggerFramWork();
public:
	void StartDebug(TCHAR* pszFile);//接收调试事件，开始调试进程
};


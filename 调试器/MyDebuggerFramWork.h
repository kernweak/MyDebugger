#pragma once
#include"initSomeThing.h"
class CMyDebuggerFramWork
{
public:
	CMyDebuggerFramWork();
	virtual ~CMyDebuggerFramWork();
public:
	BOOL OpenDebugProcess(TCHAR* pszFile);//创建调试进程
	void StartDebug();//接收调试事件，开始调试进程
	BOOL SetOepBreak();//在OEP上设置软件断点
	BOOL SetCcPoint(SIZE_T dwAddress, BOOL TempCC);//设置软件断点
	BOOL ResetDelCcPoint(SIZE_T dwAddress);//去除CC断点
	BOOL DelCcPoint(SIZE_T dwAddress, BOOL TempCC);//删除CC断点
	
public:
	DEBUG_EVENT m_dbgEvent = { 0 };
	//vector<CCBPINFO>m_VecCCBp; //软件断点数组
	PROCESS_INFORMATION m_ProInfo = {};//进程信息
};


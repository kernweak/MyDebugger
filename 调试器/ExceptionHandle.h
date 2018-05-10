#pragma once
#include"initSomeThing.h"
#include "MyDebuggerFramWork.h"
#define BUFFER_MAX      128
#define MEMPAGE_LEN     4
#include <Winternl.h>

class CExceptionHandle
{
public:
	typedef	struct _MemoryBreakType
	{
		DWORD   newType;
		DWORD   oldType;
		SIZE_T nLen;
		bool bo;
	}MemoryBreakType;
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
	BOOL ShowMemoryData(char* pszCmd);//打印内存信息
	BOOL EditMemoryData();//修改内存信息
	int DisplayDestProcessMemory(LPVOID pAddr,int nLen);//显示调试进程目标内存数据
	int IsEffectiveAddress(IN LPVOID lpAddr, IN PMEMORY_BASIC_INFORMATION pMbi);//判断是否是有效地址



	BOOL WaitUserInput();//等待用户输入




	void PrintCommandHelp(char ch);//查看帮助
	void PrintContext();//打印信息
	void PrintStack();//查看栈信息
	BOOL GetCurrentThreadContext(CONTEXT *pContext);//获取当前线程上下文
	BOOL SetCurrentThreadContext(CONTEXT *pContext);//设置当前线程上下文
	int EditRegisterValue(char* pszCmd);//修改寄存器的值
	BOOL Editasm(SIZE_T dwAddress);//修改汇编数据
	int GetCurrentEip(DWORD dwThreadId);//获取Eip
	BOOL GetCurrentModules(list<DLLNODE>& DllList, HANDLE hProcess, DEBUG_EVENT DebugEvent);//获取当前程序所有模块
	BOOL ShowMod();//显示模块
	int ParseSingleSetp();//处理单步
	VOID PrintInstruction(int Eip,BOOL bContinue,int nItem);   // 输出指令
	int Ucommand(char *pszCmd, BOOL bISContinue);//处理U命令
	int ParseBCommand(char *pszCmd);//断点相关命令

	bool setBreakpoint_hardExec(HANDLE hThread, ULONG_PTR uAddress);//设置硬件执行断点
	BOOL setBreakpoint_hardRW(HANDLE hThread, ULONG_PTR uAddress, int type, DWORD dwLen);//设置硬件读写断点
	BOOL setConditPoint(HANDLE hThread, ULONG_PTR uAddress, int type, DWORD dwLen);//设置条件断点断点
	void dump(char* str);
	//////
	//设置内存断点
	int AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview);
	//移除内存断点
	int RemoveMemoryBreak(LPVOID nAddr);
	//判断在不在map里
	DWORD beinset(LPVOID  addr, DWORD dw);
	//内存断点
	void Setmm();
	void huanyabread(LPVOID lpAddr);

	void setAllBreakpoint(HANDLE hProc);
	//设置除当前外的其它断点
	void setAllBreakpointOther(HANDLE hProc);

	void AADebug(HANDLE hDebugProcess);
	
	HANDLE m_hProc;
	LPVOID m_lpBaseOfImage;
private:
	BOOL m_nIsTCommand; // 之前是否是T命令
	DEBUG_EVENT m_dbgEvent;
	CONTEXT TheContext = { CONTEXT_ALL };
	PROCESS_INFORMATION m_ProInfo;
	BOOL flag = FALSE;// 检查异常是否是调试器安装的断点引发的
	HANDLE m_hThread;
	char opcode[100] = { };
	DWORD	m_dwShowDataAddr = 0;//数据连续显示地址
	list<DLLNODE> m_DllList;//模块链表
	bool isGo=0;
	HANDLE theThread;
	CONTEXT Thect = { 0 };
	DWORD  m_pDR6=0;
	HANDLE hProc;
	
	//
	//  获取输出流的句柄
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	//内存断点保存  地址，new属性  old属性
	map<LPVOID, MemoryBreakType> Memorymap;
	FARPROC myfun;
	LPVOID lpBaseOfImage;//加载基址
};


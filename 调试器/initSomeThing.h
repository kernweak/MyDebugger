#pragma once
#include "stdafx.h"
#include<Windows.h>
#include<stdio.h>
#include "RegStruct.h"
#include <vector>
#include<string>
#include <map>
#include <list>
#include <TlHelp32.h>
#include"Tool.h"
using namespace std;
// 包含反汇编引擎的头文件和库文件
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include "BeaEngine_4.1/Win32/headers/BeaEngine.h"
#include "XEDParse/XEDParse.h"
#pragma comment(lib,"BeaEngine_4.1\\Win32\\Win32\\Lib\\BeaEngine.lib")
#pragma comment(lib,"legacy_stdio_definitions.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")
extern BOOL g_isUserTf;

#ifdef _WIN64
#pragma comment (lib,"XEDParse\\x64\\XEDParse_x64.lib")
#else
#pragma comment (lib,"XEDParse\\x86\\XEDParse_x86.lib")
#endif // _WIN64


#define DBGPRINT(error)  \
		printf("文件：%s中函数：%s 第%d行，错误：%s\n",\
			__FILE__,\
			__FUNCTION__,\
			__LINE__,\
			error);

typedef struct _BPINFO
{
	DWORD dwAddress; // 断点地址
	BOOL bOnce;		 // 一次性断点
	BYTE OldCode;

}CCBPINFO, *PCCBPINFO;


//内存、硬件断点属性
//内存、硬件断点节点
typedef struct {
	DWORD       dwBpOrder;		//断点序号
	BOOL        isActive;       //是否有效
	BOOL		isResume;		//是否需要恢复针对硬件断点
	DWORD      lpBpAddr;		//断点地址
	int		enuBpRWE;		//断点读、写、执行属性
	DWORD       dwBpLen;		//断点长度
								//    DWORD       dwNewProtect;   //新的内存页属性
	DWORD		dwOldProtect;   //之前的内存页属性
}BPNODE, *PBPNODE;

extern vector<BPNODE> g_HardBp;

extern vector<CCBPINFO> g_VecCCBp;

class TheBeaClass
{
public:
	TheBeaClass();
	~TheBeaClass();
	void UseBea(char*opcode, DISASM disAsm);
};


//模块节点结构
typedef struct {
	DWORD		dwModBase;
	DWORD		dwModSize;
	DWORD		dwModEntry;
	WCHAR*		szModName;
	WCHAR*		szModPath;
}DLLNODE, *PDLLNODE;
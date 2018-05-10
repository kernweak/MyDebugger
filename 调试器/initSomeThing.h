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
// ��������������ͷ�ļ��Ϳ��ļ�
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
		printf("�ļ���%s�к�����%s ��%d�У�����%s\n",\
			__FILE__,\
			__FUNCTION__,\
			__LINE__,\
			error);

typedef struct _BPINFO
{
	DWORD dwAddress; // �ϵ��ַ
	BOOL bOnce;		 // һ���Զϵ�
	BYTE OldCode;

}CCBPINFO, *PCCBPINFO;


//�ڴ桢Ӳ���ϵ�����
//�ڴ桢Ӳ���ϵ�ڵ�
typedef struct {
	DWORD       dwBpOrder;		//�ϵ����
	BOOL        isActive;       //�Ƿ���Ч
	BOOL		isResume;		//�Ƿ���Ҫ�ָ����Ӳ���ϵ�
	DWORD      lpBpAddr;		//�ϵ��ַ
	int		enuBpRWE;		//�ϵ����д��ִ������
	DWORD       dwBpLen;		//�ϵ㳤��
								//    DWORD       dwNewProtect;   //�µ��ڴ�ҳ����
	DWORD		dwOldProtect;   //֮ǰ���ڴ�ҳ����
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


//ģ��ڵ�ṹ
typedef struct {
	DWORD		dwModBase;
	DWORD		dwModSize;
	DWORD		dwModEntry;
	WCHAR*		szModName;
	WCHAR*		szModPath;
}DLLNODE, *PDLLNODE;
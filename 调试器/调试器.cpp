// 调试器.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "MyDebuggerFramWork.h"
#include <conio.h>
#define CHAR_TO_WCHAR(lpChar,lpW_Char)  MultiByteToWideChar(CP_ACP,NULL,lpChar,-1,lpW_Char,_countof(lpW_Char));
int main()
{
	printf("请输入程序打开模式，1为直接拖拽，2为附加活动进程\n");
	char szFileName[MAX_PATH]{};
	int a = 0;
	scanf_s("%d", &a);
	getchar();
	if (a == 1) {
		printf("选择直接拖拽文件,请拖拽文件");
		while (1)
		{
			if (_kbhit())
			{
				INPUT_RECORD e;
				DWORD d = 0;
				BOOL b = WriteConsoleInput(GetStdHandle(STD_INPUT_HANDLE), &e, sizeof(INPUT_RECORD), &d);
				gets_s(szFileName);
				break;
			}
			Sleep(1);
		}
	}
	else if(a == 2) {
		printf("选择附加进程，");

		printf("请输入进程的ID：\n");
		int nPid = 0;
		scanf_s("%d", &nPid);


		if (!AddPrivilege(GetCurrentProcess(), SE_DEBUG_NAME/*字符串形式的权限名*/)) {
			printf("提升权限失败\n");
			system("pause");
			return 0;
		}

		if (!DebugActiveProcess(nPid))
		{
			DBGPRINT("附加进程失败")
				return FALSE;
		}
	}
	
	
	
	system("cls");
	WCHAR wszFileName[MAX_PATH]{};
	CHAR_TO_WCHAR(szFileName, wszFileName)
	CMyDebuggerFramWork temp1;
	temp1.OpenDebugProcess(wszFileName);
	temp1.StartDebug();
    return 0;
}


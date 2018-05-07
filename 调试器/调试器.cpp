// 调试器.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "MyDebuggerFramWork.h"
#include <conio.h>
#define CHAR_TO_WCHAR(lpChar,lpW_Char)  MultiByteToWideChar(CP_ACP,NULL,lpChar,-1,lpW_Char,_countof(lpW_Char));
int main()
{
	printf("------>Debug:");
	char szFileName[MAX_PATH]{};
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
	system("cls");
	WCHAR wszFileName[MAX_PATH]{};
	CHAR_TO_WCHAR(szFileName, wszFileName)
	CMyDebuggerFramWork temp1;
	temp1.OpenDebugProcess(wszFileName);
	temp1.StartDebug();
    return 0;
}


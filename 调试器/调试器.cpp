// ������.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "MyDebuggerFramWork.h"
#include <conio.h>
#define CHAR_TO_WCHAR(lpChar,lpW_Char)  MultiByteToWideChar(CP_ACP,NULL,lpChar,-1,lpW_Char,_countof(lpW_Char));
int main()
{
	printf("����������ģʽ��1Ϊֱ����ק��2Ϊ���ӻ����\n");
	char szFileName[MAX_PATH]{};
	int a = 0;
	scanf_s("%d", &a);
	getchar();
	if (a == 1) {
		printf("ѡ��ֱ����ק�ļ�,����ק�ļ�");
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
		printf("ѡ�񸽼ӽ��̣�");

		printf("��������̵�ID��\n");
		int nPid = 0;
		scanf_s("%d", &nPid);


		if (!AddPrivilege(GetCurrentProcess(), SE_DEBUG_NAME/*�ַ�����ʽ��Ȩ����*/)) {
			printf("����Ȩ��ʧ��\n");
			system("pause");
			return 0;
		}

		if (!DebugActiveProcess(nPid))
		{
			DBGPRINT("���ӽ���ʧ��")
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


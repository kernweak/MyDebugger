#include "stdafx.h"
#include "Tool.h"

//************************************
// Method:    GetParamCount
// FullName:  GetParamCount
// Description:ȡ�ò����ĸ���
// Access:    public 
// Returns:   int
// Qualifier:
// Parameter: char * pszCmd
// Date: 2018/5/7 21:03
// Author : RuiQiYang
//************************************
int GetParamCount(char * pszCmd)
{
	if (NULL == pszCmd)
	{
		return 0;
	}
	int nCount = 1;
	BOOL bIsHaving = FALSE;
	for (; 0 != *pszCmd; ++pszCmd)
	{
		if ((' ' == *pszCmd))
		{
			if (FALSE == bIsHaving)
			{
				++nCount;
				bIsHaving = TRUE;
			}
		}
		else
		{
			bIsHaving = FALSE;
		}
	}
	return nCount;
}

//************************************
// Method:    SafeInput
// FullName:  SafeInput
// Description:��������м��
// Access:    public 
// Returns:   int
// Qualifier:
// Parameter: char * szBuffer
// Parameter: int nSize
// Date: 2018/5/8 8:43
// Author : RuiQiYang
//************************************
int SafeInput(char * szBuffer, int nSize)
{
	int i;
	char ch = ' ';

	if (szBuffer == NULL || nSize < 1)
	{
		return 0;
	}

	fflush(stdin);
	memset(szBuffer, 0, sizeof(char) * nSize);
	for (i = 0; i < nSize - 1 && ch != '\n'; ++i)
	{
		ch = getc(stdin);
		if (ch != '\n')
		{
			szBuffer[i] = ch;
		}
	}
	szBuffer[i] = 0;
	fflush(stdin);
	return i;
}

//************************************
// Method:    SafeHexInput
// FullName:  SafeHexInput
// Description:��ȫ����ʮ��������
// Access:    public 
// Returns:   int
// Qualifier:
// Parameter: char * szBuffer
// Parameter: int nSize
// Date: 2018/5/8 9:01
// Author : RuiQiYang
//************************************
int SafeHexInput(char * szBuffer, int nSize)
{
	int i;
	char ch = ' ';

	if (szBuffer == NULL || nSize < 1)
	{
		return 0;
	}

	fflush(stdin);
	memset(szBuffer, 0, sizeof(char) * nSize);
	int j = 0;
	for (i = 0; i < nSize - 1 && ch != '\n'; ++i)
	{
		ch = getc(stdin);
		if (ch != '\n' && isxdigit(ch))
		{
			szBuffer[j] = ch;
			j++;
		}
	}
	szBuffer[j] = '\n';
	fflush(stdin);
	return i;
}

//************************************
// Method:    printOpcode
// FullName:  printOpcode
// Description:��ӡ�����
// Access:    public 
// Returns:   void
// Qualifier:
// Parameter: const unsigned char * pOpcode
// Parameter: int nSize
// Date: 2018/5/8 14:43
// Author : RuiQiYang
//************************************
void printOpcode(const unsigned char * pOpcode, int nSize)
{
	for (int i = 0; i < nSize; ++i)
	{
		printf("%02X ", pOpcode[i]);
	}
}

//************************************
// Method:    AddPrivilege
// FullName:  AddPrivilege
// Description:��������Ӷ�Ӧ��Ȩ��
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: HANDLE hProcess
// Parameter: const TCHAR * pszPrivilegeName
// Date: 2018/5/9 9:22
// Author : RuiQiYang
//************************************
BOOL AddPrivilege(HANDLE hProcess, const TCHAR * pszPrivilegeName)
{
	// ���̵���Ȩʹ��LUIDֵ����ʾ, ���, ��Ҫ�Ȼ�ȡ�����Ȩ������Ӧ��LUIDֵ


	// 0. ��ȡ��Ȩ��Ӧ��LUIDֵ
	LUID privilegeLuid;
	if (!LookupPrivilegeValue(NULL, pszPrivilegeName, &privilegeLuid))
		return FALSE;


	// 1. ��ȡ����������
	HANDLE hToken = NULL;
	// ������ʱ, ��Ҫ����TOKEN_ADJUST_PRIVILEGES Ȩ��(���Ȩ�������޸�������Ȩ)
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("������:%x\n", GetLastError());
		return 0;
	}

	// 2. ʹ��������Ȩ�޸ĺ�����SeDebug��LUID��Ȩֵ��ӵ�����������
	TOKEN_PRIVILEGES tokenPrivieges; // �µ���Ȩ

									 // ʹ����Ȩ��LUID����ʼ���ṹ��.
	tokenPrivieges.PrivilegeCount = 1; // ��Ȩ����
	tokenPrivieges.Privileges[0].Luid = privilegeLuid; // ����ȨLUID���浽������
	tokenPrivieges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;// ������ֵ��Ϊ����(�н���,�Ƴ�������״̬)



																   // ���ú��������Ȩ
	return AdjustTokenPrivileges(hToken,              // Ҫ�����Ȩ������
		FALSE,               // TRUE���Ƴ���Ȩ, FALSE�������Ȩ
		&tokenPrivieges,     // Ҫ��ӵ���Ȩ����
		sizeof(tokenPrivieges),// ������Ȩ����Ĵ�С
		NULL,                // �ɵ���Ȩ����
		NULL                  // �ɵ���Ȩ����ĳ���
	);
}

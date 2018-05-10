#include "stdafx.h"
#include "Tool.h"

//************************************
// Method:    GetParamCount
// FullName:  GetParamCount
// Description:取得参数的个数
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
// Description:对输入进行检测
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
// Description:安全输入十六进制数
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
// Description:打印反汇编
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
// Description:给进程添加对应的权限
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
	// 进程的特权使用LUID值来表示, 因此, 需要先获取传入的权限名对应的LUID值


	// 0. 获取特权对应的LUID值
	LUID privilegeLuid;
	if (!LookupPrivilegeValue(NULL, pszPrivilegeName, &privilegeLuid))
		return FALSE;


	// 1. 获取本进程令牌
	HANDLE hToken = NULL;
	// 打开令牌时, 需要加上TOKEN_ADJUST_PRIVILEGES 权限(这个权限用于修改令牌特权)
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("错误码:%x\n", GetLastError());
		return 0;
	}

	// 2. 使用令牌特权修改函数将SeDebug的LUID特权值添加到本进程令牌
	TOKEN_PRIVILEGES tokenPrivieges; // 新的特权

									 // 使用特权的LUID来初始化结构体.
	tokenPrivieges.PrivilegeCount = 1; // 特权个数
	tokenPrivieges.Privileges[0].Luid = privilegeLuid; // 将特权LUID保存到数组中
	tokenPrivieges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;// 将属性值设为启用(有禁用,移除等其他状态)



																   // 调用函数添加特权
	return AdjustTokenPrivileges(hToken,              // 要添加特权的令牌
		FALSE,               // TRUE是移除特权, FALSE是添加特权
		&tokenPrivieges,     // 要添加的特权数组
		sizeof(tokenPrivieges),// 整个特权数组的大小
		NULL,                // 旧的特权数组
		NULL                  // 旧的特权数组的长度
	);
}

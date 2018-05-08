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
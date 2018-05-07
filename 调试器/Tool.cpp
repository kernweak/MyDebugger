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

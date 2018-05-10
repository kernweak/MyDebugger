#pragma once


#include <io.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
#include <iostream>
#include <shlobj.h>
int GetParamCount(char *pszCmd);// 取得参数的个数

int SafeInput(char *szBuffer,int nSize);//对输入进行检测

int SafeHexInput(char *szBuffer,int nSize);//安全输入十六进制


void printOpcode(const unsigned char* pOpcode, int nSize);//打印反汇编；

BOOL AddPrivilege(HANDLE hProcess, const TCHAR* pszPrivilegeName);//给进程添加对应的权限
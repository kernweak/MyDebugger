#pragma once


#include <io.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
#include <iostream>
#include <shlobj.h>
int GetParamCount(char *pszCmd);// ȡ�ò����ĸ���

int SafeInput(char *szBuffer,int nSize);//��������м��

int SafeHexInput(char *szBuffer,int nSize);//��ȫ����ʮ������


void printOpcode(const unsigned char* pOpcode, int nSize);//��ӡ����ࣻ

BOOL AddPrivilege(HANDLE hProcess, const TCHAR* pszPrivilegeName);//��������Ӷ�Ӧ��Ȩ��
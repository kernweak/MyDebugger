#pragma once
#include"initSomeThing.h"
#include "MyDebuggerFramWork.h"
#define BUFFER_MAX      128
#define MEMPAGE_LEN     4

class CExceptionHandle
{
public:
	TheBeaClass m_BEA;
	CExceptionHandle();
	CExceptionHandle(DEBUG_EVENT dbgEvent);
	virtual ~CExceptionHandle();																																																																																																																																																																
	DWORD OnException(DEBUG_EVENT& dbgEvent);
	BOOL getDbgEvent(DEBUG_EVENT dbgEvent);
	BOOL getProcessInfo(PROCESS_INFORMATION mProInfo);//��ȡ������Ϣ
	BOOL ResetDelAllPoint();//�������жϵ�
	BOOL ResetSetAllPoint();//���¼������жϵ�
	BOOL Print(SIZE_T dwAddress);//��ӡ�����
	BOOL WaitUserInput();//�ȴ��û�����
	void PrintCommandHelp(char ch);//�鿴����
	void PrintContext();//��ӡ��Ϣ
	void PrintStack();//�鿴ջ��Ϣ
	BOOL GetCurrentThreadContext(CONTEXT *pContext);//��ȡ��ǰ�߳�������
	BOOL SetCurrentThreadContext(CONTEXT *pContext);//���õ�ǰ�߳�������
	int EditRegisterValue(char* pszCmd);//�޸ļĴ�����ֵ
	BOOL Editasm(SIZE_T dwAddress);//�޸Ļ������
private:
	DEBUG_EVENT m_dbgEvent;
	CONTEXT TheContext = { CONTEXT_ALL };
	PROCESS_INFORMATION m_ProInfo;
	BOOL flag = FALSE;// ����쳣�Ƿ��ǵ�������װ�Ķϵ�������
	HANDLE m_hThread;
	char opcode[100] = { };
};


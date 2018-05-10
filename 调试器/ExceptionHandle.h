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
	BOOL ShowMemoryData(char* pszCmd);//��ӡ�ڴ���Ϣ
	BOOL EditMemoryData();//�޸��ڴ���Ϣ
	int DisplayDestProcessMemory(LPVOID pAddr,int nLen);//��ʾ���Խ���Ŀ���ڴ�����
	int IsEffectiveAddress(IN LPVOID lpAddr, IN PMEMORY_BASIC_INFORMATION pMbi);//�ж��Ƿ�����Ч��ַ
	BOOL WaitUserInput();//�ȴ��û�����
	void PrintCommandHelp(char ch);//�鿴����
	void PrintContext();//��ӡ��Ϣ
	void PrintStack();//�鿴ջ��Ϣ
	BOOL GetCurrentThreadContext(CONTEXT *pContext);//��ȡ��ǰ�߳�������
	BOOL SetCurrentThreadContext(CONTEXT *pContext);//���õ�ǰ�߳�������
	int EditRegisterValue(char* pszCmd);//�޸ļĴ�����ֵ
	BOOL Editasm(SIZE_T dwAddress);//�޸Ļ������
	int GetCurrentEip(DWORD dwThreadId);//��ȡEip
	BOOL GetCurrentModules(list<DLLNODE>& DllList, HANDLE hProcess, DEBUG_EVENT DebugEvent);//��ȡ��ǰ��������ģ��
	BOOL ShowMod();//��ʾģ��
	int ParseSingleSetp();//������
	VOID PrintInstruction(int Eip,BOOL bContinue,int nItem);   // ���ָ��
	int Ucommand(char *pszCmd, BOOL bISContinue);//����U����
	int ParseBCommand(char *pszCmd);//�ϵ��������

	bool setBreakpoint_hardExec(HANDLE hThread, ULONG_PTR uAddress);//����Ӳ��ִ�жϵ�
	BOOL setBreakpoint_hardRW(HANDLE hThread, ULONG_PTR uAddress, int type, DWORD dwLen);//����Ӳ����д�ϵ�

private:
	BOOL m_nIsTCommand; // ֮ǰ�Ƿ���T����
	DEBUG_EVENT m_dbgEvent;
	CONTEXT TheContext = { CONTEXT_ALL };
	PROCESS_INFORMATION m_ProInfo;
	BOOL flag = FALSE;// ����쳣�Ƿ��ǵ�������װ�Ķϵ�������
	HANDLE m_hThread;
	char opcode[100] = { };
	DWORD	m_dwShowDataAddr = 0;//����������ʾ��ַ
	list<DLLNODE> m_DllList;//ģ������
	bool isGo=0;
	HANDLE theThread;
	CONTEXT Thect = { 0 };
	DWORD  m_pDR6=0;
};


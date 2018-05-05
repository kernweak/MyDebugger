#include "stdafx.h"
#include "MyDebuggerFramWork.h"


CMyDebuggerFramWork::CMyDebuggerFramWork()
{
}


CMyDebuggerFramWork::~CMyDebuggerFramWork()
{
}

void CMyDebuggerFramWork::StartDebug(TCHAR * pszFile)
{
	if (pszFile == nullptr) {
		return;
	}
	STARTUPINFO stcStartupInfo = { sizeof(STARTUPINFO) };//STARTUPINFO����ָ���½��̵����������Ե�һ���ṹ
	PROCESS_INFORMATION stcProcInfo = { 0 };//������Ϣ
	/*�������Խ���*/
	BOOL bRet = FALSE;
	bRet = CreateProcess(pszFile,		//��ִ��ģ���·��
		NULL,			//������
		NULL,			//��ȫ������
		NULL,			//�߳������Ƿ�ɼ̳�
		FALSE,			//�Ƿ�̳��˾��
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,//�Ե��Է�ʽ����
		NULL,			//�½��̵Ļ�����
		NULL,			//�½��̵ĵ�ǰ����·������ǰĿ¼��
		&stcStartupInfo,//ָ������������
		&stcProcInfo);
	/*��������ѭ��*/
	DEBUG_EVENT dbgEvent = { 0 };
	DWORD code = 0;
	while (1) {
		// ��������Խ��̲����˵����¼��� �����ͻ�
		// ����Ӧ����Ϣ������ṹ������У�����
		// �����з��ء���������Խ���û�е����¼���
		// �����ᴦ������״̬��
		WaitForDebugEvent(&dbgEvent, -1);
		code = DBG_CONTINUE;
		switch (dbgEvent.dwDebugEventCode) {
			
		}
	}

}

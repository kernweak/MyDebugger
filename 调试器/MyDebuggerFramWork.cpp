#include "stdafx.h"
#include "MyDebuggerFramWork.h"
#include"ExceptionHandle.h"


CMyDebuggerFramWork::CMyDebuggerFramWork()
{
}


CMyDebuggerFramWork::~CMyDebuggerFramWork()
{
}


//************************************
// Method:    OpenDebugProcess
// FullName:  CMyDebuggerFramWork::OpenDebugProcess
// Description:�������Խ���
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: TCHAR * pszFile
// Date: 2018/5/7 10:58
// Author : RuiQiYang
//************************************
BOOL CMyDebuggerFramWork::OpenDebugProcess(TCHAR * pszFile)
{
	if (pszFile == nullptr) {
		return FALSE;
	}
	STARTUPINFO stcStartupInfo = { sizeof(STARTUPINFO) };//STARTUPINFO����ָ���½��̵����������Ե�һ���ṹ
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
		&m_ProInfo);	//������Ϣ
	if (bRet)
		return TRUE;
	else
		return FALSE;
}

//************************************
// Method:    StartDebug
// FullName:  CMyDebuggerFramWork::StartDebug
// Description:
// Access:    public 
// Returns:   void
// Qualifier:
// Parameter: TCHAR * pszFile
// Date: 2018/5/7 9:55
// Author : RuiQiYang
//************************************
void CMyDebuggerFramWork::StartDebug()
{
	BOOL isSystemPoint = 0;
	/*��������ѭ��*/

	DWORD code = 0;
	CExceptionHandle MyExcept;
	MyExcept.getProcessInfo(m_ProInfo);
	while (1) {
		// ��������Խ��̲����˵����¼��� �����ͻ�
		// ����Ӧ����Ϣ������ṹ������У�����
		// �����з��ء���������Խ���û�е����¼���
		// �����ᴦ������״̬��
		WaitForDebugEvent(&m_dbgEvent, -1);
		code = DBG_CONTINUE;		
		switch (m_dbgEvent.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			if (isSystemPoint) {
				printf("�쳣�¼�\n");
				MyExcept.m_hProc = m_hProc;
				MyExcept.m_lpBaseOfImage = m_lpBaseOfImage;
				MyExcept.getDbgEvent(m_dbgEvent);
				code = MyExcept.OnException(m_dbgEvent);
			}
			isSystemPoint = 1;
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			printf("���̴����¼�\n");
			printf("\n���ػ�ַ��%08X,OEP:%08X\n",
				m_dbgEvent.u.CreateProcessInfo.lpBaseOfImage,
				m_dbgEvent.u.CreateProcessInfo.lpStartAddress);
			m_hProc = m_dbgEvent.u.CreateProcessInfo.hProcess;
			m_lpBaseOfImage = m_dbgEvent.u.CreateProcessInfo.lpBaseOfImage;
			SetOepBreak();
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			printf("�̴߳����¼�\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			printf("�����˳��¼�\n");
			//goto _EXIT;

		case EXIT_THREAD_DEBUG_EVENT:
			printf("�߳��˳��¼�\n");
			break;
		case LOAD_DLL_DEBUG_EVENT:
			printf("DLL�����¼�\n");
			printf("\t���ػ�ַ��%08X\n",
				m_dbgEvent.u.LoadDll.lpBaseOfDll);
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			printf("DLLж���¼�\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			printf("�����ַ�������¼�\n");
			break;
		case RIP_EVENT:
			printf("RIP�¼����Ѿ���ʹ����\n");
			break;
		}
		// 2.1 ���������Ϣ
		// 2.2 �����û�����

		// 3. �ظ�������ϵͳ
		// �����Խ��̲��������¼�֮�󣬻ᱻϵͳ����
		// �ڵ������ظ�������ϵͳ֮�󣬱����Խ��̲�
		// �����У��ظ�DBG_CONTINUE�������У������
		// �ظ���DBG_CONTINUE����ô�����ԵĽ��̵��쳣
		// ������ƽ��޷������쳣��
		// ����ظ���DBG_EXCEPTION_HANDLED�� ���쳣
		// �ַ��У�����ǵ�һ���쳣�����쳣�ͱ�ת����
		// �û����쳣�������ȥ��������ǵڶ��Σ�����
		// �ͱ���������
		// һ������£������쳣�¼�֮�⣬���ظ�DBG_CONTINUE
		// ���쳣�¼��£�����������в�ͬ�Ļظ���ԭ���ǣ�
		// 1. ����쳣�Ǳ����Խ�����������ģ���ô����������
		//    �ظ�DBG_EXCEPTION_HANDLED����������Ϊ����
		//    �����Խ��̵��쳣������ƴ�����쳣��
		// 2. ����쳣�ǵ��������������(�¶ϵ�)����ô������
		//    ��Ҫ��ȥ���쳣֮��ظ�DBG_CONTINUE��
		ContinueDebugEvent(m_dbgEvent.dwProcessId,//���Ǽ���ִ�й����̵߳ĺ���
			m_dbgEvent.dwThreadId,
			code);
	}

}

//************************************
// Method:    SetOepBreak
// FullName:  CMyDebuggerFramWork::SetOepBreak
// Description:��OEP����������ϵ�
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Date: 2018/5/7 11:11
// Author : RuiQiYang
//************************************
BOOL CMyDebuggerFramWork::SetOepBreak()
{
	SetCcPoint((SIZE_T)m_dbgEvent.u.CreateProcessInfo.lpStartAddress, FALSE);
	return 0;
}

//************************************
// Method:    SetCcPoint
// FullName:  CMyDebuggerFramWork::SetCcPoint
// Description:��������ϵ�
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: SIZE_T dwAddress
// Parameter: BOOL TempCC
// Date: 2018/5/7 11:13
// Author : RuiQiYang
//************************************
BOOL CMyDebuggerFramWork::SetCcPoint(SIZE_T dwAddress, BOOL TempCC)
{
	BYTE Int3 = 0xcc;
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;
	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, PAGE_READWRITE, &oldProtect);//�ı����ں˵ı������ԡ�

	if (!ReadProcessMemory(m_ProInfo.hProcess, (LPVOID)dwAddress, &oldbyte, 1, &len)) {//��ȡ�ڴ���Ϣ����ԭ������д��oldbyte
		DBGPRINT("��ȡ�����ڴ�ʧ��");
		return FALSE;
	}
	if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)dwAddress, &Int3, 1, &len)){//д���ڴ���Ϣ����ԭ��λ��д��0xCc
		DBGPRINT("д������ڴ�ʧ��");
	return false;
}

	VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, oldProtect, &oldProtect);

	g_VecCCBp.push_back({ dwAddress ,TempCC,oldbyte});
	return TRUE;
}

//************************************
// Method:    ResetDelCcPoint
// FullName:  CMyDebuggerFramWork::ResetDelCcPoint
// Description:ȥ��CC�ϵ�
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: SIZE_T dwAddress
// Date: 2018/5/9 10:25
// Author : RuiQiYang
//************************************
BOOL CMyDebuggerFramWork::ResetDelCcPoint(SIZE_T dwAddress)
{
	BYTE Int3 = 0xcc;
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;
	for (int i = 0; i < g_VecCCBp.size(); i++)
	{
		if (g_VecCCBp[i].dwAddress == dwAddress)
		{
			byte code = g_VecCCBp[i].OldCode;
			VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, PAGE_READWRITE, &oldProtect);

			if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)dwAddress, &code, 1, &len)) return FALSE;

			VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, oldProtect, &oldProtect);

		}
	}
	return 0;
}

//************************************
// Method:    DelCcPoint
// FullName:  CMyDebuggerFramWork::DelCcPoint
// Description:ɾ��CC�ϵ�
// Access:    public 
// Returns:   BOOL
// Qualifier:
// Parameter: SIZE_T dwAddress
// Parameter: BOOL TempCC
// Date: 2018/5/7 19:22
// Author : RuiQiYang
//************************************
BOOL CMyDebuggerFramWork::DelCcPoint(SIZE_T dwAddress, BOOL TempCC)
{
	BYTE Int3 = 0xcc;
	BYTE oldbyte;
	DWORD oldProtect;
	DWORD len;
	for (int i = 0;i < g_VecCCBp.size();i++)
	{
		if (g_VecCCBp[i].dwAddress == dwAddress)
		{
			byte code = g_VecCCBp[i].OldCode;
			VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, PAGE_READWRITE, &oldProtect);

			if (!WriteProcessMemory(m_ProInfo.hProcess, (LPVOID)dwAddress, &code, 1, &len)) return FALSE;

			VirtualProtectEx(m_ProInfo.hProcess, (LPVOID)dwAddress, 1, oldProtect, &oldProtect);
			g_VecCCBp.erase(g_VecCCBp.begin() + i);
		}
	}
	return TRUE;
}

#pragma once
#include"initSomeThing.h"
class CMyDebuggerFramWork
{
public:
	CMyDebuggerFramWork();
	virtual ~CMyDebuggerFramWork();
public:
	BOOL OpenDebugProcess(TCHAR* pszFile);//�������Խ���
	void StartDebug();//���յ����¼�����ʼ���Խ���
	BOOL SetOepBreak();//��OEP����������ϵ�
	BOOL SetCcPoint(SIZE_T dwAddress, BOOL TempCC);//��������ϵ�
	BOOL ResetDelCcPoint(SIZE_T dwAddress);//ȥ��CC�ϵ�
	BOOL DelCcPoint(SIZE_T dwAddress, BOOL TempCC);//ɾ��CC�ϵ�
	
public:
	DEBUG_EVENT m_dbgEvent = { 0 };
	//vector<CCBPINFO>m_VecCCBp; //����ϵ�����
	PROCESS_INFORMATION m_ProInfo = {};//������Ϣ
};


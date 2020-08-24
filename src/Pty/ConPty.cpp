 /*
 * Copyright 2020, WindTerm.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ConPty.h"

#include <QThread>

#ifdef Q_OS_WIN
#include <process.h>
#endif

#define CONPTY_MINIMAL_WINDOWS_VERSION 18309

class PipeThread : public QThread {
public:
	PipeThread(ConPty *conpty, LPVOID pipe)
		: QThread(conpty)
		, m_conpty(conpty)
		, m_pipe(pipe)
	{}

	void run() final {
		constexpr DWORD BUFF_SIZE = 512;
		char szBuffer[BUFF_SIZE];

		while (isInterruptionRequested() == false) {
			if (isInterruptionRequested()) {
				return;
			}
			DWORD bytesRead;
			bool readSuccess = ReadFile(m_pipe, szBuffer, BUFF_SIZE, &bytesRead, NULL);

			if (readSuccess == false) {
				m_conpty->setErrorCode(GetLastError());
				return;
			}

			if (isInterruptionRequested()) {
				return;
			}

			if (readSuccess && bytesRead > 0) {
				m_conpty->appendBuffer(QByteArray(szBuffer, bytesRead));
			}
		}
	}

private:
	ConPty *m_conpty;
	LPVOID m_pipe;
};

ConPty::ConPty(QObject *parent /*= nullptr*/)
	: m_inPipe(INVALID_HANDLE_VALUE)
	, m_outPipe(INVALID_HANDLE_VALUE)
	, m_pipeThread(nullptr)
	, m_ptyHandler(INVALID_HANDLE_VALUE)
{}

ConPty::~ConPty() {
	stop();
}

void ConPty::appendBuffer(const QByteArray &buffer) {
	if (buffer.isEmpty() == false) {
		{
			ThreadLocker<SpinMutex> locker(m_mutex);
			m_buffer.append(buffer);
		}
		emit readyRead();
	}
}

HRESULT ConPty::createPseudoConsoleAndPipes(HPCON *phPC, HANDLE *phPipeIn, HANDLE *phPipeOut,
											qint16 rows, qint16 columns) {
	HRESULT hr = E_UNEXPECTED;
	HANDLE hPipePTYIn = INVALID_HANDLE_VALUE;
	HANDLE hPipePTYOut = INVALID_HANDLE_VALUE;

	if (CreatePipe(&hPipePTYIn, phPipeOut, NULL, 0) && CreatePipe(phPipeIn, &hPipePTYOut, NULL, 0)) {
#if COMPILE_CONPTY_ENABLED
		hr = CreatePseudoConsole({columns, rows}, hPipePTYIn, hPipePTYOut, 0, phPC);
#endif
		if (INVALID_HANDLE_VALUE != hPipePTYOut) CloseHandle(hPipePTYOut);
		if (INVALID_HANDLE_VALUE != hPipePTYIn) CloseHandle(hPipePTYIn);
	}
	return hr;
}

HRESULT ConPty::initStartupInfoAttachedToPseudoConsole(STARTUPINFOEX *pStartupInfo, HPCON hPC) {
	HRESULT hr = E_UNEXPECTED;

	if (pStartupInfo) {
		SIZE_T attrListSize;

		pStartupInfo->StartupInfo.cb = sizeof(STARTUPINFOEX);

		InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);

		pStartupInfo->lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(malloc(attrListSize));

		if (pStartupInfo->lpAttributeList
			&& InitializeProcThreadAttributeList(pStartupInfo->lpAttributeList, 1, 0, &attrListSize)) {
			hr = UpdateProcThreadAttribute(
				pStartupInfo->lpAttributeList,
				0,
				PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
				hPC,
				sizeof(HPCON),
				NULL,
				NULL
			) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
		} else {
			hr = HRESULT_FROM_WIN32(GetLastError());
		}
	}
	return hr;
}

bool ConPty::createProcess(QString command, const QString &arguments,
						   const QString &workingDirectory, const QStringList &environment,
						   qint16 rows, qint16 columns) {
	if (isAvailable() == false) {
		setErrorString(tr("Windows 10 version below 1809 is not supported."));
		return false;
	}
	stop();

	HRESULT hr = createPseudoConsoleAndPipes(&m_ptyHandler, &m_inPipe, &m_outPipe, rows, columns); 

	if (hr == S_OK) {
		m_startupInfo = std::make_unique<STARTUPINFOEX>();
		m_processInformation = std::make_unique<PROCESS_INFORMATION>();

		m_pipeThread = new PipeThread(this, m_inPipe);
		m_pipeThread->start();

		if (initStartupInfoAttachedToPseudoConsole(m_startupInfo.get(), m_ptyHandler) == S_OK) {
			std::wstring env = environment.join(QChar('\0')).append(QChar('\0')).toStdWString();

			if (arguments.isEmpty() == false) {
				command.append(" ").append(arguments);
			}

			LPWSTR szCommand = new wchar_t[command.size() + 1];
			int commandLength = command.toWCharArray(szCommand);
			szCommand[commandLength] = '\0';

			hr = CreateProcess(
				NULL,
				szCommand,
				NULL,
				NULL,
				FALSE,
				EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
				LPWSTR(env.data()),
				workingDirectory.isEmpty() ? NULL : workingDirectory.toStdWString().c_str(),
				&m_startupInfo->StartupInfo,
				m_processInformation.get()
			) ? S_OK : GetLastError();

			delete szCommand;
			szCommand = nullptr;
		}
	}

	if (hr == S_OK) {
		m_rows = rows;
		m_columns = columns;

		installWinProcessEventNotifier(m_processInformation->hProcess);
	} else {
		setErrorCode(GetLastError());
	}
	return true;
}

bool ConPty::isAvailable() {
	qint32 buildNumber = QSysInfo::kernelVersion().split(".").last().toInt();
	return (buildNumber >= CONPTY_MINIMAL_WINDOWS_VERSION) ? true : false;
}

QByteArray ConPty::readAll() {
	ThreadLocker<SpinMutex> locker(m_mutex);
	return std::move(m_buffer);
}

bool ConPty::resizeWindow(qint16 rows, qint16 columns) {
	bool success = true;

	if (rows != m_rows && columns != m_columns) {
#if COMPILE_CONPTY_ENABLED
		HRESULT hr = (m_ptyHandler != INVALID_HANDLE_VALUE)
				   ? ResizePseudoConsole(m_ptyHandler, { columns, rows })
				   : S_FALSE;
		success = (hr == S_OK) ? true : false;
#endif
		if (success) {
			rows = m_rows;
			columns = m_columns;
		}
	}
	Q_ASSERT(success);
	return success;
}

void ConPty::stop() {
	if (m_pipeThread) {
		m_pipeThread->requestInterruption();
	}

	if (m_processInformation) {
		uninstallWinProcessEventNotifier(m_processInformation->hProcess);
		CloseHandle(m_processInformation->hThread);
		CloseHandle(m_processInformation->hProcess);
	}

	if (m_startupInfo) {
		DeleteProcThreadAttributeList(m_startupInfo->lpAttributeList);
		free(m_startupInfo->lpAttributeList);
	}

	if (m_ptyHandler != INVALID_HANDLE_VALUE) {
#if COMPILE_CONPTY_ENABLED
		ClosePseudoConsole(m_ptyHandler);
#endif
	}

	if (m_inPipe != INVALID_HANDLE_VALUE) {
		CloseHandle(m_inPipe);
	}

	if (m_outPipe != INVALID_HANDLE_VALUE) {
		CloseHandle(m_outPipe);
	}

	if (m_pipeThread) {
		m_pipeThread->wait(1000);
		m_pipeThread->deleteLater();
	}
}

qint64 ConPty::write(const QByteArray &text) {
	DWORD bytesWritten;

	WriteFile(m_outPipe, text.data(), text.size(), &bytesWritten, NULL);
	return bytesWritten;
}

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

#include "Pty.h"

#ifdef Q_OS_WIN
	#include <windows.h>
	#include <QWinEventNotifier>
#endif // Q_OS_WIN

Pty::Pty()
	: m_columns(-1)
	, m_errorCode(0)
	, m_rows(-1)
#ifdef Q_OS_WIN
	, m_winProcessEventNotifier(nullptr)
#endif
{}

QString Pty::errorString() {
	ThreadLocker<SpinMutex> locker(m_mutex);
	return std::move(m_errorString);
}

#ifdef Q_OS_WIN
void Pty::installWinProcessEventNotifier(void *handle) {
	if (m_winProcessEventNotifier == nullptr) {
		m_winProcessEventNotifier = new QWinEventNotifier(handle, this);

		connect(m_winProcessEventNotifier, &QWinEventNotifier::activated, this, [this](HANDLE handle) {
			if (handle) {
				DWORD exitCode;

				if (GetExitCodeProcess(handle, &exitCode)) {
					setErrorString(QString("Process exited with code %1").arg(
						QString::number(exitCode, (exitCode >= 0xFF) ? 16 : 10).prepend((exitCode >= 0xFF) ? "0x" : "")
					));
				}
				m_winProcessEventNotifier->setEnabled(false);
			}
		});
	}

	if (m_winProcessEventNotifier->handle() != handle) {
		m_winProcessEventNotifier->setHandle(handle);
		m_winProcessEventNotifier->setEnabled(true);
	}
}
#endif

void Pty::setErrorCode(int errorCode) {
	constexpr int bufferLength = 512;
	wchar_t buffer[bufferLength];

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errorCode,
				  LANG_NEUTRAL, buffer, bufferLength, NULL);

	QString lastError = QString::fromWCharArray(buffer);
	setErrorString(lastError);

	m_errorCode = errorCode;
}

void Pty::setErrorString(const QString &errorString) {
	if (errorString.isEmpty() == false) {
		{
			ThreadLocker<SpinMutex> locker(m_mutex);
			m_errorString = errorString;	
		}
		emit errorOccurred();
	}
}

#ifdef Q_OS_WIN
void Pty::uninstallWinProcessEventNotifier(void *handle) {
	if (m_winProcessEventNotifier != nullptr
		&& m_winProcessEventNotifier->handle() == handle) {
		m_winProcessEventNotifier->deleteLater();
		m_winProcessEventNotifier = nullptr;
	}
}
#endif

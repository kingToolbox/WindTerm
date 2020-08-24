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

#include "WinPty.h"

#include <QFileInfo>
#include <QLocalSocket>
#include <QCoreApplication>

#include <sstream>

const char *WINPTY_AGENT_NAME	= "winpty-agent.exe";
const char *WINPTY_DLL_NAME		= "winpty.dll";

QString castErrorToString(winpty_error_ptr_t error_ptr) {
	return QString::fromStdWString(winpty_error_msg(error_ptr));
}

WinPty::WinPty(QObject *parent /*= nullptr*/)
	: m_ptyHandler(nullptr)
	, m_innerHandle(INVALID_HANDLE_VALUE)
	, m_outSocket(nullptr)
	, m_inSocket(nullptr)
{}

WinPty::~WinPty() {
	stop();
}

bool WinPty::createProcess(QString command, const QString &arguments,
						   const QString &workingDirectory, const QStringList &environment,
						   qint16 rows, qint16 columns) {
	bool success = false;
	winpty_error_ptr_t errorPtr = nullptr;
	QString errorString;

	do {
		stop();

		if (isAvailable() == false) {
			errorString = tr("Winpty-agent.exe or winpty.dll not found!.");
			break;
		}
		QString commandWithArguments = command;

		if (arguments.isEmpty() == false) {
			commandWithArguments.append(" ").append(arguments);
		}
		std::wstring env = environment.join(QChar('\0')).append(QChar('\0')).toStdWString();
		winpty_config_t* startConfig = winpty_config_new(0, &errorPtr);

		if (startConfig == nullptr) {
			errorString = QString("WinPty Error: create start config -> %1").arg(castErrorToString(errorPtr));
			break;
		}
		winpty_config_set_initial_size(startConfig, columns, rows);
		winpty_config_set_mouse_mode(startConfig, WINPTY_MOUSE_MODE_AUTO);

		m_ptyHandler = winpty_open(startConfig, &errorPtr);
		winpty_config_free(startConfig);

		if (m_ptyHandler == nullptr) {
			errorString = QString("WinPty Error: start agent -> %1").arg(castErrorToString(errorPtr));
			break;
		}

		QString m_conInName = QString::fromWCharArray(winpty_conin_name(m_ptyHandler));
		QString m_conOutName = QString::fromWCharArray(winpty_conout_name(m_ptyHandler));
		m_outSocket = std::make_unique<QLocalSocket>();
		m_inSocket = std::make_unique<QLocalSocket>();

		m_outSocket->connectToServer(m_conInName, QIODevice::WriteOnly);
		m_outSocket->waitForConnected();

		m_inSocket->connectToServer(m_conOutName, QIODevice::ReadOnly);
		m_inSocket->waitForConnected();

		if (m_outSocket->state() != QLocalSocket::ConnectedState
			&& m_inSocket->state() != QLocalSocket::ConnectedState) {
			errorString = QString("WinPty Error: Unable to connect local sockets -> %1 / %2")
								  .arg(m_outSocket->errorString())
								  .arg(m_inSocket->errorString());

			m_inSocket.reset(nullptr);
			m_outSocket.reset(nullptr);
			break;
		}

		connect(m_inSocket.get(), &QLocalSocket::readyRead, this, [this]() {
			emit readyRead();
		});

		winpty_spawn_config_t* spawnConfig = winpty_spawn_config_new(
			WINPTY_SPAWN_FLAG_AUTO_SHUTDOWN,
			command.toStdWString().c_str(),
			commandWithArguments.toStdWString().c_str(),
			workingDirectory.isEmpty() ? NULL : workingDirectory.toStdWString().c_str(),
			env.c_str(),
			&errorPtr
		);

		if (spawnConfig == nullptr) {
			errorString = QString("WinPty Error: create spawn config -> %1").arg(castErrorToString(errorPtr));
			break;
		}

		BOOL spawnSuccess = winpty_spawn(m_ptyHandler, spawnConfig, &m_innerHandle, nullptr, nullptr, &errorPtr);
		winpty_spawn_config_free(spawnConfig);

		if (spawnSuccess == FALSE) {
			errorString = QString("WinPty Error: start terminal process -> %1").arg(castErrorToString(errorPtr));
			break;
		}
		success = true;
	} while (0);

	if (errorString.isEmpty() == false) {
		Q_ASSERT(success == false);

		winpty_error_free(errorPtr);
		setErrorString(errorString);
	}

	if (success) {
		m_columns = columns;
		m_rows = rows;

		installWinProcessEventNotifier(m_innerHandle);
	}
	return success;
}

QByteArray WinPty::readAll() {
	QByteArray buffer;

	if (m_inSocket) {
		buffer = m_inSocket->readAll();
		Q_ASSERT(buffer.isEmpty() == false);
	}
	return buffer;
}

bool WinPty::resizeWindow(qint16 rows, qint16 columns) {
	bool success = true;

	if (rows != m_rows && columns != m_columns) {
		success = m_ptyHandler ? winpty_set_size(m_ptyHandler, columns, rows, nullptr) : false;

		if (success) {
			m_rows = rows;
			m_columns = columns;
		}
	}
	Q_ASSERT(success);
	return success;
}

void WinPty::stop() {
	if (m_ptyHandler != nullptr) {
		winpty_free(m_ptyHandler);
		m_ptyHandler = nullptr;
	}

	if (m_innerHandle != INVALID_HANDLE_VALUE) {
		uninstallWinProcessEventNotifier(m_innerHandle);
		CloseHandle(m_innerHandle);
		m_innerHandle = INVALID_HANDLE_VALUE;
	}

	m_outSocket.reset(nullptr);
	m_inSocket.reset(nullptr);
}

qint64 WinPty::write(const QByteArray &text) {
	qint64 bytesWritten = -1;

	if (m_outSocket) {
		bytesWritten = m_outSocket->write(text);
		Q_ASSERT(bytesWritten != -1);
	}
	return bytesWritten;
}

bool WinPty::isAvailable() {
	return QFile::exists(QCoreApplication::applicationDirPath() + "/" + WINPTY_AGENT_NAME)
		&& QFile::exists(QCoreApplication::applicationDirPath() + "/" + WINPTY_DLL_NAME);
}
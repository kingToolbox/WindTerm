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

#ifndef WINPTY_H
#define WINPTY_H

#pragma once

#include "Pty.h"

#ifdef Q_OS_WIN
	#include <windows.h>
#endif // Q_OS_WIN

#include "winpty_api.h"

class QLocalSocket;

class WinPty
	: public Pty
{
	Q_OBJECT

public:
	WinPty(QObject *parent = nullptr);
	virtual ~WinPty();

	bool createProcess(QString command, const QString &arguments,
					   const QString &workingDirectory, const QStringList &environment,
					   qint16 rows, qint16 columns) final;
	static bool isAvailable();
	QByteArray readAll() final;
	bool resizeWindow(qint16 rows, qint16 columns) final;
	qint64 write(const QByteArray &text) final;

private:
	void stop();

private:
	Q_DISABLE_COPY(WinPty)

	winpty_t *m_ptyHandler;
	HANDLE m_innerHandle;
	std::unique_ptr<QLocalSocket> m_inSocket;
	std::unique_ptr<QLocalSocket> m_outSocket;
};

#endif // WINPTY_H
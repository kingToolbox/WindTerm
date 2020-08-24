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

#ifndef CONPTY_H
#define CONPTY_H

#pragma once

#include "Pty.h"

#ifdef Q_OS_WIN
	#include <windows.h>
#endif // Q_OS_WIN

class PipeThread;

class ConPty
	: public Pty
{
	Q_OBJECT

public:
	ConPty(QObject *parent = nullptr);
	virtual ~ConPty();

	void appendBuffer(const QByteArray &buffer);
	bool createProcess(QString command, const QString &arguments,
					   const QString &workingDirectory, const QStringList &environment,
					   qint16 rows, qint16 columns) final;
	static bool isAvailable();
	QByteArray readAll() final;
	bool resizeWindow(qint16 rows, qint16 columns) final;
	qint64 write(const QByteArray &text) final;

private:
	HRESULT createPseudoConsoleAndPipes(HPCON *phPC, HANDLE *phPipeIn, HANDLE *phPipeOut, qint16 rows, qint16 columns);
	HRESULT initStartupInfoAttachedToPseudoConsole(STARTUPINFOEX *pStartupInfo, HPCON hPC);
	void stop();

private:
	Q_DISABLE_COPY(ConPty)

	QByteArray m_buffer;
	PipeThread *m_pipeThread;

	HANDLE m_inPipe;
	HANDLE m_outPipe;
	HPCON m_ptyHandler;
	std::unique_ptr<PROCESS_INFORMATION> m_processInformation;
	std::unique_ptr<STARTUPINFOEX> m_startupInfo;
};

#endif // CONPTY_H
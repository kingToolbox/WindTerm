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
#ifndef UNIXPTY_H
#define UNIXPTY_H

#pragma once

#include <QtGlobal>

#ifdef Q_OS_UNIX

#include "Pty.h"
#include <QProcess>
#include <QSocketNotifier>

#include <termios.h>

class ShellProcess
	: public QProcess
{
    Q_OBJECT

public:
	ShellProcess();

private:
	void setupChildProcess() final;

private:
	int m_handleMaster;
	int m_handleSlave;
    QString m_handleSlaveName;

private:
	friend class UnixPty;
};

class UnixPty
	: public Pty
{
public:
	UnixPty(QObject *parent = nullptr);
    virtual ~UnixPty();

	bool createProcess(QString command, const QString &arguments,
					   const QString &workingDirectory, const QProcessEnvironment &environment,
					   int rows, int columns) final;
	static bool isAvailable();
	bool resizeWindow(int rows, int columns) final;
    QByteArray readAll() final;
	qint64 write(const QByteArray &text) final;

private:
	void moveToThread(QThread *targetThread);
	void setError(const char *error);
	bool setTerminalAttributes(struct ::termios *ttmode);
	void stop();
	bool terminalAttributes(struct ::termios *ttmode);

private:
	qint64 m_pid;
	ShellProcess m_shellProcess;
	QSocketNotifier *m_readMasterNotify;

	char *m_buffer;
	QByteArray m_shellReadBuffer;
};

#endif // Q_OS_UNIX
#endif // UNIXPTY_H

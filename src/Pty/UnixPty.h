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
	explicit ShellProcess(QObject *parent = nullptr);

protected:
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
	// Qt 5 hook. Removed in Qt 6 in favour of setChildProcessModifier().
	void setupChildProcess() final;
#endif

private:
	// Runs in the forked child, between fork() and exec(). Everything it calls
	// must be async-signal-safe, so it is limited to dup2/setsid/ioctl on the
	// already-open slave descriptor. The utmpx bookkeeping that used to live
	// here has moved to UnixPty::registerUtmpx(), in the parent.
	void applyChildSetup();

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
	Q_OBJECT

public:
	explicit UnixPty(QObject *parent = nullptr);
	~UnixPty() override;

	bool createProcess(QString command, const QString &arguments,
					   const QString &workingDirectory, const QStringList &environment,
					   qint16 rows, qint16 columns) final;
	static bool isAvailable();
	bool resizeWindow(qint16 rows, qint16 columns) final;
	QByteArray readAll() final;
	qint64 write(const QByteArray &text) final;

	// Moves the shell process - not this object - to another thread.
	// Deliberately not called moveToThread(): that name would hide
	// QObject::moveToThread() and make it uncallable on a UnixPty.
	void moveProcessToThread(QThread *targetThread);

private:
	void readFromMaster();
	void registerUtmpx();
	void setError(const char *error);
	bool setTerminalAttributes(struct ::termios *ttmode);
	void stop();
	bool terminalAttributes(struct ::termios *ttmode);

private:
	Q_DISABLE_COPY(UnixPty)

	qint64 m_pid;
	ShellProcess m_shellProcess;
	QSocketNotifier *m_readMasterNotify;

	char *m_buffer;
	QByteArray m_shellReadBuffer;
};

#endif // Q_OS_UNIX
#endif // UNIXPTY_H

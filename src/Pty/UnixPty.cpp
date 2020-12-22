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
#include "UnixPty.h"
#ifdef Q_OS_UNIX

#include <QFileInfo>
#include <QThread>

#include <errno.h>
#include <utmpx.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

constexpr int BUFFER_SIZE	= 0x800; // 2048 bytes

ShellProcess::ShellProcess()
	: QProcess()
	, m_handleMaster(-1)
	, m_handleSlave(-1)
{
	setProcessChannelMode(QProcess::MergedChannels);
}

void ShellProcess::setupChildProcess() {
	dup2(m_handleSlave, STDIN_FILENO);
	dup2(m_handleSlave, STDOUT_FILENO);
	dup2(m_handleSlave, STDERR_FILENO);

	pid_t sid = setsid();
	ioctl(m_handleSlave, TIOCSCTTY, 0);
	tcsetpgrp(m_handleSlave, sid);

	struct utmpx utmpxInfo;
	memset(&utmpxInfo, 0, sizeof(utmpxInfo));

	strncpy(utmpxInfo.ut_user, qgetenv("USER"), sizeof(utmpxInfo.ut_user));

	QString device(m_handleSlaveName);
	if (device.startsWith("/dev/")) {
		device = device.mid(5);
	}
	const char *d = device.toLatin1().constData();
	strncpy(utmpxInfo.ut_line, d, sizeof(utmpxInfo.ut_line));
	strncpy(utmpxInfo.ut_id, d + strlen(d) - sizeof(utmpxInfo.ut_id), sizeof(utmpxInfo.ut_id));

	struct timeval tv;
	gettimeofday(&tv, 0);
	utmpxInfo.ut_tv.tv_sec = tv.tv_sec;
	utmpxInfo.ut_tv.tv_usec = tv.tv_usec;

	utmpxInfo.ut_type = USER_PROCESS;
	utmpxInfo.ut_pid = getpid();

	utmpxname(_PATH_UTMPX);
	setutxent();
	pututxline(&utmpxInfo);
	endutxent();

#if !defined(Q_OS_UNIX)
	updwtmpx(_PATH_UTMPX, &loginInfo);
#endif
}

UnixPty::UnixPty(QObject *parent /*= nullptr*/)
	: Pty(parent)
	, m_pid(0)
	, m_readMasterNotify(nullptr)
{
	m_buffer = static_cast<char *>(malloc(BUFFER_SIZE));
}

UnixPty::~UnixPty() {
	stop();

	free(m_buffer);
	m_buffer = nullptr;
}

bool UnixPty::createProcess(QString command, const QString &arguments,
							const QString &workingDirectory, const QProcessEnvironment &environment,
							int rows, int columns) {
	if (m_shellProcess.state() == QProcess::Running) {
		return false;
	}

	QFileInfo fileInfo(command);
	if (fileInfo.isRelative() || fileInfo.exists() == false) {
		setErrorString(tr("UnixPty: shell file path must be absolute"));
		return false;
	}

	bool success = false;
	do {
		int result = 0;

		m_shellProcess.m_handleMaster = ::posix_openpt(O_RDWR | O_NOCTTY);
		if (m_shellProcess.m_handleMaster < 0) {
			setError("Unable to open master");
			break;
		}

		m_shellProcess.m_handleSlaveName = ptsname(m_shellProcess.m_handleMaster);
		if (m_shellProcess.m_handleSlaveName.isEmpty()) {
			setError("Unable to get slave name");
			break;
		}

		result = grantpt(m_shellProcess.m_handleMaster);
		if (result != 0) {
			setError("Unable to change perms for slave");
			break;
		}

		result = unlockpt(m_shellProcess.m_handleMaster);
		if (result != 0) {
			setError("Unable to unlock slave");
			break;
		}

		m_shellProcess.m_handleSlave = ::open(m_shellProcess.m_handleSlaveName.toLatin1().data(), O_RDWR | O_NOCTTY);
		if (m_shellProcess.m_handleSlave < 0) {
			setError("Unable to open slave");
			break;
		}

		int flags = fcntl(m_shellProcess.m_handleMaster, F_GETFL, 0);
		result = fcntl(m_shellProcess.m_handleMaster, F_SETFL, flags | O_NONBLOCK);
		if (result == -1) {
			setError("Unable to set non-blocking mode for master");
			break;
		}

		result = fcntl(m_shellProcess.m_handleMaster, F_SETFD, FD_CLOEXEC);
		if (result == -1) {
			setError("Unable to set flags for master");
			break;
		}

		result = fcntl(m_shellProcess.m_handleSlave, F_SETFD, FD_CLOEXEC);
		if (result == -1) {
			setError("Unable to set flags for slave");
			break;
		}

		struct ::termios ttmode;
		if (terminalAttributes(&ttmode) == false) {
			break;
		}
		ttmode.c_iflag |= IXON;
		ttmode.c_iflag |= IUTF8;
		ttmode.c_lflag |= ECHO;

#ifdef Q_OS_MACOS
		ttmode.c_cc[VDSUSP] = 25;
		ttmode.c_cc[VSTATUS] = 20;
#endif
		if (setTerminalAttributes(&ttmode) == false) {
			break;
		}

		m_readMasterNotify = new QSocketNotifier(m_shellProcess.m_handleMaster, QSocketNotifier::Read, &m_shellProcess);
		m_readMasterNotify->setEnabled(true);
		m_readMasterNotify->moveToThread(m_shellProcess.thread());

		QObject::connect(m_readMasterNotify, &QSocketNotifier::activated, [this](int socket) {
			Q_UNUSED(socket)
			int readSize = 0;
			QByteArray readData;

			do {
				readSize = ::read(m_shellProcess.m_handleMaster, m_buffer, BUFFER_SIZE);

				if (readSize == -1) {
					if (errno == EAGAIN) {
						QThread::yieldCurrentThread();
						continue;
					} else {
						break;
					}
				}
				readData.append(QByteArray::fromRawData(m_buffer, readSize));
			} while (readSize == BUFFER_SIZE || (readSize == -1 && errno == EAGAIN)); //last data block always < readSize

			if (readData.isEmpty() == false) {
				m_shellReadBuffer.append(readData);
				emit readyRead();
			}
		});

		m_shellProcess.setWorkingDirectory(workingDirectory);
		m_shellProcess.setProcessEnvironment(environment);
		m_shellProcess.setReadChannel(QProcess::StandardOutput);
		m_shellProcess.start(command, arguments.isEmpty() ? QStringList() : QStringList(arguments));
		m_shellProcess.waitForStarted();

		m_pid = m_shellProcess.processId();
		success = resizeWindow(rows, columns);
	} while(0);

	if (success == false) {
		stop();
	}
	Q_ASSERT(success == true);
	return success;
}

bool UnixPty::resizeWindow(int rows, int columns) {
	if (rows != m_rows || columns != m_columns) {
		bool success = false;
		struct winsize winSize;

		memset(&winSize, 0, sizeof(winSize));
		winSize.ws_row = static_cast<quint16>(rows);
		winSize.ws_col = static_cast<quint16>(columns);

		if (ioctl(m_shellProcess.m_handleMaster, TIOCSWINSZ, &winSize) == 0
			&& ioctl(m_shellProcess.m_handleSlave, TIOCSWINSZ, &winSize) == 0) {
			m_rows = rows;
			m_columns = columns;
			success = true;
		}
		return success;
	}
	return true;
}

void UnixPty::setError(const char *error) {
	Pty::setErrorString(QString("%1: %2 -> %3").arg(tr("UnixPty"), tr(error), strerror(errno)));
}

bool UnixPty::setTerminalAttributes(struct ::termios *ttmode) {
	Q_ASSERT(m_shellProcess.m_handleMaster >= 0);
	int result = -1;

	if (m_shellProcess.m_handleMaster >=0) {
		result = tcsetattr(m_shellProcess.m_handleMaster, TCSANOW, ttmode);

		if (result != 0) {
			setError("Unable to set terminal attributes");
		}
	}
	return (result == 0);
}

void UnixPty::stop() {
	m_shellProcess.m_handleSlaveName = QString();

	if (m_shellProcess.m_handleSlave >= 0) {
		::close(m_shellProcess.m_handleSlave);
		m_shellProcess.m_handleSlave = -1;
	}

	if (m_shellProcess.m_handleMaster >= 0) {
		::close(m_shellProcess.m_handleMaster);
		m_shellProcess.m_handleMaster = -1;
	}

	if (m_shellProcess.state() == QProcess::Running) {
		m_readMasterNotify->disconnect();
		m_readMasterNotify->deleteLater();

		m_shellProcess.terminate();
		m_shellProcess.waitForFinished(1000);

		if (m_shellProcess.state() == QProcess::Running) {
			QProcess::startDetached(QString("kill -9 %1").arg(m_pid));
			m_shellProcess.kill();
			m_shellProcess.waitForFinished(1000);
		}
		Q_ASSERT(m_shellProcess.state() == QProcess::NotRunning);
	}
}

bool UnixPty::terminalAttributes(struct ::termios *ttmode) {
	Q_ASSERT(m_shellProcess.m_handleMaster >= 0);
	int result = -1;

	if (m_shellProcess.m_handleMaster >= 0) {
		result = tcgetattr(m_shellProcess.m_handleMaster, ttmode);

		if (result != 0) {
			setError("Unable to get terminal attributes");
		}
	}
	return (result == 0);
}

QByteArray UnixPty::readAll() {
	QByteArray shellReadBuffer = m_shellReadBuffer;

	m_shellReadBuffer.clear();
	return shellReadBuffer;
}

qint64 UnixPty::write(const QByteArray &text) {
	int writeSize = ::write(m_shellProcess.m_handleMaster, text.constData(), text.size());
	Q_ASSERT(writeSize == text.size());

	if (writeSize == -1) {
		setError("Unable to write output");
	}
	return writeSize;
}

bool UnixPty::isAvailable() {
	return true;
}

void UnixPty::moveToThread(QThread *targetThread) {
	m_shellProcess.moveToThread(targetThread);
}

#endif // Q_OS_UNIX
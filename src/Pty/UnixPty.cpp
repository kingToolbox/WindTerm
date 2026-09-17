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
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <utmpx.h>

constexpr int BUFFER_SIZE	= 0x800; // 2048 bytes

ShellProcess::ShellProcess(QObject *parent /*= nullptr*/)
	: QProcess(parent)
	, m_handleMaster(-1)
	, m_handleSlave(-1)
{
	setProcessChannelMode(QProcess::MergedChannels);

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
	// Qt 6 removed setupChildProcess(); setChildProcessModifier() is the
	// supported replacement and runs at the same point, in the forked child.
	setChildProcessModifier([this]() { applyChildSetup(); });
#endif
}

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
void ShellProcess::setupChildProcess() {
	applyChildSetup();
}
#endif

void ShellProcess::applyChildSetup() {
	// Async-signal-safe only: this runs between fork() and exec(). Anything
	// that allocates, takes a lock or touches Qt is undefined behaviour here,
	// which is why the utmpx bookkeeping lives in the parent instead.
	if (m_handleSlave < 0) {
		return;
	}

	::dup2(m_handleSlave, STDIN_FILENO);
	::dup2(m_handleSlave, STDOUT_FILENO);
	::dup2(m_handleSlave, STDERR_FILENO);

	const pid_t sid = ::setsid();
	::ioctl(m_handleSlave, TIOCSCTTY, 0);

	if (sid != -1) {
		::tcsetpgrp(m_handleSlave, sid);
	}
}

UnixPty::UnixPty(QObject *parent /*= nullptr*/)
	: Pty()
	, m_pid(0)
	, m_readMasterNotify(nullptr)
	, m_buffer(nullptr)
{
	setParent(parent);
	m_buffer = static_cast<char *>(malloc(BUFFER_SIZE));
}

UnixPty::~UnixPty() {
	stop();

	free(m_buffer);
	m_buffer = nullptr;
}

bool UnixPty::createProcess(QString command, const QString &arguments,
							const QString &workingDirectory, const QStringList &environment,
							qint16 rows, qint16 columns) {
	if (m_shellProcess.state() == QProcess::Running) {
		return false;
	}

	if (m_buffer == nullptr) {
		setErrorString(tr("UnixPty: out of memory"));
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

		const char *slaveName = ::ptsname(m_shellProcess.m_handleMaster);
		if (slaveName == nullptr) {
			setError("Unable to get slave name");
			break;
		}
		m_shellProcess.m_handleSlaveName = QString::fromLocal8Bit(slaveName);

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

		m_shellProcess.m_handleSlave = ::open(slaveName, O_RDWR | O_NOCTTY);
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

		// The slave is deliberately *not* FD_CLOEXEC-protected against the
		// child: applyChildSetup() dup2()s it onto the standard descriptors
		// before exec(), and the copies survive. The original fd does not.
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

		m_readMasterNotify = new QSocketNotifier(m_shellProcess.m_handleMaster,
												 QSocketNotifier::Read, &m_shellProcess);
		m_readMasterNotify->setEnabled(true);

		QObject::connect(m_readMasterNotify, &QSocketNotifier::activated,
						 &m_shellProcess, [this](QSocketDescriptor, QSocketNotifier::Type) {
			readFromMaster();
		});

		m_shellProcess.setWorkingDirectory(workingDirectory);
		if (environment.isEmpty() == false) {
			m_shellProcess.setEnvironment(environment);
		}
		m_shellProcess.setReadChannel(QProcess::StandardOutput);
		m_shellProcess.start(command, arguments.isEmpty() ? QStringList() : QStringList(arguments));

		if (m_shellProcess.waitForStarted() == false) {
			setErrorString(tr("UnixPty: %1").arg(m_shellProcess.errorString()));
			break;
		}

		m_pid = m_shellProcess.processId();
		registerUtmpx();

		success = resizeWindow(rows, columns);
	} while(0);

	if (success == false) {
		stop();
	}
	return success;
}

void UnixPty::readFromMaster() {
	int readSize = 0;
	QByteArray readData;

	do {
		readSize = ::read(m_shellProcess.m_handleMaster, m_buffer, BUFFER_SIZE);

		if (readSize == -1) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (readSize == 0) {
			break;
		}
		readData.append(m_buffer, readSize);
	} while (readSize == BUFFER_SIZE);

	if (readData.isEmpty() == false) {
		{
			ThreadLocker<SpinMutex> locker(m_mutex);
			m_shellReadBuffer.append(readData);
		}
		emit readyRead();
	}
}

// Best-effort utmpx registration, done in the parent once the child is
// running. The original code did this between fork() and exec(), where
// pututxline() - which allocates and takes a lock - is not legal.
// On macOS /var/run/utmpx is root-owned, so this is expected to be a no-op
// for a normal user.
void UnixPty::registerUtmpx() {
	const QByteArray device = m_shellProcess.m_handleSlaveName.startsWith(QLatin1String("/dev/"))
		? m_shellProcess.m_handleSlaveName.mid(5).toLocal8Bit()
		: m_shellProcess.m_handleSlaveName.toLocal8Bit();

	if (device.isEmpty() || m_pid <= 0) {
		return;
	}

	struct utmpx utmpxInfo;
	memset(&utmpxInfo, 0, sizeof(utmpxInfo));

	const QByteArray user = qgetenv("USER");
	if (user.isEmpty() == false) {
		strncpy(utmpxInfo.ut_user, user.constData(), sizeof(utmpxInfo.ut_user) - 1);
	}

	const char *d = device.constData();
	strncpy(utmpxInfo.ut_line, d, sizeof(utmpxInfo.ut_line) - 1);

	// ut_id holds the trailing characters of the tty name, but only when the
	// name is long enough - otherwise the original pointer arithmetic walked
	// off the front of the buffer.
	const size_t deviceLength = static_cast<size_t>(device.size());
	const size_t idLength = sizeof(utmpxInfo.ut_id);
	const char *id = (deviceLength >= idLength) ? (d + deviceLength - idLength) : d;
	strncpy(utmpxInfo.ut_id, id, idLength);

	struct timeval tv;
	gettimeofday(&tv, nullptr);
	utmpxInfo.ut_tv.tv_sec = tv.tv_sec;
	utmpxInfo.ut_tv.tv_usec = tv.tv_usec;

	utmpxInfo.ut_type = USER_PROCESS;
	utmpxInfo.ut_pid = static_cast<pid_t>(m_pid);

	utmpxname(_PATH_UTMPX);
	setutxent();
	pututxline(&utmpxInfo);
	endutxent();
}

bool UnixPty::resizeWindow(qint16 rows, qint16 columns) {
	if (rows == m_rows && columns == m_columns) {
		return true;
	}

	if (m_shellProcess.m_handleMaster < 0) {
		return false;
	}

	struct winsize winSize;
	memset(&winSize, 0, sizeof(winSize));
	winSize.ws_row = static_cast<unsigned short>(rows);
	winSize.ws_col = static_cast<unsigned short>(columns);

	// Setting the size on the master is what propagates to the line
	// discipline and raises SIGWINCH in the child. The slave ioctl is only a
	// belt-and-braces call and must not decide the outcome: the slave fd may
	// legitimately be closed by then.
	if (ioctl(m_shellProcess.m_handleMaster, TIOCSWINSZ, &winSize) != 0) {
		return false;
	}
	if (m_shellProcess.m_handleSlave >= 0) {
		ioctl(m_shellProcess.m_handleSlave, TIOCSWINSZ, &winSize);
	}

	m_rows = rows;
	m_columns = columns;
	return true;
}

void UnixPty::setError(const char *error) {
	Pty::setErrorString(QString("%1: %2 -> %3").arg(tr("UnixPty"), tr(error), strerror(errno)));
}

bool UnixPty::setTerminalAttributes(struct ::termios *ttmode) {
	int result = -1;

	if (m_shellProcess.m_handleMaster >= 0) {
		result = tcsetattr(m_shellProcess.m_handleMaster, TCSANOW, ttmode);

		if (result != 0) {
			setError("Unable to set terminal attributes");
		}
	}
	return (result == 0);
}

void UnixPty::stop() {
	// Tear down in dependency order: the notifier watches the master fd, so it
	// has to go before the fd is closed, and the child has to be reaped before
	// the pty it is attached to disappears.
	if (m_readMasterNotify != nullptr) {
		m_readMasterNotify->setEnabled(false);
		m_readMasterNotify->disconnect();
		delete m_readMasterNotify;
		m_readMasterNotify = nullptr;
	}

	if (m_shellProcess.state() != QProcess::NotRunning) {
		m_shellProcess.terminate();
		m_shellProcess.waitForFinished(1000);

		if (m_shellProcess.state() != QProcess::NotRunning) {
			if (m_pid > 0) {
				::kill(static_cast<pid_t>(m_pid), SIGKILL);
			}
			m_shellProcess.kill();
			m_shellProcess.waitForFinished(1000);
		}
	}
	m_pid = 0;

	m_shellProcess.m_handleSlaveName = QString();

	if (m_shellProcess.m_handleSlave >= 0) {
		::close(m_shellProcess.m_handleSlave);
		m_shellProcess.m_handleSlave = -1;
	}

	if (m_shellProcess.m_handleMaster >= 0) {
		::close(m_shellProcess.m_handleMaster);
		m_shellProcess.m_handleMaster = -1;
	}
}

bool UnixPty::terminalAttributes(struct ::termios *ttmode) {
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
	ThreadLocker<SpinMutex> locker(m_mutex);

	QByteArray shellReadBuffer = m_shellReadBuffer;
	m_shellReadBuffer.clear();
	return shellReadBuffer;
}

qint64 UnixPty::write(const QByteArray &text) {
	if (m_shellProcess.m_handleMaster < 0) {
		return -1;
	}

	// The master is O_NONBLOCK, so a short write is normal rather than an
	// error; keep going until the whole buffer is out or the pty refuses it.
	qint64 written = 0;

	while (written < text.size()) {
		const ssize_t result = ::write(m_shellProcess.m_handleMaster,
									   text.constData() + written,
									   static_cast<size_t>(text.size() - written));

		if (result > 0) {
			written += result;
			continue;
		}
		if (result == -1 && errno == EINTR) {
			continue;
		}
		if (result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			QThread::yieldCurrentThread();
			continue;
		}
		setError("Unable to write output");
		return (written > 0) ? written : -1;
	}
	return written;
}

bool UnixPty::isAvailable() {
	return true;
}

void UnixPty::moveProcessToThread(QThread *targetThread) {
	m_shellProcess.moveToThread(targetThread);
}

#endif // Q_OS_UNIX

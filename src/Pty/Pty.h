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

#ifndef PTY_H
#define PTY_H

#include <QObject>

#include "Public/Spin.h"

class QWinEventNotifier;

class Pty
	: public QObject
{
	Q_OBJECT

public:
	Pty();
	virtual ~Pty() = default;

	virtual bool createProcess(QString command, const QString &arguments,
							   const QString &workingDirectory, const QStringList &environment,
							   qint16 rows, qint16 columns) = 0;
	int errorCode() const { return m_errorCode; }
	QString errorString();
	virtual QByteArray readAll() = 0;	
	virtual bool resizeWindow(qint16 rows, qint16 columns) = 0;
	void setErrorCode(int errorCode);
	void setErrorString(const QString &errorString);
	virtual qint64 write(const QByteArray &text) = 0;

protected:
#ifdef Q_OS_WIN
	void installWinProcessEventNotifier(void *handle);
	void uninstallWinProcessEventNotifier(void *handle);
#endif

Q_SIGNALS:
	void errorOccurred();
	void readyRead();

protected:
	SpinMutex m_mutex;

	qint16 m_columns;
	qint16 m_rows;

private:
	Q_DISABLE_COPY(Pty)

	int m_errorCode;
	QString m_errorString;

#ifdef Q_OS_WIN
	QWinEventNotifier *m_winProcessEventNotifier;
#endif
};

#endif // PTY_H

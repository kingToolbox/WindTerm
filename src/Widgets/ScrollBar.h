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

#ifndef SCROLLBAR_H
#define SCROLLBAR_H

#pragma once

#include <QScrollBar>

class ScrollBar : public QScrollBar
{
	Q_OBJECT

public:
	explicit ScrollBar(Qt::Orientation orientation, QWidget *parent = nullptr);	
	virtual ~ScrollBar() = default;

	qint64 maximum() const { return m_maximum; }
	qint64 minimum() const { return m_minimum; }
	bool setMaximum(qint64 maximum);
	bool setMinimum(qint64 minimum);
	bool setPage(int page);
	bool setRange(qint64 minimum, qint64 maximum);
	bool setSingleStep(int singleStep);
	bool setValue(qint64 value);
	qint64 value() const { return m_value; }

private:
	void createConnections();

Q_SIGNALS:
	void pageChanged(int page) const;
	void rangeChanged(qint64 minimum, qint64 maximum) const;
	void singleStepChanged(int singleStep) const;
	void valueChanged(qint64 value, qint64 oldValue) const;

private:
	Q_DISABLE_COPY(ScrollBar)

	qint64 m_maximum;
	qint64 m_minimum;
	qint64 m_value;
};

#endif // SCROLLBAR_H
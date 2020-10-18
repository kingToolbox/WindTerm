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

#ifndef SPLITTER_H
#define SPLITTER_H

#pragma once

#include <QSplitter>

extern const char* const SPLITTER_RATIO;

class Splitter : public QSplitter
{
	Q_OBJECT

public:
	explicit Splitter(QWidget *parent = 0);
	~Splitter();

	void showIndex(int index);
	void hideIndex(int index);
	bool isIndexVisible(int index);
	void setIndexVisible(int index, bool visible);

	void setMainIndex(int mainIndex);

protected:
	bool eventFilter(QObject *obj, QEvent *event);

	QSplitterHandle *createHandle();

Q_SIGNALS:
	void showIndexRequested(int index);
	void hideIndexRequested(int index);

private:
	Q_DISABLE_COPY(Splitter)

	int m_mainIndex;
};

#endif // SPLITTER_H
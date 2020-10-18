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

#include "Splitter.h"

#include <QEvent>
#include <QVariant>

const char* const SPLITTER_RATIO = "ratio";

Splitter::Splitter(QWidget *parent)
	: QSplitter(parent)
	, m_mainIndex(0)
{}

Splitter::~Splitter()
{}

void Splitter::showIndex(int index) {
	if (isIndexVisible(index))
		return;

	emit showIndexRequested(index);

	if (QSplitterHandle *handle = this->handle(index)) {
		QList<int> sizes = this->sizes();

		int total = 0;
		for (int size : sizes) {
			total += size;
		}

		float ratio = handle->property(SPLITTER_RATIO).toFloat();
		if (ratio == 0.0) {
			ratio = 0.18f;
		}

		int offset = 0;
		int size = total * ratio;

		if (index > 0) {
			for (int i = 0; i < index; i++) {
				offset += sizes[i];
			}
			offset -= size;
		} else {
			offset = size;
		}

		if (index <= m_mainIndex) {
			index += 1;
		}
		moveSplitter(offset, index);
	}
}

void Splitter::hideIndex(int index) {
	if (isIndexVisible(index) == false)
		return;

	emit hideIndexRequested(index);

	if (QSplitterHandle *handle = this->handle(index)) {
		QList<int> sizes = this->sizes();
		int size = sizes[index];

		float total = 0;
		for (int size : sizes) {
			total += size;
		}
		handle->setProperty(SPLITTER_RATIO, size / total);

		int offset = 0;
		for (int i = 0; i <= index; i++) {
			if (i == index && index <= m_mainIndex)
				break;
			offset += sizes[i];
		}

		if (index <= m_mainIndex) {
			index += 1;
		}
		moveSplitter(offset, index);
	}
}

bool Splitter::isIndexVisible(int index) {
	if (index >= 0 && index < count()) {
		return sizes()[index] > 0;
	}
	
	Q_ASSERT(false);
	return false;
}

void Splitter::setIndexVisible(int index, bool visible) {
	if (visible) {
		showIndex(index);
	} else {
		hideIndex(index);
	}
}

void Splitter::setMainIndex(int mainIndex) {
	m_mainIndex = mainIndex;
}

bool Splitter::eventFilter(QObject *obj, QEvent *event) {
	if (event->type() == QEvent::MouseButtonDblClick) {
		if (QSplitterHandle *handle = dynamic_cast<QSplitterHandle *>(obj)) {
			for (int i = 0; i < count(); i++) {
				if (handle == this->handle(i)) {
					if (i <= m_mainIndex && i > 0) {
						i--;
					}
					bool visible = isIndexVisible(i);
					setIndexVisible(i, !visible);
					break;
				}
			}
		}
	}
	return QSplitter::eventFilter(obj, event);
}

QSplitterHandle *Splitter::createHandle() {
	QSplitterHandle *handle = QSplitter::createHandle();
	handle->installEventFilter(this);
	
	return handle;
}
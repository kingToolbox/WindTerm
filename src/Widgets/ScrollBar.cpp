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

#include "ScrollBar.h"

#include <QEvent>
#include <QVariant>

ScrollBar::ScrollBar(Qt::Orientation orientation, QWidget *parent /*= nullptr*/)
	: QScrollBar(orientation, parent)
{
	m_maximum = QScrollBar::maximum();
	m_minimum = QScrollBar::minimum();
	m_value = QScrollBar::value();

	setContextMenuPolicy(Qt::PreventContextMenu);
	createConnections();
}

void ScrollBar::createConnections() {
	connect(this, &QScrollBar::valueChanged, this, [this](qint64 value) {
		if (m_maximum > INT_MAX) {
			value *= (double)m_maximum / INT_MAX;
		}

		if (m_value != value) {
			qint64 oldValue = m_value;
			m_value = value;

			emit valueChanged(m_value, oldValue);
		}
	});

	connect(this, &QScrollBar::actionTriggered, this, [this](int action) {
		qint64 oldValue = m_value;

		switch (action) {
		case QAbstractSlider::SliderMove:
			if (m_maximum > INT_MAX) {
				m_value = (QScrollBar::sliderPosition() * ((double)m_maximum / INT_MAX));
			} else {
				m_value = QScrollBar::sliderPosition();
			}
			break;
		case QAbstractSlider::SliderPageStepAdd:
			m_value = std::min(m_maximum, m_value + pageStep());
			break;
		case QAbstractSlider::SliderPageStepSub:
			m_value = std::max(m_minimum, m_value - pageStep());
			break;
		case QAbstractSlider::SliderSingleStepAdd:
			m_value = std::min(m_maximum, m_value + singleStep());
			break;
		case QAbstractSlider::SliderSingleStepSub:
			m_value = std::max(m_minimum, m_value - singleStep());
			break;
		case QAbstractSlider::SliderToMaximum:
			m_value = m_maximum;
			break;
		case QAbstractSlider::SliderToMinimum:
			m_value = m_minimum;
			break;
		}

		if (m_maximum > INT_MAX) {
			Q_ASSERT(QScrollBar::maximum() == INT_MAX);
			QScrollBar::setSliderPosition(m_value * ((double)INT_MAX / m_maximum));
		}

		if (m_value != oldValue) {
			emit valueChanged(m_value, oldValue);
		}
	});
}

bool ScrollBar::setMaximum(qint64 maximum) {
	return setRange(std::min(m_minimum, maximum), maximum);
}

bool ScrollBar::setMinimum(qint64 minimum) {
	return setRange(minimum, std::max(minimum, m_maximum));
}

bool ScrollBar::setPage(int page) {
	if (page > 0 && page != QScrollBar::pageStep()) {
		QScrollBar::setPageStep(page);
		emit pageChanged(page);

		return true;
	}
	return false;
}

bool ScrollBar::setRange(qint64 minimum, qint64 maximum) {
	if (minimum >= 0 && minimum <= maximum && (m_minimum != minimum || m_maximum != maximum)) {
		m_maximum = maximum;
		m_minimum = minimum;

		QScrollBar::setRange(
			(m_minimum > INT_MAX) ? INT_MAX : m_minimum,
			(m_maximum > INT_MAX) ? INT_MAX : m_maximum
		);
		emit rangeChanged(minimum, maximum);

		return true;
	}
	return false;
}

bool ScrollBar::setSingleStep(int singleStep) {
	if (singleStep > 0 && singleStep != QScrollBar::singleStep()) {
		QScrollBar::setSingleStep(singleStep);
		emit singleStepChanged(singleStep);

		return true;
	}
	return false;
}

bool ScrollBar::setValue(qint64 value) {
	value = qBound(m_minimum, value, m_maximum);

	if (m_value != value) {
		qint64 oldValue = m_value;
		m_value = value;

		if (m_maximum > INT_MAX) {
			value *= (double)INT_MAX / m_maximum;
		}
		
		{
			QSignalBlocker blocker(this);
			QScrollBar::setValue(value);
		}
		emit valueChanged(m_value, oldValue);

		return true;
	}
	return false;
}
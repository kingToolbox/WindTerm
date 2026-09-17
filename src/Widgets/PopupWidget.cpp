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

#include "PopupWidget.h"

#include <QAction>
#include <QApplication>
#include <QGuiApplication>
#include <QMouseEvent>
#include <QPropertyAnimation>
#include <QScreen>
#include <QStyle>
#include <QToolButton>
#include <QVBoxLayout>

#define TRIANGLE_HEIGHT 18

PopupWidget::PopupWidget(QWidget *parent /*= nullptr*/)
	: QFrame(parent)
{
	setWindowFlags(Qt::Window
					| Qt::FramelessWindowHint
					| Qt::WindowStaysOnTopHint
					| Qt::X11BypassWindowManagerHint
					| Qt::WindowDoesNotAcceptFocus);

	setAttribute(Qt::WA_ShowWithoutActivating, true);
	setAttribute(Qt::WA_X11DoNotAcceptFocus, true);
	setAttribute(Qt::WA_DeleteOnClose, true);
	setFocusPolicy(Qt::NoFocus);
	setFrameShape(QFrame::StyledPanel);
	setMouseTracking(true);
	createLayout();
}

PopupWidget::~PopupWidget() {
	if (QAbstractButton *button = dynamic_cast<QAbstractButton *>(parent())) {
		if (QToolButton *toolButton = dynamic_cast<QToolButton *>(parent())) {
			if (QAction *action = toolButton->defaultAction()) {
				action->setChecked(false);
			}
		}
		button->setChecked(false);
	}
	// Kill any running effect
	stopFade();
}

void PopupWidget::startFadeIn(int duration) {
	stopFade();

	setWindowOpacity(0.0);

	m_fadeAnimation = new QPropertyAnimation(this, "windowOpacity", this);
	m_fadeAnimation->setDuration(duration);
	m_fadeAnimation->setStartValue(0.0);
	m_fadeAnimation->setEndValue(1.0);
	m_fadeAnimation->setEasingCurve(QEasingCurve::OutQuad);
	// Not DeleteWhenStopped: that schedules a deleteLater() on stop(), which
	// would race the explicit teardown in stopFade(). The animation is
	// parented to this widget and dies with it instead.
	m_fadeAnimation->start();
}

void PopupWidget::stopFade() {
	if (m_fadeAnimation) {
		m_fadeAnimation->stop();
		m_fadeAnimation->deleteLater();
		m_fadeAnimation = nullptr;
	}
	setWindowOpacity(1.0);
}

void PopupWidget::createLayout() {
	QVBoxLayout *vBoxLayout = new QVBoxLayout;
	vBoxLayout->setSpacing(0);

	setLayout(vBoxLayout);
}

bool PopupWidget::eventFilter(QObject *watched, QEvent *event) {
	switch (event->type()) {
	case QEvent::FocusOut:
		if (QWidget *widget = dynamic_cast<QWidget *>(watched)) {
			if (isAncestorOf(widget) == false && QApplication::activePopupWidget() == nullptr) {
				bool hasMenuAncestor = false;

				do {
					if (widget->inherits("QMenu")) {
						hasMenuAncestor = true;
						break;
					}
				} while ((widget = widget->parentWidget()) != nullptr);

				if (hasMenuAncestor == false) {
					close();
				}
			}
		}
		break;
	case QEvent::KeyPress: {
		if (QKeyEvent *keyEvent = dynamic_cast<QKeyEvent *>(event)) {
			QWidget *activePopupWidget = QApplication::activePopupWidget();
			
			if (keyEvent->matches(QKeySequence::Cancel)) {				
				if (activePopupWidget) {
					activePopupWidget->close();
				} else {
					close();
				}
				return true;
			} else if (isAncestorOf(QApplication::focusWidget()) == false) {
				if (activePopupWidget == nullptr) {
					close();
				}
			}
		}
		break;
	}
	case QEvent::NonClientAreaMouseButtonPress:
	case QEvent::WindowStateChange:
		close();
		break;
	case QEvent::MouseButtonPress: {
		if (QMouseEvent *mouseEvent = dynamic_cast<QMouseEvent *>(event)) {
			do {
				// globalPos() is deprecated since Qt 6.0.
				QPoint globalPos = mouseEvent->globalPosition().toPoint();

				if (rect().contains(mapFromGlobal(globalPos)))
					break;

				if (QAbstractButton *button = dynamic_cast<QAbstractButton *>(parentWidget())) {
					if (button->rect().contains(button->mapFromGlobal(globalPos))) {
						break;
					}
				}
				setAttribute(Qt::WA_NoMouseReplay);
				close();
			} while (0);
		}
		break;
	}
	case QEvent::WindowDeactivate: {
		if (QWidget *parentWidget = this->parentWidget()) {
			if (parentWidget->isAncestorOf(QApplication::focusWidget()) == false) {
				close();
			}
		}
		break;
	}
	}
	return false;
}

void PopupWidget::mousePressEvent(QMouseEvent *event) {
	setAttribute(Qt::WA_NoMouseReplay);
	QWidget::mousePressEvent(event);
}

void PopupWidget::setCentralWidget(QWidget *widget) {
	widget->layout()->setContentsMargins(QMargins());
	widget->setParent(this);
	layout()->addWidget(widget);
	adjustSize();
}

void PopupWidget::show(Area hArea, Area vArea) {
	Q_ASSERT(parentWidget() != nullptr);

	if (QWidget *parent = parentWidget()) {
		QPoint newPos;
		QPolygon triPolygon;
		QRect rectPolygon;

		QPoint pos = parent->mapToGlobal(QPoint());
		QRect rect = parent->rect();
		// QDesktopWidget was removed in Qt 6; the widget's own QScreen is the
		// direct replacement and is also more correct on mixed-DPI setups.
		const QScreen *widgetScreen = screen() ? screen() : QGuiApplication::primaryScreen();
		QRect screenRect = widgetScreen ? widgetScreen->availableGeometry() : QRect();

		int topMargin = style()->pixelMetric(QStyle::PM_LayoutTopMargin);
		int bottomMargin = style()->pixelMetric(QStyle::PM_LayoutBottomMargin);
		int leftMargin = style()->pixelMetric(QStyle::PM_LayoutLeftMargin);
		int rightMargin = style()->pixelMetric(QStyle::PM_LayoutRightMargin);
		int triangleHeight = std::max(TRIANGLE_HEIGHT, topMargin);

		if (pos.y() < height()) {
			if (vArea == TopArea) {
				vArea = BottomArea;
			}
		} else {
			if (vArea == BottomArea && screenRect.height() - pos.y() - rect.height() < height()) {
				vArea = TopArea;
			}
		}

		if (hArea == MiddleArea) {
			newPos.setX(qBound(0, pos.x() + (rect.width() - width()) / 2, screenRect.width() - width()));
		} else {
			if (hArea == LeftArea) {
				if (pos.x() + rect.width() < width()) {
					hArea = RightArea;
				}
			} else {
				if (screenRect.width() - pos.x() < width()) {
					hArea = LeftArea;
				}
			}
			newPos.setX((hArea == LeftArea) ? pos.x() + rect.width() - width() : pos.x());
		}
		newPos.setY((vArea == BottomArea) ? pos.y() + rect.height() : pos.y() - height() - triangleHeight);

		int xCenter = pos.x() + (rect.width() / 2) - newPos.x();

		if (vArea == TopArea) {
			triPolygon << QPoint(xCenter - triangleHeight, height())
					   << QPoint(xCenter, height() + triangleHeight)
					   << QPoint(xCenter + triangleHeight, height());
			rectPolygon = QRect(0, 0, width(), height());
			layout()->setContentsMargins(leftMargin, topMargin, rightMargin, bottomMargin + triangleHeight * 2);
		} else {
			triPolygon << QPoint(xCenter - triangleHeight, triangleHeight)
					   << QPoint(xCenter, 0)
					   << QPoint(xCenter + triangleHeight, triangleHeight);
			rectPolygon = QRect(0, triangleHeight, width(), height());
			layout()->setContentsMargins(leftMargin, topMargin + triangleHeight, rightMargin, bottomMargin);
		}

		QRegion triangle(triPolygon);
		QRegion rectangle(rectPolygon, QRegion::Rectangle);
		QRegion mask = rectangle.united(triangle);
		setMask(mask);

		move(newPos);
		QWidget::show();

		startFadeIn(200);
		qApp->installEventFilter(this);
	}
}
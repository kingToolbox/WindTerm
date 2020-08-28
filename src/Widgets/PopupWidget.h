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

#ifndef POPUPWIDGET_H
#define POPUPWIDGET_H

#pragma once

#include <QFrame>

class PopupWidget : public QFrame
{
	Q_OBJECT

public:
	explicit PopupWidget(QWidget *parent = nullptr);
	virtual ~PopupWidget();

	enum Area { LeftArea, MiddleArea, RightArea, TopArea, BottomArea };

public:
	void setCentralWidget(QWidget *widget);
	void show(Area hArea, Area vArea);

private:
	void createLayout();
	bool eventFilter(QObject *watched, QEvent *event) override;
	void mousePressEvent(QMouseEvent *event) override;

private:
	Q_DISABLE_COPY(PopupWidget)
};

#endif // POPUPWIDGET_H
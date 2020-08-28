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

#ifndef CRYPTOGRAPHIC_H
#define CRYPTOGRAPHIC_H

#pragma once

class QByteArray;

class Cryptographic {
public:
	Cryptographic() = default;

	static QByteArray decrypt(const QByteArray &data, const QByteArray &pbkdf2);
	static QByteArray encrypt(const QByteArray &data, const QByteArray &pbkdf2);
	static QByteArray pbkdf2(const QByteArray &password, const QByteArray &salt);
	static QByteArray salt();

private:
	static QByteArray doCrypt(QByteArray data, const QByteArray &key, const QByteArray &iv, int enc);
	static QByteArray iv(const QByteArray &pbkdf2);
	static QByteArray key(const QByteArray &pbkdf2);
};

#endif // CRYPTOGRAPHIC_H
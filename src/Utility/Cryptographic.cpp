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

#include "Cryptographic.h"

#include <QByteArray>
#include <qpassworddigestor.h>
#include <QRandomGenerator>

#include "openssl/evp.h"

constexpr int AES_256_IV_LENGTH			= 16;
constexpr int AES_256_KEY_LENGTH		= 32;
constexpr int PBKDF2_LENGTH				= AES_256_IV_LENGTH + AES_256_KEY_LENGTH;
constexpr int PBKDF2_ITERATION_COUNT	= 100000;

QByteArray Cryptographic::decrypt(const QByteArray &data, const QByteArray &pbkdf2) {
	return doCrypt(QByteArray::fromBase64(data), Cryptographic::key(pbkdf2), Cryptographic::iv(pbkdf2), 0);
}

QByteArray Cryptographic::doCrypt(QByteArray data, const QByteArray &key, const QByteArray &iv, int enc) {
	QByteArray crypted(data.length() + EVP_MAX_BLOCK_LENGTH, '\0');
	int cryptedLength = 0;
	int length;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	EVP_CipherInit_ex(
		ctx,
		EVP_aes_256_cbc(),
		nullptr,
		reinterpret_cast<const uchar *>(key.constData()),
		reinterpret_cast<const uchar *>(iv.constData()),
		enc
	);

	EVP_CipherUpdate(
		ctx,
		reinterpret_cast<uchar *>(crypted.data()),
		&length,
		reinterpret_cast<const uchar *>(data.constData()),
		data.length()
	);
	cryptedLength += length;

	EVP_CipherFinal_ex(ctx, reinterpret_cast<uchar *>(crypted.data() + cryptedLength), &length);
	cryptedLength += length;

	EVP_CIPHER_CTX_free(ctx);

	crypted.resize(cryptedLength);
	return crypted;
}

QByteArray Cryptographic::encrypt(const QByteArray &data, const QByteArray &pbkdf2) {
	QByteArray encrypted = doCrypt(data, Cryptographic::key(pbkdf2), Cryptographic::iv(pbkdf2), 1);
	return encrypted.toBase64();
}

QByteArray Cryptographic::iv(const QByteArray &pbkdf2) {
	Q_ASSERT(pbkdf2.length() == PBKDF2_LENGTH);
	return QByteArray::fromRawData(pbkdf2.constData() + AES_256_KEY_LENGTH, AES_256_IV_LENGTH);
}

QByteArray Cryptographic::key(const QByteArray &pbkdf2) {
	Q_ASSERT(pbkdf2.length() == PBKDF2_LENGTH);
	return QByteArray::fromRawData(pbkdf2.constData(), AES_256_KEY_LENGTH);
}

QByteArray Cryptographic::pbkdf2(const QByteArray &password, const QByteArray &salt) {
	return QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha3_512, password, salt, PBKDF2_ITERATION_COUNT, PBKDF2_LENGTH);
}

QByteArray Cryptographic::salt() {
	QByteArray number = QByteArray::number(QRandomGenerator::system()->generate64());
	QByteArray numberHash = QCryptographicHash::hash(number, QCryptographicHash::Sha512);
	return numberHash.toBase64();
}

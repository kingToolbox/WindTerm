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

#ifndef CIRCULARBUFFER_H
#define CIRCULARBUFFER_H

#pragma once

#include <QtAlgorithms>
#include <QtGlobal>

#define ROUND_UP_POW2(value)	{ (1 << (32 - qCountLeadingZeroBits(value))) }

template <typename T>
class CircularBuffer {
public:
	CircularBuffer(quint32 capacity)
		: m_currentIndex(0) {
		Q_ASSERT(capacity < (1 << 31));

		m_capacity = ROUND_UP_POW2(capacity);
		m_mask = m_capacity - 1;
		m_buffer = static_cast<qint64 *>(calloc(m_capacity, sizeof(qint64)));

		clear();
	}

	~CircularBuffer() {
		free(m_buffer);
		m_buffer = nullptr;
	}

	void append(const T &value) {
		m_buffer[++m_currentIndex & m_mask] = value;
	}

	const T &at(qint64 index) const {
		Q_ASSERT(index >= std::max<qint64>(0, m_currentIndex + 1 - m_capacity) && index <= m_currentIndex);
		return m_buffer[index & m_mask];
	}

	int capacity() const { return m_capacity; }
	void clear() {
		m_currentIndex = -1;
		memset(m_buffer, 0xFF, m_capacity * sizeof(qint64));

#ifdef _DEBUG
		for (int i = 0; i < m_capacity; i++) {
			Q_ASSERT(m_buffer[i] == -1);
		}
#endif // _DEBUG
	}

	qint64 currentIndex() const { return m_currentIndex; }
	qint64 minIndex() const { return std::max<qint64>(0, m_currentIndex + 1 - m_capacity); }

	const T &operator [](qint64 index) const {
		Q_ASSERT(index >= std::max<qint64>(0, m_currentIndex + 1 - m_capacity) && index <= m_currentIndex);
		return m_buffer[index & m_mask];
	}

private:
	T *m_buffer;
	qint64 m_currentIndex;

	int m_capacity;
	int m_mask;
};

class Int64CircularBuffer : public CircularBuffer<qint64> {
public:
	Int64CircularBuffer(quint32 capacity)
		: CircularBuffer<qint64>(capacity)
	{}
};

#endif // CIRCULARBUFFER_H
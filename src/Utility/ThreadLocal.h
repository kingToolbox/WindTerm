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

#ifndef THREADLOCAL_H
#define THREADLOCAL_H

#include <QObject>

#include <mutex>
#include <vector>
#include <boost/thread.hpp>

#include "Spin.h"

#define STATIC_LOCAL_COUNT	6

class ThreadLocalWatcher : public QObject {
	Q_OBJECT

public:
	ThreadLocalWatcher() = default;

protected:
	void stopWatchCurrentThread();
	void watchCurrentThread();
	virtual void clear(const boost::thread::id &id) = 0;

private:
	Q_DISABLE_COPY(ThreadLocalWatcher)
};

template <typename T>
class ThreadLocal : public ThreadLocalWatcher {
public:
	ThreadLocal()
		: m_mainThreadId(boost::this_thread::get_id())
	{
		for (int i = 0; i < STATIC_LOCAL_COUNT; i++) {
			m_staticLocals[i] = nullptr;
		}
	}
	
	~ThreadLocal() {
		clearAll();
	}

	void clear(const boost::thread::id &id) {
		std::lock_guard<SpinMutex> lock(m_mutex);

		if (removeLocal(id)) {
			stopWatchCurrentThread();
		}
	}

	void clearAll() {
		std::lock_guard<SpinMutex> lock(m_mutex);

		for (int i = 0; i < STATIC_LOCAL_COUNT; i++) {
			if (Local *local = m_staticLocals[i]) {
				delete local;
				m_staticLocals[i] = nullptr;
			}
		}

		if (m_dynamicLocals) {
			for (Local *local : *m_dynamicLocals) {
				delete local;
			}
			m_dynamicLocals.reset(nullptr);
		}
	}

	T *get() {
		boost::thread::id id = boost::this_thread::get_id();

		for (const Local *local : m_staticLocals) {
			if (local && local->id == id) {
				return local->ptr;
			}
		}

		if (m_dynamicLocals) {
			std::lock_guard<SpinMutex> lock(m_mutex);

			for (const Local *local : *m_dynamicLocals) {
				if (local && local->id == id) {
					return local->ptr;
				}
			}
		}
		return nullptr;
	}

	boost::thread::id mainThreadId() const {
		return m_mainThreadId;
	}

	void reset(T *t) {
		std::lock_guard<SpinMutex> lock(m_mutex);
		boost::thread::id id = boost::this_thread::get_id();

		bool removed = removeLocal(id);
		bool added = addLocal(id, t);

		if (id != m_mainThreadId) {
			if (removed) {
				if (added == false) {
					stopWatchCurrentThread();
				}
			} else {
				if (added) {
					watchCurrentThread();
				}
			}
		}
	}

private:
	bool addLocal(const boost::thread::id &id, T *t) {
		if (t == nullptr) {
			return false;
		}

		for (int i = 0; i < STATIC_LOCAL_COUNT; i++) {
			if (m_staticLocals[i] == nullptr) {
				m_staticLocals[i] = new Local(id, t);

				return true;
			}
		}

		if (m_dynamicLocals.get() == nullptr) {
			m_dynamicLocals = std::make_unique<LocalVector>();
		}
		m_dynamicLocals->push_back(new Local(id, t));
		return true;
	}

	bool removeLocal(const boost::thread::id &id) {
		for (int i = 0; i < STATIC_LOCAL_COUNT; i++) {
			Local *local = m_staticLocals[i];

			if (local && local->id == id) {
				delete local;
				m_staticLocals[i] = nullptr;

				return true;
			}
		}

		if (m_dynamicLocals) {
			for (auto it = m_dynamicLocals->begin(); it != m_dynamicLocals->end(); ++it) {
				Local *local = *it;

				if (local && local->id == id) {
					delete local;
					m_dynamicLocals->erase(it);

					return true;
				}
			}
		}
		return false;
	}

private:
	Q_DISABLE_COPY(ThreadLocal)

	struct Local {
		boost::thread::id id;
		T *ptr;

		Local(boost::thread::id id_, T *ptr_)
			: id(id_)
			, ptr(ptr_)
		{}

		~Local() {
			delete ptr;
			ptr = nullptr;
		}
	};
	typedef std::vector<Local *> LocalVector;
	std::unique_ptr<LocalVector> m_dynamicLocals;

	Local *m_staticLocals[STATIC_LOCAL_COUNT];

	boost::thread::id m_mainThreadId;
	SpinMutex m_mutex;
};

#endif // THREADLOCAL_H
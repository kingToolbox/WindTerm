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

#ifndef SCOPEGUARD_H
#define SCOPEGUARD_H

class ScopeGuard {
	typedef std::function<void()> GuardFunction;

public:
	ScopeGuard(GuardFunction acquire, GuardFunction release)
		: m_active(true)
		, m_release(std::move(release))
	{
		acquire();
	}

	~ScopeGuard() {
		if (m_active) {
			m_release();
		}
	}

	ScopeGuard() = delete;
	ScopeGuard(const ScopeGuard &) = delete;
	ScopeGuard &operator=(const ScopeGuard &) = delete;

	ScopeGuard(ScopeGuard &&other)
		: m_active(other.m_active)
		, m_release(std::move(other.m_release))
	{
		other.cancel();
	}

	void cancel() {
		m_active = false;
	}
	
private:
	bool m_active;
	GuardFunction m_release;
};

#endif // SCOPEGUARD_H

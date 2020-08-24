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

#include "TelnetProtocol.h"

#include <iomanip>
#include <mutex>
#include <sstream>

const char *arrTelnetCmds[] =
{
  "XEOF",  "SUSP",  "ABORT", "EOR",  "SE",
  "NOP",   "DM",    "BREAK", "IP",   "AO",
  "AYT",   "EC",    "EL",    "GA",   "SB",
  "WILL",  "WONT",  "DO",    "DONT", "IAC"
};

const char *arrTelnetOpts[] =
{
	"BINARY", "ECHO", "RCP", "SUPPRESS GO AHEAD", "NAME", "STATUS", "TIMING MARK", "RCTE", 
	"NAOL", "NAOP", "NAOCRD", "NAOHTS", "NAOHTD", "NAOFFD", "NAOVTS", "NAOVTD", 
	"NAOLFD", "EXTEND ASCII", "LOGOUT", "BYTE MACRO", "DATA ENTRY TERMINAL", "SUPDUP", "SUPDUP OUTPUT", "SEND LOCATION",
	"TERMINAL TYPE", "END OF RECORD", "TACACS UID", "OUTPUT MARKING", "TTYLOC", "3270 REGIME", "X.3 PAD", "NAWS",
	"TSPEED", "LFLOW", "LINEMODE", "XDISPLOC", "OLD ENVIRON", "AUTHENTICATION", "ENCRYPT", "NEW ENVIRON", 
	"TN3270E", "XAUTH", "CHARSET", "RSP", "COM PORT CONTROL", "SUPPRESS LOCAL ECHO", "START TLS", "KERMIT", 
	"SEND-URL", "FORWARD_X",
};

std::string TelnetProtocol::GetCommandName(uchar chTelnetCmd)
{
	if (chTelnetCmd >= TELCMD_XEOF && chTelnetCmd <= TELCMD_IAC)
		return arrTelnetCmds[chTelnetCmd - TELCMD_XEOF];

	std::ostringstream oss;
	oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)chTelnetCmd << "(Unknown Telnet Command)";
	return oss.str();
}

std::string TelnetProtocol::GetOptionName(uchar chTelnetOption)
{
	if (chTelnetOption >= TELOPT_BINARY && chTelnetOption <= TELOPT_FORWARD_X) { return arrTelnetOpts[chTelnetOption - TELOPT_BINARY];} 
	else if (chTelnetOption == TELOPT_MCCP1) { return "MUD COMPRESSION PROTOCOL (V1)"; }
	else if (chTelnetOption == TELOPT_MCCP2) { return "MUD COMPRESSION PROTOCOL (V2)"; }
	else if (chTelnetOption == TELOPT_MSP) { return "MUD SOUND PROTOCOL"; }
	else if (chTelnetOption == TELOPT_MXP) { return "MUD EXTENSION PROTOCOL";}
	else if (chTelnetOption == TELOPT_PRAGMA_LOGON) { return "TELOPT PRAGMA LOGON"; }
	else if (chTelnetOption == TELOPT_SSPI_LOGON) { return "TELOPT SSPI LOGON"; }
	else if (chTelnetOption == TELOPT_PRAGMA_HEARTBEAT) { return "TELOPT PRAGMA HEARTBEAT"; }
	else if (chTelnetOption == TELOPT_EXOPL) { return "EXTENDED OPTIONS LIST"; }

	std::ostringstream oss;
	oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)chTelnetOption << "(Unknown Telnet Option)";
	return oss.str();
}

TelnetOptionVector &TelnetProtocol::GetOptionVector()
{
	static TelnetOptionVector m_vTelnetOption;
	static std::once_flag flag;

	std::call_once(flag, [&]() {
		m_vTelnetOption.clear();
		m_vTelnetOption.resize(TELOPT_INDEX_MAX);

		m_vTelnetOption[TELOPT_INDEX_NAWS].Init(TELOPT_NAWS, TELNET_CLIENT, TELOPT_STATE_INACTIVE_REQUESTED);
		m_vTelnetOption[TELOPT_INDEX_TTYPE].Init(TELOPT_TTYPE, TELNET_CLIENT, TELOPT_STATE_INACTIVE_REQUESTED);
		m_vTelnetOption[TELOPT_INDEX_ECHO].Init(TELOPT_ECHO, TELNET_SERVER, TELOPT_STATE_INACTIVE_REQUESTED);
		m_vTelnetOption[TELOPT_INDEX_SERVER_SGA].Init(TELOPT_SGA, TELNET_SERVER, TELOPT_STATE_INACTIVE_REQUESTED);
		m_vTelnetOption[TELOPT_INDEX_CLIENT_SGA].Init(TELOPT_SGA, TELNET_CLIENT, TELOPT_STATE_INACTIVE_REQUESTED);
		m_vTelnetOption[TELOPT_INDEX_SERVER_BIN].Init(TELOPT_BINARY, TELNET_SERVER, TELOPT_STATE_INACTIVE);
		m_vTelnetOption[TELOPT_INDEX_CLIENT_BIN].Init(TELOPT_BINARY, TELNET_CLIENT, TELOPT_STATE_INACTIVE);
	});

	return m_vTelnetOption;
}

TelnetProtocol::TelnetProtocol()
{
	m_name = "Telnet";
}

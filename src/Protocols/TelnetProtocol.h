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

#ifndef TELNETPROTOCOL_H
#define TELNETPROTOCOL_H

#pragma once

#include <vector>
#include "Protocol.h"

typedef unsigned char uchar;

/* TELNET Command Codes: */
constexpr uchar TELCMD_XEOF				= 236;	/* End of file: EOF is already used	*/
constexpr uchar TELCMD_SUSP				= 237;	/* Suspend process					*/
constexpr uchar TELCMD_ABORT			= 238;	/* Abort process					*/
constexpr uchar TELCMD_EOR				= 239;	/* end of record (transparent mode)	*/
constexpr uchar TELCMD_SE				= 240;	/* end sub negotiation				*/
constexpr uchar TELCMD_NOP				= 241;	/* nop								*/
constexpr uchar TELCMD_DM				= 242;	/* data mark--for connect. cleaning	*/
constexpr uchar TELCMD_BREAK			= 243;	/* break							*/
constexpr uchar TELCMD_IP				= 244;	/* interrupt process--permanently	*/
constexpr uchar TELCMD_AO				= 245;	/* abort output--but let prog finish*/
constexpr uchar TELCMD_AYT				= 246;	/* are you there					*/
constexpr uchar TELCMD_EC				= 247;	/* erase the current character		*/
constexpr uchar TELCMD_EL				= 248;	/* erase the current line			*/
constexpr uchar TELCMD_GA				= 249;	/* you may reverse the line			*/
constexpr uchar TELCMD_SB				= 250;	/* interpret as subnegotiation		*/
constexpr uchar TELCMD_WILL				= 251;	/* I will use option				*/
constexpr uchar TELCMD_WONT				= 252;	/* I won't use option				*/
constexpr uchar TELCMD_DO				= 253;	/* please, you use option			*/
constexpr uchar TELCMD_DONT				= 254;	/* you are not to use option		*/
constexpr uchar TELCMD_IAC				= 255;	/* interpret as command				*/

/* The telnet options represented as strings */
constexpr uchar TELOPT_BINARY			= 0;   // Binary Transmission - RFC 856
constexpr uchar TELOPT_ECHO				= 1;   // Echo                - RFC 857
constexpr uchar TELOPT_RCP				= 2;   // Reconnection
constexpr uchar TELOPT_SGA				= 3;   // Suppress Go Ahead   - RFC 858
constexpr uchar TELOPT_NAMS				= 4;   // Approx Message Size Negotiation
constexpr uchar TELOPT_STATUS			= 5;   // Status              - RFC 859
constexpr uchar TELOPT_TM				= 6;   // Timing Mark         - RFC 860
constexpr uchar TELOPT_RCTE				= 7;   // Remote controlled transmission and echo - RFC 563,726
constexpr uchar TELOPT_NAOL				= 8;   // Negotiate about output line width - NIC50005
constexpr uchar TELOPT_NAOP				= 9;   // Negotiate about output page size - NIC50005
constexpr uchar TELOPT_NAOCRD			= 10;  // Negotiate about CR disposition - RFC 652
constexpr uchar TELOPT_NAOHTS			= 11;  // Negotiate about horizontal tabstops - RFC 653
constexpr uchar TELOPT_NAOHTD			= 12;  // Negotiate about horizontal tab disposition - RFC 654
constexpr uchar TELOPT_NAOFFD			= 13;  // Negotiate about formfeed disposition - RFC 655
constexpr uchar TELOPT_NAOVTS			= 14;  // Negotiate about vertical tab stops - RFC 656
constexpr uchar TELOPT_NAOVTD			= 15;  // Negotiate about vertical tab disposition - RFC 657
constexpr uchar TELOPT_NAOLFD			= 16;  // Negotiate about output LF disposition - RFC 658
constexpr uchar TELOPT_XASCII			= 17;  // Extended ascic character set - RFC 698
constexpr uchar TELOPT_LOGOUT			= 18;  // Force logout             - RFC 727
constexpr uchar TELOPT_BM				= 19;  // Byte Macro         - RFC 735
constexpr uchar TELOPT_DET				= 20;  // Data Entry Terminal - RFC 732,1043
constexpr uchar TELOPT_SUPDUP			= 21;  // SUPDUP Protocol             - RFC 734,736
constexpr uchar TELOPT_SUPDUPOUTPUT		= 22;  // SUPDUP Output      - RFC 749
constexpr uchar TELOPT_SNDLOC			= 23;  // Send Location      - RFC 779
constexpr uchar TELOPT_TTYPE			= 24;  // Terminal Type      - RFC 1091
constexpr uchar TELOPT_EOR				= 25;  // End of Record      - RFC 885
constexpr uchar TELOPT_TUID				= 26;  // TACACS User Identification - RFC 927
constexpr uchar TELOPT_OUTMRK			= 27;  // Output Marking     - RFC 933
constexpr uchar TELOPT_TTYLOC			= 28;  // Terminal Location Number - RFC 946
constexpr uchar TELOPT_3270REGIME		= 29;  // Telnet 3270 Regime - RFC 1041
constexpr uchar TELOPT_X3PAD			= 30;  // X.3 PAD            - RFC 1053
constexpr uchar TELOPT_NAWS				= 31;  // Negotiate window size - RFC 1073
constexpr uchar TELOPT_TSPEED			= 32;  // Terminal Speed     - RFC 1079
constexpr uchar TELOPT_LFLOW			= 33;  // Remote Flow Control - RFC 1372
constexpr uchar TELOPT_LINEMODE			= 34;  // Linemode option     - RFC 1184
constexpr uchar TELOPT_XDISPLOC			= 35;  // X Display Location - RFC 1096
constexpr uchar TELOPT_OLD_ENVIRON		= 36;  // Environment Option - RFC 1408
constexpr uchar TELOPT_AUTHENTICATION	= 37;  // Authenticate - RFC 1416,2941,2942,2943,2951
constexpr uchar TELOPT_ENCRYPT			= 38;  // Encryption Option - RFC 2946
constexpr uchar TELOPT_NEW_ENVIRON		= 39;  // New Environment Option - RFC 1572
constexpr uchar TELOPT_TN3270E			= 40;  // TN3270 enhancements    - RFC 2355
constexpr uchar TELOPT_XAUTH			= 41;  // XAUTH
constexpr uchar TELOPT_CHARSET			= 42;  // Negotiate charset to use - RFC 2066
constexpr uchar TELOPT_RSP				= 43;  // Telnet remote serial port
constexpr uchar TELOPT_COM_PORT_OPTION	= 44;  // Com port control option - RFC 2217
constexpr uchar TELOPT_SLE				= 45;  // Telnet suppress local echo
constexpr uchar TELOPT_STARTTLS			= 46;  // Telnet Start TLS
constexpr uchar TELOPT_KERMIT			= 47;  // Automatic Kermit file transfer - RFC 2840
constexpr uchar TELOPT_SEND_URL			= 48;  // Send URL
constexpr uchar TELOPT_FORWARD_X		= 49;  // X forwarding
constexpr uchar TELOPT_MCCP1            = 85;  // Mud Compression Protocol (v1)
constexpr uchar TELOPT_MCCP2            = 86;  // Mud Compression Protocol (v2)
constexpr uchar TELOPT_MSP              = 90;  // Mud Sound Protocol
constexpr uchar TELOPT_MXP              = 91;  // Mud eXtension Protocol
constexpr uchar TELOPT_ZMP				= 93;	// Zenith Mud Protocol
constexpr uchar TELOPT_PRAGMA_LOGON		= 138; // Telnet option pragma logon
constexpr uchar TELOPT_SSPI_LOGON		= 139; // Telnet option SSPI login
constexpr uchar TELOPT_PRAGMA_HEARTBEAT	= 140; // Telnet option pragma heartbeat
constexpr uchar TELOPT_GMCP				= 201; // Generic Mud Communication Protocol
constexpr uchar TELOPT_EXOPL			= 255; // extended-options-list - RFC 861

/* Option Subnegotiation Constants: */
constexpr uchar TELSUB_IS				= 0;   // An option IS
constexpr uchar TELSUB_SEND				= 1;   // Send an option
constexpr uchar TELSUB_INFO				= 2;   // Environ: informational version of IS
constexpr uchar TELSUB_NAME				= 3;

/* Keyboard Command Characters: */
constexpr char TELKEY_LF				= '\n';	// Line Feed
constexpr char TELKEY_CR				= '\r';	// Carriage Return
constexpr char TELKEY_BEL				= '\a';	// Bell (attention signal)
constexpr char TELKEY_BS				= '\b';	// Back Space
constexpr char TELKEY_HT				= '\t';	// Horizontal Tab
constexpr char TELKEY_VT				= '\v';	// Vertical Tab
constexpr char TELKEY_FF				= '\f';	// Form Feed

enum TelnetOptionIndex : uchar {
	TELOPT_INDEX_NAWS,
	TELOPT_INDEX_TSPEED,
	TELOPT_INDEX_TTYPE,
	TELOPT_INDEX_NEW_ENVIRON,
	TELOPT_INDEX_LFLOW,
	TELOPT_INDEX_LINEMODE,
	TELOPT_INDEX_ECHO,
	TELOPT_INDEX_SERVER_SGA,
	TELOPT_INDEX_CLIENT_SGA,
	TELOPT_INDEX_SERVER_BIN,
	TELOPT_INDEX_CLIENT_BIN,
	TELOPT_INDEX_MAX
};

enum TelnetAction : uchar {
	TELACT_ABORT,	// Abort Process
	TELACT_AO,		// Abort Output
	TELACT_AYT,		// Are You There
	TELACT_BREAK,	// serial-line break
	TELACT_EC,		// Erase Character
	TELACT_EL,		// Erase Line
	TELACT_EOF,		// end-of-file on session input
	TELACT_EOL,		// Telnet end-of-line sequence (CRLF, as opposed to CR NUL that escapes a literal CR)
	TELACT_EOR,		// End Of Record
	TELACT_GA,		// Go Ahead
	TELACT_IP,		// Interrupt Process
	TELACT_NOP,		// transmit data with no effect
	TELACT_SUSP		// Suspend Process
};

enum TelnetSide : uchar {
	TELNET_SERVER,
	TELNET_CLIENT
};

#define BIT_INACTIVE	0x00
#define BIT_ACTIVE		0x01
#define BIT_REQUESTED	0x10

enum TelnetOptionState {
	TELOPT_STATE_INACTIVE = BIT_INACTIVE,
	TELOPT_STATE_ACTIVE = BIT_ACTIVE,
	TELOPT_STATE_INACTIVE_REQUESTED = BIT_INACTIVE | BIT_REQUESTED,
	TELOPT_STATE_ACTIVE_REQUESTED = BIT_ACTIVE | BIT_REQUESTED 
};

struct TelnetOption {
	int nTelnetOption;

	TelnetSide eTelnetSide;
	TelnetOptionState eOptionState;

	TelnetOption() :
	  nTelnetOption(-1),
	  eTelnetSide(TELNET_SERVER),
	  eOptionState(TELOPT_STATE_INACTIVE)
	{}

	void Init(uchar _nTelnetOption, TelnetSide _eTelnetSide, TelnetOptionState _eOptionState)
	{
		nTelnetOption = _nTelnetOption;
		eTelnetSide = _eTelnetSide;
		eOptionState = _eOptionState;
	}
};
typedef std::vector<TelnetOption> TelnetOptionVector;
typedef std::vector<TelnetOptionState> TelnetOptionStateVector;

class TelnetProtocol : public Protocol
{
public:
	TelnetProtocol();

	std::string GetCommandName(uchar chTelnetCmd);
	std::string GetOptionName(uchar chTelnetOpt);
	
	TelnetOptionVector &GetOptionVector();
};

#endif // TELNETPROTOCOL_H
# WindTerm
A professional SSH/Telnet/Serial/Shell/Sftp client for DevOps.

_Hello WindTerm :rose:, hello world!_

**We're just beginning! If you want a high performance text editor, you can try [WindEdit](https://www.github.com/kingToolbox/DIGEdit/).**

# License
**Completely FREE for commercial and non-commercial use without limitations.**
**All released source codes (except thirdparty directory) are provided under the terms of Apache-2.0 license.**

# Introduction

See [Intro Videos](https://kingtoolbox.github.io)

# Download

Windows Binary: https://github.com/kingToolbox/WindTerm/releases

(The binary of Macos and Linux will be committed later)

# Source Code

WindTerm is a **partial** open source project, and the source will be gradually opened.

Open source code includes, but is not limited to, the classes that can be used independently, such as functional, algorithms, gui widgets, etc., as well as functional libraries, such as network, protocols, etc., as well as all types that require open source according to the license.

# Issues and feature requests

Any issues and feature requests are welcome.

Please click [issues](https://github.com/kingToolbox/WindTerm/issues) to commit an issue or a feature request.

Please click [Discussion](https://github.com/kingToolbox/WindTerm/discussions) to discuss anything about SSH, SFtp, Shell(Linux shell, Windows cmd and powershell), Telnet, Serial and WindTerm.

# Screenshots

Main Window (zsh):

![MainWindow](https://github.com/kingToolbox/WindTerm/blob/master/images/screenshots/WindTerm.png)

Split views:

![SplitView](https://github.com/kingToolbox/WindTerm/blob/master/images/screenshots/SplitView.png)

DigeWhite Theme:

![DigeWhite Theme](https://github.com/kingToolbox/WindTerm/blob/master/images/screenshots/WindTerm_DigeWhite_Theme.png)

# Features

### SSH, Telnet, Tcp, Shell, Serial
- SSH v2, Telnet, Raw Tcp, Serial, Shell protocols implemented. [Intro Video](https://kingtoolbox.github.io/2020/01/22/new-session/)
- Supports SSH auto execution when session authenticated.
- Supports SSH agent forwarding. [Intro Video](https://kingtoolbox.github.io/2020/08/22/ssh_agent_forwarding/)
- Supports SSH auto login with password, public-key, keyboard-interactive, gssapi-with-mic. [Intro Video](https://kingtoolbox.github.io/2020/01/23/auto-login/)
- Supports X11 forwarding. [Intro Video](https://kingtoolbox.github.io/2020/07/21/x11_forwarding/)
- Supports direct/local port forwarding, reverse/remote port forwarding and dynamic port forwarding. [Intro Video](https://kingtoolbox.github.io/2020/07/21/port_forwarding/)
- Integrated sftp, scp client, supports download, upload, remove, rename, make new file/directory and so on. [Intro Video](https://kingtoolbox.github.io/tags/transfer/)
- Integrated local file manager, supports move to, copy to, copy from, remove, rename, make new file/directory and so on.
- Supports Cmd, PowerShell and Cmd, PowerShell as administrator.
### GUI
- Session dialog and session tree.
- **Command palette.** [Intro Video](https://kingtoolbox.github.io/tags/command-palette/)
- **Command sender.** [Intro Video](https://kingtoolbox.github.io/tags/sender/)
- **Quick Bar.** [Intro Video](https://kingtoolbox.github.io/2020/08/22/quickbar/)
- **Paste Dialog.** [Intro Video](https://kingtoolbox.github.io/2020/08/22/paste_dialog/)
- **Local and remote modes with vim keybindings. (Using Shift+Enter key to switch between remote and local mode**) [Intro Video](https://kingtoolbox.github.io/2020/06/21/keyboard-modes/)
- Supports time stamp, folding, outlining, split views.
- **Supports powerline in Linux and PowerShell, e.g. Oh-My-Zsh, Oh-My-Posh.** [Intro Image](https://github.com/kingToolbox/WindTerm#screenshots)
- Supports color schemes like vscode. [Intro Video](https://kingtoolbox.github.io/2020/01/23/highlight/)
- Supports searching and previewing. [Intro Video](https://kingtoolbox.github.io/2020/01/22/search-and-mark/)
- Supports highlighting the opening and closing delimiter, such as (), [], {} and the customed delimiters. [Intro Video](https://kingtoolbox.github.io/2020/06/28/pair/)
- Supports changing the UI theme. [Intro Video](https://kingtoolbox.github.io/2020/09/18/theme/)
- Supports setting the tab color. [Intro Video](https://kingtoolbox.github.io/2020/09/18/tabbar-change-tabcolor/)
- Supports closing tabs to the right.
- Supports setting the windows transparency. [Intro video](https://kingtoolbox.github.io/2020/11/13/windows-opacity/)
- Supports select-to-copy and middle-click-to-paste.
- Supports searching text online with Google, Bing, Github, Stackoverflow, Wikipedia and DuckDuckGo. [Intro video](https://kingtoolbox.github.io/2020/11/13/search-online/)
### Term
- Supports vt100, vt220, vt340, vt420, vt520, xterm, xterm-256-colors.
- Supports unicode, emojis, true-color, mouse protocol, etc.
- Supports auto wrap mode. [Intro Video](https://kingtoolbox.github.io/2020/01/22/auto-wrap/)
- Protocols and terms can be customed.
- All vttest tests have passed except Tektronix 4014.
### Session
- **Supports HTTP and SOCKS5 proxy.** [Intro Video](https://kingtoolbox.github.io/2020/10/17/proxy/)
- Supports manual and automated session logging. [Intro Video](https://kingtoolbox.github.io/tags/logging/)
- Rename and duplicate session. [Intro Video](https://kingtoolbox.github.io/tags/tabbar/)
- Restore last sessions and layouts when restart. [Intro Video](https://kingtoolbox.github.io/2020/01/22/restore-sessions/)
### Performance
- High performance, low memory, low latency. [Intro Video](https://kingtoolbox.github.io/2020/01/23/windterm-putty-performance/)

# Sftp Performance

The hardware used for generating the data in these benchmarks was

    windows 10 - 2.3 GHz Intel Core i5 and 8GB memory.

**WindTerm1.72, WindTerm 1.2, FileZilla 3.48.1, WinSCP 5.17.2 (Build 10278)** tests are performed on WSL(Ubuntu 18.04.2). 

The version of clients:

| Application | Version | Release Date |
| --- | --- | --- |
| windterm | v1.72 | 2020-10-25 |
| windterm | v1.2 | 2020-06-15 |
| FileZilla | v3.48.1 | 2020-05-19 |
| WinScp | v5.17.2 (Build 10278) | 2020-03-09 |

**All test data is for reference only.**

- 5GB huge file (5,154,830 KB), generated by random data

| | Download Time | Download Rate | Upload Time | Upload Rate |
| --- | --- | --- | --- | --- |
| WindTerm 1.72 (Use high speed transfer) | **23s** | **216.3 MB/s** | **20s** | **247.0 MB/s** |
| WindTerm 1.72 | **23s** | **214.7 MB/s** | **20s** | **244.0 MB/s** |
| WindTerm 1.2 | 37s | 139.3 MB/s | 43s | 119.9 MB/s |
| FileZilla | 32s | 161.1 MB/s | 30s | 171.8 MB/s |
| WinSCP | 81s | 63.7 MB/s | 91s | 56.7 MB/s |

- 4400 files, 16 folders (107,042 KB), unzipped from [vim-7.4.1049.zip](https://github.com/vim/vim/archive/v7.4.1049.zip)

| | Download Time | Download Rate | Upload Time | Upload Rate |
| --- | --- | --- | --- | --- |
| WindTerm 1.7 | **26s** | **3.9 MB/s** | 13s | 8.1 MB/s |
| WindTerm 1.2 | 32s | 3.4 MB/s | **10s** | **10.7 MB/s** |
| FileZilla | 48s | 2.2 MB/s | 35s | 3.1 MB/s |
| WinSCP | 42s | 2.6 MB/s | 12s | 8.9 MB/s |

# Terminal Performance

The hardware used for generating the data in these benchmarks was

    windows 10 - 2.3 GHz Intel Core i5 and 8GB memory.
    MacOs 10.13 - 2.3 GHz Intel Core i5 and 8GB memory.

**WindTerm 1.72, rxvt, putty, xterm, Windows Terminal** tests are performed on WSL(Ubuntu 18.04.2). 

**Iterm2, kitty, Alacritty** tests are performed on MacOS shell, 

    For WindTerm: No color scheme used in windterm. Color scheme will result in approximately 2% loss and more memory usage.

    For Alacritty: Only supports up to 100,000 scrollback lines, so every test use "history: 100000" setting and no memory usage measured.

    For Windows Terminal: Only supports up to 65,535 scrollback lines, so every test use "historySize: 65535" setting and no memory usage measured. 

The version of terminals:

| Application | Version | Release Date |
| --- | --- | --- |
| windterm | v1.72 | 2020-10-25 |
| rxvt-unicode | v9.2.2 | 2016-05-14 |
| putty | v0.71 | 2019-03-16 |
| xterm | v3.30 | 2017-06-20 |
| iterm2 | v3.3.6 | 2019-10-09 |
| alacritty | v0.5.0 | 2020-07-21 |
| kitty | v0.14.6 | 2019-09-25 |
| Windows Terminal | v1.3.2651.0 | 2020-09-22 |

**All test data is for reference only.**

- 97.6MB random text (102,401,504 bytes, 1,329,878 lines, generated and tested by [random_test.sh](https://github.com/kingToolbox/WindTerm/blob/master/benchmark/urandom_test.sh))

In all cases, three runs were made to warm system caches. The reported numbers are the median of five runs. 

1. Telnet:

| | Lines of scrollback | Data Rate(MB/sec) | Memory Usage(MB) |
| --- | --- | --- | --- |
| WindTerm | unlimited | **52.1** | **106.6** |
| rxvt | 1,350,000 | 37.8 | 842.2 | 
| Putty | 1,350,000 | 4.9 | 733.4 |
| xterm | 1,350,000 | 2.2 | 3328.4 |
| Windows Terminal + telnet.exe | 65,535 | 0.1 | Not measured, use 65,535 scrollback lines setting |

2. SSH:

| | Lines of scrollback | Data Rate(MB/sec) | Memory Usage(MB) |
| --- | --- | --- | --- |
| WindTerm | unlimited | **41.8** | **108.5** |
| rxvt | 1,350,000 | 40.2 | 842.2 | 
| Putty | 1,350,000 | 4.8 | 734.9 |
| xterm | 1,350,000 | 2.3 | 3328.4 |
| Windows Terminal + ssh.exe | 65,535 | 2.1 | Not measured, use 65,535 scrollback lines setting |

3. Shell:

| | Lines of scrollback | Data Rate(MB/sec) | Memory Usage(MB) |
| --- | --- | --- | --- |
| iterm2 | unlimited | - (Take too long time) | more than 1300 |
| kitty | unlimited | 17.2 | 2655 |
| Alacritty | 100,000 | 41.3 | - |

- time seq 1 n

1. n = 1,000,000, scrollback = 1,000,000 Lines

| | Time(sec) | Memory Usage(MB) |
| --- | --- | --- |
| WindTerm | 1.236 | **16.1** |
| rxvt | 5.082 | 633.3 |
| putty | 4.161 | 551.1 |
| xterm | 40.421 | 2500.7 |
| iterm2 | 2.116 | 146.3 |
| Kitty | 2.535 | 2376.5 |
| Alacritty | **1.162** | Not measured, use 100,000 scrollback lines setting |
| Windows Terminal + ssh.exe | 23.246 | Not measured, use 65,535 scrollback lines setting |

2. n = 2,000,000, scrollback = 2,000,000 Lines

| | Time(sec) | Memory Usage(MB) |
| --- | --- | --- |
| WindTerm | **2.287** | **24.1** |
| rxvt | 10.896 | 1266.6 |
| putty | 16.045 | 1102.6 |
| xterm | 68.154 | 5005.5 |
| iterm2 | 4.181 | 383.2 |
| Kitty | 5.620 | 4749.9 |
| Alacritty | 2.322 | Not measured, use 100,000 scrollback lines setting |
| Windows Terminal + ssh.exe | 50.381 | Not measured, use 65,535 scrollback lines setting |

3. n = 5,000,000 scrollback = 5,000,000 Lines

| | Time(sec) | Memory Usage(MB) |
| --- | --- | --- |
| WindTerm | **5.520** | **68.2** |
| rxvt | 27.533 | 3166.2 |
| putty | 45.911 | 2757.1 |
| xterm | - | Out of memmory |
| iterm2 | 10.805 | 1048.3 |
| Kitty | - | Out of memory |
| Alacritty | 5.799 | Not measured, use 100,000 scrollback lines setting |
| Windows Terminal + ssh.exe | 130.371 | Not measured, use 65,535 scrollback lines setting |

4. n = 10,000,000 scrollback = 10,000,000 Lines

| | Time(sec) | Memory Usage(MB) |
| --- | --- | --- |
| WindTerm | **10.674** | **133.3** |
| rxvt | - | Out of memory |
| putty | - | Out of memory |
| xterm | - | Out of memmory |
| iterm2 | 20.468 | 2231.3 |
| Kitty | - | Out of memory |
| Alacritty | 11.598 | Not measured, use 100,000 scrollback lines setting |
| Windows Terminal + ssh.exe | 264.739 | Not measured, use 65,535 scrollback lines setting |

5. n = 10,000,000 scrollback = 30 Lines

| | Time(sec) | Memory Usage(MB) |
| --- | --- | --- |
| WindTerm | 10.167 | 0.7 |
| rxvt | **9.687** | **0.1** |
| putty | 95.382 | 0.4 |
| xterm | 286.510 | **0.1** |
| iterm2 | 25.448 | 7.4 |
| Kitty | 16.104 | 0.5 |
| Alacritty | 11.798 | Not measured, use zero scrollback lines setting |
| Windows Terminal + ssh.exe | 261.096 | Not measured, use zero scrollback lines setting |

# Latency

Considering the network influence on the latency, the following data is from [WindEdit](https://github.com/kingToolbox/digedit).
DIGEdit is the text component of WindTerm.

|   | Min | Max | Avg | SD |
| --- | --- | --- | --- | --- |
|WindEdit| 1.9 | 7.6 | 2.9 | 0.8 |
|Windows Notepad | 0.9 | 16.5 | 7.8 | 1.8 |
|GVim | 0.9 | 10.4 | 2.8 | 1.2 |

# Shortcuts

| Shortcut | Action |
| --- | --- |
| Alt+C | Copy |
| Alt+D | Show command palette |
| Alt+F | Find |
| Alt+F3 | Find next |
| Alt+Shift+F3 | Find previous |
| Alt+F4 | Exit |
| Alt+M, Alt+F | Toggle full screen |
| Alt+M, Alt+H | Toggle hex view |
| Alt+N | New session |
| Alt+O | Open session |
| Alt+S | Save text |
| Alt+T, Alt+B | Toggle margin blank |
| Alt+T, Alt+F | Toggle margin fold |
| Alt+T, Alt+N | Toggle margin number |
| Alt+T, Alt+S | Toggle margin symbol |
| Alt+V | Paste |
| Alt+W, Alt+D | Close active dock |
| Alt+W, Alt+G | Close active group |
| Alt+W, Alt+H | Split horizontally |
| Alt+W, Alt+L | Show outline pane |
| Alt+W, Alt+V | Split vertically |
| Alt+X | Copy and paste |
| Alt+- | Zoom in |
| Alt++ | Zoom out |
| Alt+\[ | Activate next view |
| Alt+] | Activate previous view |
| Ctrl+. | Jump to next fold |
| Ctrl+, | Jump to previous fold |
| Ctrl+Shift+A | Select all text |
| Ctrl+Shift+T | Reopen closed session |
| Ctrl+Shift+W | Close current session |
| Ctrl+Shift+- | Select current fold text |
| Shift+Del | Copy |
| Shift+End | Jump to document end |
| Shift+Home | Jump to document home |
| Shift+Ins | Paste |
| Shift+PgDown | Jump to next page |
| Shift+PgUp | Jump to previous page |

# Roadmap

**Release cycle:**

  2-4 weeks.

**Next release (Late November，for reference only):**
- **Linux Version**
- **Linux Shells**
- Xmodem, Ymodem, Zmodem(sz, rz)
- External tools

**Todo list:**
- Protocols:
  - Rlogin
  - Mosh
  - SSH
    - ProxyCommand
- UI:
  - Config dialog
- Terminal:
  - MacOs bash
- Session:
  - Auto Complete
  - Chat mode
  - Log viewer
- File transfer:
  - ftp, ftps
- Script, macro and plugin stystem
- More ...

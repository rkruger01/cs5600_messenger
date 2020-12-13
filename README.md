# EasyChat

#### Project Description

This is a simple socket-based chat client developed for my Computer Networking course, modeled after
classic IRC servers. With features such as nicknames, colored messages, and public-key encryption, EasyChat is a simple
but surprisingly powerful chat client!

#### System Requirements

- Python 3.8

- Windows 10+ (not tested on other platforms)

- PyCryptodome

  `pip install pycryptodome`

#### Getting Started

1. Download a copy of the EasyChat code to your system.

`git clone https://github.com/rkruger01/cs5600_messenger.git`

2. Launch the EasyChat server.
   `python3 server.py`
3. Define what port the server is operating on, then generate the configuration file.

       Server Port:
       4444
       /config
       Server Nickname:
       My Server
       Server IP (defaults to {your public IP}):
       192.168.0.1
       Server Port:
       4444
       Password (optional):
       mypassword

4. Distribute the configuration file generated with the EasyChat client `client.py`.
5. Launch the EasyChat client and select the configuration file in the file explorer.

   `python3 client.py`

#### Contributors

- https://github.com/mjw4yt

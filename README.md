# libsscrypto

Build libsscrypto.dll for shadowsocks-windows.

## Build

1) Get source code

    git clone https://github.com/GangZhuo/libsscrypto.git
    cd libsscrypto
    git submodule init
    git submodule update
    
2) Compile

  a) Open libsscrypto.sln with Visual Studio 2015.
	 
  b) Change the configuration to Release or Debug
  
  c) Change the platform to Win32.
  
  d) Right click the project mbedTLS, and select Properties.
  
         i) Select General on left panel, and change Platform Toolset to v140.
	 
	 ii) Select C/C++ / Code Generation, and change Runtime Library to /MT or /MTd .
  
  e) Right click Solution, and select Build Solution.
  
  
  
  

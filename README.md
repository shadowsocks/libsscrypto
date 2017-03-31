# libsscrypto

Build libsscrypto.dll for shadowsocks-windows.

## Build

1) Get source code

    git clone https://github.com/shadowsocks/libsscrypto.git
    cd libsscrypto
    git submodule update --init
    
2) Compile

  a) Open libsscrypto.sln with Visual Studio 2017.
	 
  b) Change the configuration to Release
  
  c) Change the platform to Win32.
  
  d) Right click the project mbedTLS, and select Properties.
  
     i) Select General on left panel, and change Platform Toolset to v141.
	 
     ii) Select C/C++ / Code Generation, and change Runtime Library to /MT .
  
  e) Right click Solution, and select Build Solution.
  
  
  
  

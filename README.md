# ArchitectureInfo

## Retrieves information about architecture (32 or 64-bit) for dll and exe

Operating System: Windows

```
Usage: architectureinfo.exe "path to folder"
```

Download the latest version from github: https://github.com/chipmunk-sm/ArchitectureInfo/releases


[![CMake](https://github.com/chipmunk-sm/ArchitectureInfo/actions/workflows/build.yml/badge.svg)](https://github.com/chipmunk-sm/ArchitectureInfo/actions/workflows/build.yml)


![screen](https://user-images.githubusercontent.com/29524958/122629460-b8e68700-d0ac-11eb-98be-270aba5a0184.png)


## Build


open "x64 Native Tools Command Prompt for VS 2019" or set build environment in preferred way.
```
CD "working folder" 
git clone https://github.com/chipmunk-sm/ArchitectureInfo.git
CD ArchitectureInfo
MKDIR build
CD build
cmake ../
cmake --build . --config Release
```
Copy exe and runtime libraries to "install" folder
```
cmake --install . --prefix ./install
```

Create package using ZIP
``` 
cpack -G ZIP -C Release
```

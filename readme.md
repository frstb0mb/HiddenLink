# HiddenLink
## about
This project is learning for minifilter driver about symbolic link.  
Symbolic link is redirected to other file path written in EA when driver is loaded.

## Using
Use inf file to install service.

```
>mklink symlink C:\users\smith\Desktop\truedoc.txt
symbolic link created for symlink <<===>> C:\users\smith\Desktop\truedoc.txt

>MakeHidden.exe symlink fake.txt
AllEND

>type truedoc.txt
benign link
>type symlink
benign link
>type fake.txt
fake link
>fltmc load HiddenLink

>type symlink
fake link
>fltmc unload HiddenLink

>type symlink
benign link
```

## Environment
- VS2022
- Windows10 x64 20H2
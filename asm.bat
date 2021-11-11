mkdir %~f0\..\lib
pushd %~f0\..\lib
uasm64 -mf -safeseh -coff ../source/ntdll64ll.asm
popd

#pragma once

#define DriverTag 'albA'
#define Prefix "Abla said: "
#define PROCESS_TERMINATE 0x0001
//// {33AF2223-E303-421C-BA0F-7B54F3E0D289}
//DEFINE_GUID(GUID_CALLOUT_PROCESS_BLOCK_V4 ,
//	0x33af2223, 0xe303, 0x421c, 0xba, 0xf, 0x7b, 0x54, 0xf3, 0xe0, 0xd2, 0x89);


extern LARGE_INTEGER RegistryCookie;
extern PVOID RegHandle;
extern UINT64 FilterId;
extern HANDLE hEngine;
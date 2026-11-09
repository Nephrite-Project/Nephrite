/*
 * QEMU Guest Agent win32 VSS common declarations
 *
 * Copyright Hitachi Data Systems Corp. 2013
 *
 * Authors:
 *  Tomoki Sekiyama   <tomoki.sekiyama@hds.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VSS_COMMON_H
#define VSS_COMMON_H

#define __MIDL_user_allocate_free_DEFINED__
#include <windows.h>
#include <shlwapi.h>

/* Reduce warnings to include vss.h */

/* Ignore annotations for MS IDE */
#define __in  IN
#define __out OUT
#define __RPC_unique_pointer
#define __RPC_string
#define __RPC__deref_inout_opt
#define __RPC__out
#ifndef __RPC__out_ecount_part
#define __RPC__out_ecount_part(x, y)
#endif
#define _declspec(x)

#include <vss.h>
#include "vss-handles.h"

/* Macros to convert char definitions to wchar */
#define _L(a) L##a
#define L(a) _L(a)

const GUID g_gProviderId = { 0xfd2ab117, 0xdb90, 0x4dec,
    {0x8a, 0xde, 0x8a, 0xf0, 0x18, 0xc8, 0x94, 0x72} };
const GUID g_gProviderVersion = { 0xad57d5a6, 0x468a, 0x4e64,
    {0x97, 0x36, 0x0d, 0xd5, 0x83, 0xb8, 0xea, 0x4d} };

const CLSID CLSID_QGAVSSProvider = { 0x265a213c, 0x1a25, 0x4970,
    {0xbf, 0xce, 0xe5, 0x58, 0x29, 0xbd, 0x0c, 0x0c} };

const TCHAR g_szClsid[] = TEXT("{265A213C-1A25-4970-BFCE-E55829BD0C0C}");
const TCHAR g_szProgid[] = TEXT("NephriteGAVSSProvider");

#ifdef HAVE_VSS_SDK
/* Enums undefined in VSS SDK 7.2 but defined in newer Windows SDK */
enum __VSS_VOLUME_SNAPSHOT_ATTRIBUTES {
    VSS_VOLSNAP_ATTR_NO_AUTORECOVERY       = 0x00000002,
    VSS_VOLSNAP_ATTR_TXF_RECOVERY          = 0x02000000
};
#endif

/* COM pointer utility; call ->Release() when it goes out of scope */
template <class T>
class COMPointer {
    COMPointer(const COMPointer<T> &p) { } /* no copy */
    T *p;
public:
    COMPointer &operator=(T *new_p)
    {
        /* Assignment of a new T* (or NULL) causes release of previous p */
        if (p && p != new_p) {
            p->Release();
        }
        p = new_p;
        return *this;
    }
    /* Replace by assignment to the pointer of p  */
    T **replace(void)
    {
        *this = NULL;
        return &p;
    }
    /* Make COMPointer be used like T* */
    operator T*() { return p; }
    T *operator->(void) { return p; }
    T &operator*(void) { return *p; }
    operator bool() { return !!p; }

    COMPointer(T *p = NULL) : p(p) { }
    ~COMPointer() { *this = NULL; }  /* Automatic release */
};

/*
 * COM initializer; this should declared before COMPointer to uninitialize COM
 * after releasing COM objects.
 */
class COMInitializer {
public:
    COMInitializer() { CoInitialize(NULL); }
    ~COMInitializer() { CoUninitialize(); }
};

#endif

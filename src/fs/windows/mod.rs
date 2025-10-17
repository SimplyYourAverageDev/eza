// SPDX-FileCopyrightText: 2024 Christina Sørensen
// SPDX-License-Identifier: EUPL-1.2
//
// SPDX-FileCopyrightText: 2024 eza contributors
// SPDX-License-Identifier: MIT

use std::convert::TryFrom;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_NONE_MAPPED, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetNamedSecurityInfoW, LookupAccountSidW, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, SE_FILE_OBJECT,
};
use windows_sys::Win32::System::Memory::LocalFree;

use crate::fs::fields::WindowsSecurityContext;

/// Query the Windows security descriptor for the provided `path` and
/// translate it into a simplified [`WindowsSecurityContext`].
pub fn query_security_context(path: &Path) -> Option<WindowsSecurityContext> {
    use std::ptr::null_mut;

    let mut wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut owner_sid = null_mut();
    let mut group_sid = null_mut();
    let mut security_descriptor = null_mut();

    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            &mut owner_sid,
            &mut group_sid,
            null_mut(),
            null_mut(),
            &mut security_descriptor,
        )
    };

    let result = if status == ERROR_SUCCESS {
        let owner = sid_to_account_name(owner_sid);
        let group = sid_to_account_name(group_sid);

        owner.map(|owner| WindowsSecurityContext { owner, group })
    } else {
        None
    };

    if !security_descriptor.is_null() {
        unsafe {
            LocalFree(security_descriptor.cast());
        }
    }

    result
}

fn sid_to_account_name(sid: *mut core::ffi::c_void) -> Option<String> {
    use std::ptr::{null, null_mut};

    if sid.is_null() {
        return None;
    }

    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_use = 0u32;

    unsafe {
        LookupAccountSidW(
            null(),
            sid,
            null_mut(),
            &mut name_len,
            null_mut(),
            &mut domain_len,
            &mut sid_use,
        );
    }

    if name_len == 0 {
        return sid_to_string(sid);
    }

    let mut name = vec![0u16; usize::try_from(name_len).ok()?];
    let mut domain = vec![0u16; usize::try_from(domain_len).ok()?];

    let success = unsafe {
        LookupAccountSidW(
            null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    };

    if success == 0 {
        let error = unsafe { GetLastError() };
        if error == ERROR_NONE_MAPPED {
            return sid_to_string(sid);
        }
        return None;
    }

    Some(format_account_name(&domain, &name))
}

fn sid_to_string(sid: *mut core::ffi::c_void) -> Option<String> {
    use std::ptr::null_mut;

    if sid.is_null() {
        return None;
    }

    let mut buffer = null_mut();
    let success = unsafe { ConvertSidToStringSidW(sid, &mut buffer) };
    if success == 0 || buffer.is_null() {
        return None;
    }

    let mut len = 0;
    unsafe {
        while *buffer.add(len) != 0 {
            len += 1;
        }
    }

    let slice = unsafe { std::slice::from_raw_parts(buffer, len) };
    let value = String::from_utf16_lossy(slice);

    unsafe {
        LocalFree(buffer.cast());
    }

    Some(value)
}

fn format_account_name(domain: &[u16], name: &[u16]) -> String {
    fn utf16_to_string(input: &[u16]) -> String {
        let end = input.iter().position(|&c| c == 0).unwrap_or(input.len());
        String::from_utf16_lossy(&input[..end])
    }

    let account = utf16_to_string(name);
    let domain = utf16_to_string(domain);

    if domain.is_empty() {
        account
    } else {
        format!("{domain}\\{account}")
    }
}

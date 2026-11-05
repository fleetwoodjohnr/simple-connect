//! The small native boundary for current-user-only named pipes.
//!
//! Tokio cannot accept a Rust-owned security descriptor through its safe API.
//! All native buffers and handles stay alive for the complete synchronous call;
//! no raw pointer escapes this module. See Microsoft's named-pipe security docs.
#![allow(unsafe_code)]

use std::io;
use std::path::Path;
use std::ptr::null_mut;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSID, SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenOwner, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the handle returned by OpenProcessToken.
        unsafe { CloseHandle(self.0) };
    }
}

struct LocalAllocation(*mut core::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: Windows allocated these buffers with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

/// The process account's SID, independent of display names and localization.
pub(crate) fn current_user_sid() -> io::Result<String> {
    token_sid(TokenUser)
}

/// The default owner assigned when this process creates a securable object.
pub(crate) fn current_owner_sid() -> io::Result<String> {
    token_sid(TokenOwner)
}

fn token_sid(class: TOKEN_INFORMATION_CLASS) -> io::Result<String> {
    let mut raw_token = null_mut();
    // SAFETY: output points to writable storage and the process pseudo-handle
    // remains valid. TOKEN_QUERY is the minimum required access.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(raw_token);
    let mut length = 0;
    // SAFETY: a null/zero buffer requests the required size, as documented.
    unsafe { GetTokenInformation(token.0, class, null_mut(), 0, &mut length) };
    if length == 0 || length > 64 * 1024 {
        return Err(io::Error::last_os_error());
    }
    // usize allocation supplies the pointer alignment required for TOKEN_USER.
    let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    // SAFETY: allocation is aligned and at least `length` bytes long.
    if unsafe { GetTokenInformation(token.0, class, buffer.as_mut_ptr().cast(), length, &mut length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: TokenUser and TokenOwner both begin with a PSID. The successful
    // query initialized that pointer, whose target remains inside live buffer.
    let sid = unsafe { *buffer.as_ptr().cast::<PSID>() };
    let mut text = null_mut();
    // SAFETY: SID refers into the live token information buffer.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation(text.cast());
    let mut count = 0;
    // SAFETY: the successful API returns an allocated NUL-terminated UTF-16 string.
    unsafe {
        while *text.add(count) != 0 {
            count += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(text, count)).map_err(io::Error::other)
    }
}

pub(super) fn create(path: &Path, first: bool) -> io::Result<NamedPipeServer> {
    let sid = current_user_sid()?;
    // Protected DACL: only this account, never Everyone/anonymous/default ACLs.
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})").encode_utf16().chain([0]).collect();
    let mut descriptor = null_mut();
    // SAFETY: sddl is NUL-terminated; descriptor points to writable storage.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation(descriptor);
    let mut attributes =
        SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: descriptor, bInheritHandle: 0 };
    // SAFETY: attributes and descriptor remain live for CreateNamedPipeW, which
    // copies the descriptor. Tokio takes ownership of the resulting pipe handle.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(path, (&mut attributes as *mut SECURITY_ATTRIBUTES).cast())
    }
}

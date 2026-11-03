//! Access lists, which on macOS can grant writing that the mode does not show:
//! any entry that allows something counts against a file or folder. Only
//! entries that deny pass. On Linux an access list's write shows in the group
//! bits, which the mode checks already read, so both calls answer `false`.

#[cfg(not(target_os = "macos"))]
pub(crate) use not_macos::*;

#[cfg(target_os = "macos")]
pub(crate) use macos::*;

#[cfg(not(target_os = "macos"))]
mod not_macos {
    use std::io;
    use std::os::fd::AsFd;
    use std::path::Path;

    pub(crate) fn allows(_opened: impl AsFd) -> io::Result<bool> {
        Ok(false)
    }

    pub(crate) fn path_allows(_path: &Path) -> io::Result<bool> {
        Ok(false)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CString, c_char, c_int, c_void};
    use std::io;
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    // From <sys/acl.h>.
    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ACL_NEXT_ENTRY: c_int = -1;
    const ACL_EXTENDED_DENY: c_int = 2;

    // SAFETY: these are libSystem's declarations of the functions, with
    // `acl_t` and `acl_entry_t` as opaque pointers and the enums as `int`.
    unsafe extern "C" {
        fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
        fn acl_get_link_np(path: *const c_char, kind: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    /// Frees the access list when dropped.
    struct List(*mut c_void);

    impl Drop for List {
        fn drop(&mut self) {
            // SAFETY: the list came from `acl_get_fd_np` or `acl_get_link_np`
            // and is freed once.
            unsafe { acl_free(self.0) };
        }
    }

    /// Whether the open folder or file `opened` has an access list entry that
    /// allows anything.
    pub(crate) fn allows(opened: impl AsFd) -> io::Result<bool> {
        let fd = opened.as_fd().as_raw_fd();
        // SAFETY: `fd` is open for the length of the call.
        read(unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) })
    }

    /// Whether the folder or file at `path`, itself and not what a link points
    /// to, has an access list entry that allows anything.
    pub(crate) fn path_allows(path: &Path) -> io::Result<bool> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        read(unsafe { acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED) })
    }

    /// Whether the access list `list` just returned, with `errno` set when it
    /// is null, has an entry that allows anything. Entries that only deny take
    /// rights away. Every entry is read: macOS keeps deny entries first, so an
    /// allow entry is often not the first.
    fn read(list: *mut c_void) -> io::Result<bool> {
        if list.is_null() {
            let error = io::Error::last_os_error();
            // No access list at all.
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            return Err(error);
        }
        let list = List(list);
        let mut id = ACL_FIRST_ENTRY;
        loop {
            let mut entry = null_mut();
            // SAFETY: the list is valid until dropped, and `entry` is a
            // valid out pointer.
            if unsafe { acl_get_entry(list.0, id, &mut entry) } != 0 {
                let error = io::Error::last_os_error();
                // The end of the list is EINVAL; anything else could hide
                // an entry, so the check cannot tell.
                if error.raw_os_error() == Some(libc::EINVAL) {
                    return Ok(false);
                }
                return Err(error);
            }
            id = ACL_NEXT_ENTRY;
            let mut tag: c_int = 0;
            // SAFETY: `entry` points into the list, and `tag` is a valid out
            // pointer.
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || tag != ACL_EXTENDED_DENY {
                return Ok(true);
            }
        }
    }
}

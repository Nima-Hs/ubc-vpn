//! The System Configuration dynamic store (`SCDynamicStore`), through the
//! frameworks' C API directly: the few CoreFoundation and SystemConfiguration
//! calls DNS needs, and nothing more.
//!
//! Every CoreFoundation object this module gets from a call named `Create`
//! or `Copy` is owned, and is held in a [`Cf`], which releases it once when
//! dropped. Objects reached through `Get` calls are borrowed from their
//! container and are never released here. Values cross into Rust as a
//! [`Value`], which owns plain Rust data only, so nothing borrowed outlives
//! its container.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::ptr::{NonNull, null, null_mut};

use crate::{Error, Result};

type CFTypeRef = *const c_void;
type CFIndex = isize;
type CFTypeID = usize;
type Boolean = u8;

#[repr(C)]
struct CFRange {
    location: CFIndex,
    length: CFIndex,
}

/// The callbacks CoreFoundation keeps in its own statics. Only their
/// addresses are used.
#[repr(C)]
struct Callbacks {
    _private: [u8; 0],
}

const UTF8: u32 = 0x0800_0100;
const SINT64: CFIndex = 4;
/// "The key does not exist."
const NO_KEY: c_int = 1004;
/// "Permission denied."
const ACCESS_ERROR: c_int = 1003;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeArrayCallBacks: Callbacks;
    static kCFTypeDictionaryKeyCallBacks: Callbacks;
    static kCFTypeDictionaryValueCallBacks: Callbacks;
    static kCFBooleanTrue: CFTypeRef;

    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    fn CFStringGetTypeID() -> CFTypeID;
    fn CFNumberGetTypeID() -> CFTypeID;
    fn CFBooleanGetTypeID() -> CFTypeID;
    fn CFArrayGetTypeID() -> CFTypeID;
    fn CFDictionaryGetTypeID() -> CFTypeID;

    fn CFStringCreateWithBytes(
        allocator: CFTypeRef,
        bytes: *const u8,
        length: CFIndex,
        encoding: u32,
        external: Boolean,
    ) -> CFTypeRef;
    fn CFStringGetLength(string: CFTypeRef) -> CFIndex;
    fn CFStringGetBytes(
        string: CFTypeRef,
        range: CFRange,
        encoding: u32,
        loss_byte: u8,
        external: Boolean,
        buffer: *mut u8,
        max_length: CFIndex,
        used: *mut CFIndex,
    ) -> CFIndex;

    fn CFNumberCreate(allocator: CFTypeRef, kind: CFIndex, value: *const c_void) -> CFTypeRef;
    fn CFNumberGetValue(number: CFTypeRef, kind: CFIndex, value: *mut c_void) -> Boolean;
    fn CFBooleanGetValue(boolean: CFTypeRef) -> Boolean;

    fn CFArrayCreate(
        allocator: CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        callbacks: *const Callbacks,
    ) -> CFTypeRef;
    fn CFArrayGetCount(array: CFTypeRef) -> CFIndex;
    fn CFArrayGetValueAtIndex(array: CFTypeRef, index: CFIndex) -> CFTypeRef;

    fn CFDictionaryCreate(
        allocator: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        key_callbacks: *const Callbacks,
        value_callbacks: *const Callbacks,
    ) -> CFTypeRef;
    fn CFDictionaryGetCount(dictionary: CFTypeRef) -> CFIndex;
    fn CFDictionaryGetKeysAndValues(
        dictionary: CFTypeRef,
        keys: *mut CFTypeRef,
        values: *mut CFTypeRef,
    );
}

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    static kSCDynamicStoreUseSessionKeys: CFTypeRef;

    fn SCDynamicStoreCreateWithOptions(
        allocator: CFTypeRef,
        name: CFTypeRef,
        options: CFTypeRef,
        callout: *const c_void,
        context: *mut c_void,
    ) -> CFTypeRef;
    fn SCDynamicStoreCopyValue(store: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn SCDynamicStoreSetValue(store: CFTypeRef, key: CFTypeRef, value: CFTypeRef) -> Boolean;
    fn SCDynamicStoreRemoveValue(store: CFTypeRef, key: CFTypeRef) -> Boolean;
    fn SCError() -> c_int;
    fn SCErrorString(status: c_int) -> *const c_char;
}

/// An owned CoreFoundation object, released once when dropped.
struct Cf(NonNull<c_void>);

impl Cf {
    /// Takes ownership of what a `Create` or `Copy` call returned, or `None`
    /// if it returned nothing.
    ///
    /// # Safety
    ///
    /// `object` must be null or a CoreFoundation object the caller owns one
    /// reference to, which passes to the returned value.
    unsafe fn owned(object: CFTypeRef) -> Option<Self> {
        NonNull::new(object.cast_mut()).map(Self)
    }

    fn get(&self) -> CFTypeRef {
        self.0.as_ptr().cast_const()
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        // SAFETY: this value owns exactly one reference to the object, and
        // gives it up here, once.
        unsafe { CFRelease(self.get()) }
    }
}

/// A property-list value, as the dynamic store holds them, in plain Rust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Value {
    String(String),
    Number(i64),
    Bool(bool),
    Array(Vec<Value>),
    /// The keys are strings, in the order the store gave them.
    Dict(Vec<(String, Value)>),
    /// Anything else: data, a date, a number that is not a whole one, or a
    /// dictionary with a key that is not a string.
    Other,
}

impl Value {
    /// The value under `key`, if this is a dictionary that has one.
    pub(super) fn field(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Dict(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// How deep a value read from the store may nest. What DNS reads is two
/// levels deep; anything deeper is not ours.
const DEEPEST: usize = 8;

fn string(text: &str) -> Result<Cf> {
    let length = CFIndex::try_from(text.len()).map_err(|_| Error::InvalidInput)?;
    // SAFETY: the bytes are valid for `length` bytes for the whole call, and
    // the call copies them. A `Create` call: the result is ours.
    unsafe {
        Cf::owned(CFStringCreateWithBytes(
            null(),
            text.as_ptr(),
            length,
            UTF8,
            0,
        ))
    }
    .ok_or_else(|| failed("make a string"))
}

/// Makes a CoreFoundation object of `value`, owned by the result.
fn to_cf(value: &Value) -> Result<Cf> {
    match value {
        Value::String(text) => string(text),
        Value::Number(number) => {
            // SAFETY: `number` is a live i64, as the type says, which the
            // call copies. A `Create` call: the result is ours.
            unsafe { Cf::owned(CFNumberCreate(null(), SINT64, (&raw const *number).cast())) }
                .ok_or_else(|| failed("make a number"))
        }
        Value::Array(items) => {
            let owned = items.iter().map(to_cf).collect::<Result<Vec<_>>>()?;
            let pointers: Vec<CFTypeRef> = owned.iter().map(Cf::get).collect();
            let count = CFIndex::try_from(pointers.len()).map_err(|_| Error::InvalidInput)?;
            // SAFETY: `pointers` holds `count` live objects, which the array
            // retains through the standard callbacks, so `owned` may release
            // its references afterwards. A `Create` call: the result is ours.
            unsafe {
                Cf::owned(CFArrayCreate(
                    null(),
                    pointers.as_ptr(),
                    count,
                    &raw const kCFTypeArrayCallBacks,
                ))
            }
            .ok_or_else(|| failed("make an array"))
        }
        Value::Dict(fields) => {
            let keys = fields
                .iter()
                .map(|(key, _)| string(key))
                .collect::<Result<Vec<_>>>()?;
            let values = fields
                .iter()
                .map(|(_, value)| to_cf(value))
                .collect::<Result<Vec<_>>>()?;
            let key_pointers: Vec<CFTypeRef> = keys.iter().map(Cf::get).collect();
            let value_pointers: Vec<CFTypeRef> = values.iter().map(Cf::get).collect();
            let count = CFIndex::try_from(keys.len()).map_err(|_| Error::InvalidInput)?;
            // SAFETY: both arrays hold `count` live objects, which the
            // dictionary retains through the standard callbacks. A `Create`
            // call: the result is ours.
            unsafe {
                Cf::owned(CFDictionaryCreate(
                    null(),
                    key_pointers.as_ptr(),
                    value_pointers.as_ptr(),
                    count,
                    &raw const kCFTypeDictionaryKeyCallBacks,
                    &raw const kCFTypeDictionaryValueCallBacks,
                ))
            }
            .ok_or_else(|| failed("make a dictionary"))
        }
        Value::Bool(_) | Value::Other => Err(Error::InvalidInput),
    }
}

/// The text of a CoreFoundation string, or `None` if it has none in UTF-8.
///
/// # Safety
///
/// `object` must be a live CoreFoundation string.
unsafe fn text_of(object: CFTypeRef) -> Option<String> {
    // SAFETY: the caller promises a live string.
    let length = unsafe { CFStringGetLength(object) };
    let range = || CFRange {
        location: 0,
        length,
    };
    let mut needed: CFIndex = 0;
    // SAFETY: a null buffer asks only for the size, written to `needed`.
    let converted =
        unsafe { CFStringGetBytes(object, range(), UTF8, 0, 0, null_mut(), 0, &mut needed) };
    if converted != length {
        return None;
    }
    let mut bytes = vec![0u8; usize::try_from(needed).ok()?];
    let mut used: CFIndex = 0;
    // SAFETY: `bytes` is writable for `needed` bytes, the most the call
    // writes, and `used` is a live integer.
    let converted = unsafe {
        CFStringGetBytes(
            object,
            range(),
            UTF8,
            0,
            0,
            bytes.as_mut_ptr(),
            needed,
            &mut used,
        )
    };
    if converted != length || used != needed {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// The value of a CoreFoundation object, copied into Rust.
///
/// # Safety
///
/// `object` must be a live CoreFoundation object, for the whole call.
unsafe fn from_cf(object: CFTypeRef, depth: usize) -> Value {
    if depth > DEEPEST {
        return Value::Other;
    }
    // SAFETY: the caller promises a live object; the `TypeID` calls take
    // nothing.
    let kind = unsafe { CFGetTypeID(object) };
    // SAFETY: as above, for each branch: the object is of the type checked,
    // and every object a `Get` call returns is borrowed from `object`, which
    // stays live, and is never released here.
    unsafe {
        if kind == CFStringGetTypeID() {
            return text_of(object).map_or(Value::Other, Value::String);
        }
        if kind == CFBooleanGetTypeID() {
            return Value::Bool(CFBooleanGetValue(object) != 0);
        }
        if kind == CFNumberGetTypeID() {
            let mut number: i64 = 0;
            // The call answers false when the number is not exactly an i64.
            let exact = CFNumberGetValue(object, SINT64, (&raw mut number).cast()) != 0;
            return if exact {
                Value::Number(number)
            } else {
                Value::Other
            };
        }
        if kind == CFArrayGetTypeID() {
            let count = CFArrayGetCount(object);
            let items = (0..count).map(|at| from_cf(CFArrayGetValueAtIndex(object, at), depth + 1));
            return Value::Array(items.collect());
        }
        if kind == CFDictionaryGetTypeID() {
            let count = usize::try_from(CFDictionaryGetCount(object)).unwrap_or(0);
            let mut keys: Vec<CFTypeRef> = vec![null(); count];
            let mut values: Vec<CFTypeRef> = vec![null(); count];
            // Both buffers hold room for every entry.
            CFDictionaryGetKeysAndValues(object, keys.as_mut_ptr(), values.as_mut_ptr());
            let mut fields = Vec::with_capacity(count);
            for (key, value) in keys.into_iter().zip(values) {
                if key.is_null() || CFGetTypeID(key) != CFStringGetTypeID() {
                    return Value::Other;
                }
                let Some(key) = text_of(key) else {
                    return Value::Other;
                };
                fields.push((key, from_cf(value, depth + 1)));
            }
            return Value::Dict(fields);
        }
    }
    Value::Other
}

/// The error System Configuration reports for the last call on this thread.
fn last_error(what: &str) -> Error {
    // SAFETY: no preconditions; the status is the calling thread's.
    let status = unsafe { SCError() };
    if status == ACCESS_ERROR {
        return Error::PermissionDenied;
    }
    // SAFETY: the call returns a static, NUL-terminated string for any
    // status, or null.
    let text = unsafe { SCErrorString(status) };
    let text = match text.is_null() {
        true => String::new(),
        // SAFETY: not null, so a NUL-terminated string that lives forever.
        false => unsafe { CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned(),
    };
    Error::Failed(format!(
        "could not {what} in the dynamic store: {text} ({status})"
    ))
}

fn failed(what: &str) -> Error {
    Error::Failed(format!("could not {what} for the dynamic store"))
}

/// A session with the dynamic store.
///
/// Keys it sets are session keys: configd removes them when the session
/// ends, which it does when this value is dropped or the process ends in any
/// way, even killed. So what it set never outlives the process.
pub(super) struct Store(Cf);

// SAFETY: a dynamic store session may be used from any thread, so long as
// no two use it at once. Every user holds it behind a lock, and nothing
// here gives out the object itself.
unsafe impl Send for Store {}

impl Store {
    /// Opens a session named `name`, for logs, whose keys are session keys.
    pub(super) fn session(name: &str) -> Result<Self> {
        let name = string(name)?;
        // SAFETY: both are the frameworks' own constant objects, which live
        // forever.
        let (key, yes) = unsafe { (kSCDynamicStoreUseSessionKeys, kCFBooleanTrue) };
        // SAFETY: one live key and one live value, which the dictionary
        // retains. A `Create` call: the result is ours.
        let options = unsafe {
            Cf::owned(CFDictionaryCreate(
                null(),
                &raw const key,
                &raw const yes,
                1,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            ))
        }
        .ok_or_else(|| failed("make the options"))?;
        // SAFETY: the name and options are live for the call, which retains
        // what it keeps. No callout, so no context. A `Create` call: the
        // result is ours.
        let store = unsafe {
            Cf::owned(SCDynamicStoreCreateWithOptions(
                null(),
                name.get(),
                options.get(),
                null(),
                null_mut(),
            ))
        };
        store.map(Self).ok_or_else(|| last_error("open a session"))
    }

    /// The value under `key`, or `None` if there is none.
    pub(super) fn get(&self, key: &str) -> Result<Option<Value>> {
        let key = string(key)?;
        // SAFETY: the session and key are live. A `Copy` call: the result is
        // ours.
        let value = unsafe { Cf::owned(SCDynamicStoreCopyValue(self.0.get(), key.get())) };
        let Some(value) = value else {
            // SAFETY: no preconditions.
            return match unsafe { SCError() } {
                NO_KEY => Ok(None),
                _ => Err(last_error("read a key")),
            };
        };
        // SAFETY: owned by `value`, so live for the whole call.
        Ok(Some(unsafe { from_cf(value.get(), 0) }))
    }

    /// Sets `key` to `value`, replacing what was there, as a session key.
    pub(super) fn set(&self, key: &str, value: &Value) -> Result<()> {
        let key = string(key)?;
        let value = to_cf(value)?;
        // SAFETY: the session, key and value are live; the store copies the
        // value.
        match unsafe { SCDynamicStoreSetValue(self.0.get(), key.get(), value.get()) } {
            0 => Err(last_error("set a key")),
            _ => Ok(()),
        }
    }

    /// Removes `key`. A key that is not there is no error.
    pub(super) fn remove(&self, key: &str) -> Result<()> {
        let key = string(key)?;
        // SAFETY: the session and key are live.
        if unsafe { SCDynamicStoreRemoveValue(self.0.get(), key.get()) } != 0 {
            return Ok(());
        }
        // SAFETY: no preconditions.
        match unsafe { SCError() } {
            NO_KEY => Ok(()),
            _ => Err(last_error("remove a key")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Values go into CoreFoundation and come back the same, nested, with
    // text that is not ASCII.
    #[test]
    fn a_value_comes_back_as_it_went_in() {
        let value = Value::Dict(vec![
            (
                "ServerAddresses".to_string(),
                Value::Array(vec![
                    Value::String("192.0.2.53".to_string()),
                    Value::String("192.0.2.54".to_string()),
                ]),
            ),
            ("Order".to_string(), Value::Number(-7)),
            ("Name".to_string(), Value::String("é.example".to_string())),
            ("Empty".to_string(), Value::Array(Vec::new())),
        ]);
        let object = to_cf(&value).expect("into CoreFoundation");
        // SAFETY: owned by `object`, so live for the call.
        let back = unsafe { from_cf(object.get(), 0) };
        let Value::Dict(mut fields) = back else {
            panic!("not a dictionary: {back:?}");
        };
        // A dictionary keeps no order.
        fields.sort_by(|a, b| a.0.cmp(&b.0));
        let Value::Dict(mut wanted) = value.clone() else {
            unreachable!()
        };
        wanted.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(fields, wanted);
        let back = Value::Dict(fields);
        assert_eq!(back.field("Order"), Some(&Value::Number(-7)));
        assert_eq!(back.field("Missing"), None);
    }

    #[test]
    fn a_value_with_no_plist_form_is_refused() {
        assert_eq!(to_cf(&Value::Other).err(), Some(Error::InvalidInput));
        let nested = Value::Array(vec![Value::Other]);
        assert_eq!(to_cf(&nested).err(), Some(Error::InvalidInput));
    }

    // Opening a session and reading a key that is not there needs no root,
    // and changes nothing.
    #[test]
    fn a_key_that_is_not_there_reads_as_none() {
        let store = Store::session("ubc-vpn tests").expect("a session");
        let key = "State:/Network/Service/io.github.nima-hs.ubc-vpn.test.none/DNS";
        assert_eq!(store.get(key), Ok(None));
    }
}

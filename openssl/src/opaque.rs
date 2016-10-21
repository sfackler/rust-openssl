use std::cell::UnsafeCell;

/// This is intended to be used as the inner type for types designed to be pointed to by references
/// converted from raw C pointers. It has an `UnsafeCell` internally to inform the compiler about
/// aliasability and doesn't implement `Copy`, so it can't be dereferenced.
pub struct Opaque(UnsafeCell<()>);

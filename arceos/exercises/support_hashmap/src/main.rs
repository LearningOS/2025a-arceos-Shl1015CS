#![no_std]
#![no_main]

#[macro_use]
extern crate axstd;


extern crate alloc;


use alloc::string::String;
use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use core::hash::BuildHasher;


#[derive(Default)]
struct HashMap<K, V> {
    entries: Vec<(K, V)>,
}

impl<K, V> HashMap<K, V>
where
    K: Eq,
{
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    
    fn insert(&mut self, key: K, value: V) -> Option<V>
    where
        K: Eq,
    {

        for entry in &mut self.entries {
            if entry.0 == key {
                let old_value = core::mem::replace(&mut entry.1, value);
                return Some(old_value);
            }
        }
        

        self.entries.push((key, value));
        None
    }
    
    fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|entry| (&entry.0, &entry.1))
    }
}

#[no_mangle]
fn main() {
    println!("Running memory tests...");
    test_hashmap();
    println!("Memory tests run OK!");
}

fn test_hashmap() {

    const N: u32 = 1_000;
    let mut m = HashMap::new();

    for value in 0..N {
        let key = alloc::format!("key_{}", value);
        m.insert(key, value);
    }
    let mut count = 0;
    for (k, v) in m.iter() {
        if let Some(k) = k.strip_prefix("key_") {
            assert_eq!(k.parse::<u32>().unwrap(), *v);
            count += 1;
        }
    }
    assert_eq!(count, N);
    
    println!("test_hashmap() OK!");
}

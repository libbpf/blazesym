
pub fn search_address_key<T, V: Ord>(data: &[T], address: V, keyfn: &dyn Fn(&T) -> V) -> Option<usize> {
    let mut left = 0;
    let mut right = data.len();

    if right == 0 {
	return None;
    }
    if address < keyfn(&data[0]) {
	return None;
    }

    while (left + 1) < right {
	let v = (left + right) / 2;
	let key = keyfn(&data[v]);

	if key == address {
	    return Some(v);
	}
	if address < key {
	    right = v;
	} else {
	    left = v;
	}
    }

    Some(left)
}

/// Do binary search but skip entries not having a key.
pub fn search_address_opt_key<T, V: Ord>(data: &[T], address: V, keyfn: &dyn Fn(&T) -> Option<V>) -> Option<usize> {
    let mut left = 0;
    let mut right = data.len();

    while left < right {
	let left_key = keyfn(&data[left]);
	if left_key.is_some() {
	    break;
	}
	left += 1;
    }

    if left == right {
	return None;
    }

    if address < keyfn(&data[left]).unwrap() {
	return None;
    }

    while (left + 1) < right {
	let mut v = (left + right) / 2;

	let v_saved = v;
	// Skip entries not having a key
	while v < right {
	    let key = keyfn(&data[v]);
	    if key.is_some() {
		break;
	    }
	    v += 1;
	}
	// All entries at the right side haven't keys.
	// Shrink to the left side.
	if v == right {
	    right = v_saved;
	    continue;
	}

	let key = keyfn(&data[v]).unwrap();

	if key == address {
	    return Some(v);
	}
	if address < key {
	    right = v;
	} else {
	    left = v;
	}
    }

    Some(left)
}

pub fn extract_string(raw: &[u8], off: usize) -> Option<&str> {
    let mut end = off;

    if off >= raw.len() {
	return None;
    }
    while raw[end] != 0 {
	end += 1;
    }
    let blk = raw[off..end].as_ptr() as *mut u8;
    let r = unsafe { String::from_raw_parts(blk, end - off, end - off) };
    let ret = Some(unsafe { &*(r.as_str() as *const str) }); // eliminate lifetime
    r.into_bytes().leak();
    ret
}


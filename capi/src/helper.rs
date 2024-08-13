use blazesym::helper::is_procmap_query_supported;

use crate::set_last_err;


/// Check whether the `PROCMAP_QUERY` ioctl is supported by the system.
#[no_mangle]
pub extern "C" fn blaze_supports_procmap_query() -> bool {
    match is_procmap_query_supported() {
        Ok(supported) => supported,
        Err(err) => {
            let () = set_last_err(err.kind().into());
            false
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::blaze_err;
    use crate::blaze_err_last;


    /// Test that we can check whether the `PROCMAP_QUERY` ioctl is
    /// supported.
    #[test]
    fn procmap_query_supported() {
        let _supported = blaze_supports_procmap_query();
        assert_eq!(blaze_err_last(), blaze_err::BLAZE_ERR_OK);
    }
}

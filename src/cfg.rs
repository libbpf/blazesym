macro_rules! cfg_apk {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "apk")]
            #[cfg_attr(docsrs, doc(cfg(feature = "apk")))]
            $item
        )*
    }
}

macro_rules! cfg_breakpad {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "breakpad")]
            #[cfg_attr(docsrs, doc(cfg(feature = "breakpad")))]
            $item
        )*
    }
}

macro_rules! cfg_gsym {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "gsym")]
            #[cfg_attr(docsrs, doc(cfg(feature = "gsym")))]
            $item
        )*
    }
}

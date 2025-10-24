macro_rules! echo_error {
    ($io:expr, $($arg:tt)*) => {{
        let msg = ::alloc::format!($($arg)*);
        namada_io::edisplay_line!($io, "{msg}");
        msg
    }}
}

pub(crate) use echo_error;

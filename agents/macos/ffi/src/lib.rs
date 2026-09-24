use std::slice;
mod csv_verify;
mod tls;

/// Caller supplies readable input and 64 writable output bytes; no retained pointers.
#[no_mangle]
pub unsafe extern "C" fn tcpra_hello(
    data: *const u8,
    len: usize,
    client: bool,
    out: *mut u8,
) -> i32 {
    if data.is_null() || out.is_null() || len > 262144 {
        return -1;
    }
    let bytes = slice::from_raw_parts(data, len);
    let hello = if client {
        tls::find_client_hello(bytes)
    } else {
        tls::find_server_hello(bytes)
    };
    match hello {
        Some(h) => {
            std::ptr::copy_nonoverlapping(h.key.as_ptr(), out, 64);
            1
        }
        None => 0,
    }
}

/// Fixed sizes: report=2548, key=64, pek=64, measurement=32 bytes.
#[no_mangle]
pub unsafe extern "C" fn tcpra_verify(
    report: *const u8,
    key: *const u8,
    pek: *const u8,
    measurement: *const u8,
) -> i32 {
    if report.is_null() || key.is_null() || pek.is_null() || measurement.is_null() {
        return -1;
    }
    match csv_verify::verify_report(
        slice::from_raw_parts(report, 2548),
        slice::from_raw_parts(key, 64),
        slice::from_raw_parts(pek, 64),
        slice::from_raw_parts(measurement, 32),
    ) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

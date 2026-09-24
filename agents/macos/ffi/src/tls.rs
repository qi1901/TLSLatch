use sha2::{Digest, Sha512};

const CLIENT_LABEL: &[u8] = b"tcp-level-ra/clienthello-key/v1";
const SERVER_LABEL: &[u8] = b"tcp-level-ra/serverhello-key/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloKey {
    pub key: [u8; 64],
    pub consumed: usize,
}

fn derive(label: &[u8], key_share_extension: &[u8]) -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update(label);
    hash.update(key_share_extension);
    hash.finalize().into()
}

fn be16(input: &[u8]) -> Option<usize> {
    Some(u16::from_be_bytes(input.get(..2)?.try_into().ok()?) as usize)
}

fn find_extension(body: &[u8], is_client: bool) -> Option<&[u8]> {
    let mut offset = if is_client {
        // legacy_version, random, session-id, cipher-suites, compression-methods
        let session_len = *body.get(34)? as usize;
        let mut p = 35usize.checked_add(session_len)?;
        let cipher_len = be16(body.get(p..)?)?;
        p = p.checked_add(2 + cipher_len)?;
        let compression_len = *body.get(p)? as usize;
        p.checked_add(1 + compression_len)?
    } else {
        // legacy_version, random, session-id, cipher-suite, compression-method
        let session_len = *body.get(34)? as usize;
        35usize.checked_add(session_len)?.checked_add(3)?
    };

    let extensions_len = be16(body.get(offset..)?)?;
    offset += 2;
    let end = offset.checked_add(extensions_len)?;
    if end > body.len() {
        return None;
    }
    while offset + 4 <= end {
        let extension_type = be16(body.get(offset..)?)?;
        let extension_len = be16(body.get(offset + 2..)?)?;
        offset += 4;
        let extension_end = offset.checked_add(extension_len)?;
        if extension_end > end {
            return None;
        }
        if extension_type == 51 {
            return body.get(offset..extension_end);
        }
        offset = extension_end;
    }
    None
}

fn find_hello(records: &[u8], handshake_type: u8, label: &[u8]) -> Option<HelloKey> {
    let mut record_offset = 0usize;
    let mut handshake = Vec::new();
    while record_offset + 5 <= records.len() {
        let content_type = records[record_offset];
        let record_len = be16(records.get(record_offset + 3..)?)?;
        let record_end = record_offset.checked_add(5 + record_len)?;
        if record_end > records.len() {
            return None;
        }
        if content_type == 22 {
            handshake.extend_from_slice(&records[record_offset + 5..record_end]);
            let mut h = 0usize;
            while h + 4 <= handshake.len() {
                let message_len = ((handshake[h + 1] as usize) << 16)
                    | ((handshake[h + 2] as usize) << 8)
                    | handshake[h + 3] as usize;
                let message_end = h.checked_add(4 + message_len)?;
                if message_end > handshake.len() {
                    break;
                }
                if handshake[h] == handshake_type {
                    let extension =
                        find_extension(&handshake[h + 4..message_end], handshake_type == 1)?;
                    return Some(HelloKey {
                        key: derive(label, extension),
                        consumed: record_end,
                    });
                }
                h = message_end;
            }
        }
        record_offset = record_end;
    }
    None
}

pub fn find_client_hello(records: &[u8]) -> Option<HelloKey> {
    find_hello(records, 1, CLIENT_LABEL)
}

pub fn find_server_hello(records: &[u8]) -> Option<HelloKey> {
    find_hello(records, 2, SERVER_LABEL)
}

pub fn contains_encrypted_record(records: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + 5 <= records.len() {
        let record_len = match be16(&records[offset + 3..]) {
            Some(value) => value,
            None => return false,
        };
        let end = match offset.checked_add(5 + record_len) {
            Some(value) => value,
            None => return false,
        };
        if end > records.len() {
            return false;
        }
        if records[offset] == 23 {
            return true;
        }
        offset = end;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(handshake_type: u8, client: bool, extension: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend([7u8; 32]);
        body.push(0); // session-id
        if client {
            body.extend([0, 2, 0x13, 0x01]);
            body.extend([1, 0]);
        } else {
            body.extend([0x13, 0x01, 0]);
        }
        body.extend(((4 + extension.len()) as u16).to_be_bytes());
        body.extend(51u16.to_be_bytes());
        body.extend((extension.len() as u16).to_be_bytes());
        body.extend(extension);

        let mut handshake = vec![handshake_type];
        let n = body.len();
        handshake.extend([((n >> 16) & 0xff) as u8, ((n >> 8) & 0xff) as u8, n as u8]);
        handshake.extend(body);

        let mut out = vec![22, 0x03, 0x03];
        out.extend((handshake.len() as u16).to_be_bytes());
        out.extend(handshake);
        out
    }

    #[test]
    fn derives_client_and_server_keys_from_exact_extension_data() {
        let client_extension = [0, 6, 0, 29, 0, 2, 0xaa, 0xbb];
        let server_extension = [0, 29, 0, 2, 0xcc, 0xdd];
        let client = record(1, true, &client_extension);
        let server = record(2, false, &server_extension);
        assert_eq!(
            find_client_hello(&client).unwrap().key,
            derive(CLIENT_LABEL, &client_extension)
        );
        assert_eq!(
            find_server_hello(&server).unwrap().key,
            derive(SERVER_LABEL, &server_extension)
        );
        assert_ne!(
            find_client_hello(&client).unwrap().key,
            find_server_hello(&server).unwrap().key
        );
    }

    #[test]
    fn rejects_incomplete_record_and_finds_application_data() {
        let mut client = record(1, true, &[0, 2, 0, 29]);
        client.pop();
        assert!(find_client_hello(&client).is_none());
        assert!(!contains_encrypted_record(&client));
        assert!(contains_encrypted_record(&[23, 3, 3, 0, 1, 0]));
    }
}

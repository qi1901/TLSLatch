use serde::Serialize;
use sm2::dsa::{signature::Verifier, Signature, VerifyingKey};
use std::fmt;

pub const CSV_REPORT_SIZE: usize = 2548;
pub const CSV_BINDING_SIZE: usize = 64;
pub const CSV_PEK_SIZE: usize = 64;
pub const CSV_MEASUREMENT_SIZE: usize = 32;

const USER_DATA_OFFSET: usize = 64;
const MEASUREMENT_OFFSET: usize = 144;
const SIGNED_SIZE: usize = 180;
const ANONCE_OFFSET: usize = 188;
const REPORT_SIGNATURE_OFFSET: usize = 192;
const REPORT_PEK_OFFSET: usize = 336;
const CSV_CERT_SIZE: usize = 2084;
const CERT_POINT_OFFSET: usize = 16;
const POINT_X_OFFSET: usize = 4;
const POINT_Y_OFFSET: usize = 76;
const POINT_UID_OFFSET: usize = 148;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyError {
    InvalidReportLength,
    InvalidExpectedLength,
    InvalidTrustedPekLength,
    InvalidTrustedMeasurementLength,
    BindingMismatch,
    InvalidCurve,
    InvalidUserId,
    InvalidPublicKey,
    InvalidSignatureEncoding,
    SignatureMismatch,
    PekMismatch,
    MeasurementMismatch,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for VerifyError {}

#[derive(Clone, Debug, Serialize)]
pub struct VerificationDetails {
    pub verified: bool,
    pub user_id: String,
    pub pek_hex: String,
    pub measurement_hex: String,
}

fn xor_words(input: &[u8], nonce: u32) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    for word in input.chunks_exact(4) {
        let value = u32::from_le_bytes(word.try_into().expect("four-byte word")) ^ nonce;
        output.extend_from_slice(&value.to_le_bytes());
    }
    output
}

fn reversed_32(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = input[31 - index];
    }
    output
}

pub fn verify_report(
    report: &[u8],
    expected: &[u8],
    trusted_pek: &[u8],
    trusted_measurement: &[u8],
) -> Result<VerificationDetails, VerifyError> {
    if report.len() != CSV_REPORT_SIZE {
        return Err(VerifyError::InvalidReportLength);
    }
    if expected.len() != CSV_BINDING_SIZE {
        return Err(VerifyError::InvalidExpectedLength);
    }
    if trusted_pek.len() != CSV_PEK_SIZE {
        return Err(VerifyError::InvalidTrustedPekLength);
    }
    if trusted_measurement.len() != CSV_MEASUREMENT_SIZE {
        return Err(VerifyError::InvalidTrustedMeasurementLength);
    }

    let nonce = u32::from_le_bytes(
        report[ANONCE_OFFSET..ANONCE_OFFSET + 4]
            .try_into()
            .expect("report nonce"),
    );
    let user_data = xor_words(
        &report[USER_DATA_OFFSET..USER_DATA_OFFSET + CSV_BINDING_SIZE],
        nonce,
    );
    if user_data != expected {
        return Err(VerifyError::BindingMismatch);
    }

    let pek = xor_words(
        &report[REPORT_PEK_OFFSET..REPORT_PEK_OFFSET + CSV_CERT_SIZE],
        nonce,
    );
    let point = CERT_POINT_OFFSET;
    let curve = u32::from_le_bytes(pek[point..point + 4].try_into().expect("curve identifier"));
    if curve != 3 {
        return Err(VerifyError::InvalidCurve);
    }

    let x_offset = point + POINT_X_OFFSET;
    let y_offset = point + POINT_Y_OFFSET;
    let uid_offset = point + POINT_UID_OFFSET;
    let x = reversed_32(&pek[x_offset..x_offset + 32]);
    let y = reversed_32(&pek[y_offset..y_offset + 32]);
    let uid_length = u16::from_le_bytes(
        pek[uid_offset..uid_offset + 2]
            .try_into()
            .expect("user id length"),
    ) as usize;
    if uid_length > 254 || uid_offset + 2 + uid_length > pek.len() {
        return Err(VerifyError::InvalidUserId);
    }
    let user_id = std::str::from_utf8(&pek[uid_offset + 2..uid_offset + 2 + uid_length])
        .map_err(|_| VerifyError::InvalidUserId)?;

    let mut sec1_public_key = [0u8; 65];
    sec1_public_key[0] = 4;
    sec1_public_key[1..33].copy_from_slice(&x);
    sec1_public_key[33..65].copy_from_slice(&y);
    let verifying_key = VerifyingKey::from_sec1_bytes(user_id, &sec1_public_key)
        .map_err(|_| VerifyError::InvalidPublicKey)?;

    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(&reversed_32(
        &report[REPORT_SIGNATURE_OFFSET..REPORT_SIGNATURE_OFFSET + 32],
    ));
    signature_bytes[32..].copy_from_slice(&reversed_32(
        &report[REPORT_SIGNATURE_OFFSET + 72..REPORT_SIGNATURE_OFFSET + 104],
    ));
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| VerifyError::InvalidSignatureEncoding)?;
    verifying_key
        .verify(&report[..SIGNED_SIZE], &signature)
        .map_err(|_| VerifyError::SignatureMismatch)?;

    let mut actual_pek = [0u8; CSV_PEK_SIZE];
    actual_pek[..32].copy_from_slice(&x);
    actual_pek[32..].copy_from_slice(&y);
    if actual_pek != trusted_pek {
        return Err(VerifyError::PekMismatch);
    }

    let measurement = xor_words(
        &report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + CSV_MEASUREMENT_SIZE],
        nonce,
    );
    if measurement != trusted_measurement {
        return Err(VerifyError::MeasurementMismatch);
    }

    Ok(VerificationDetails {
        verified: true,
        user_id: user_id.to_owned(),
        pek_hex: hex::encode(actual_pek),
        measurement_hex: hex::encode(measurement),
    })
}

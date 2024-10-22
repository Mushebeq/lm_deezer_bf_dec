use pyo3::prelude::*;
use hex::encode;
use blowfish::Blowfish;
use md5::{Md5, Digest};
use reqwest::blocking::get;
use std::{fs::File, io::Write};
use blowfish::cipher::{
    KeyIvInit, BlockDecryptMut, block_padding::NoPadding
};

const IV: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const SECRET_KEY: &[u8; 16] = b"g4el58wc0zvf9na1";
const DEFAULT_BLOCK: usize = 2048;
const DEFAULT_BLOCK_STREAM: usize = DEFAULT_BLOCK * 3;
type BlowCbcDec = cbc::Decryptor<Blowfish>;

mod lm_dw_deezer {
    pyo3::import_exception!(lm_dw_deezer.exceptions.no_stream_data, No_Stream_Data);
}

fn gen_blowfish_key(id_track: &str) -> Vec<u8> {
    let id_md5 = Md5::digest(id_track);
    let binding = encode(id_md5);
    let hex_id_md5 = binding.as_bytes();
    let mut bf_key = Vec::new();
    for i in 0..16 {
        let hex_byte = hex_id_md5[i] ^ hex_id_md5[i + 16] ^ SECRET_KEY[i];
        bf_key.push(hex_byte);
    }
    bf_key
}

fn decrypt_track(id_track: &str, media_url: &str, save_path: &str, progress_callback: impl Fn(f32)) -> PyResult<()> {
    let response = get(media_url).unwrap();
    if response.status() == 403 {
        return Err(
            lm_dw_deezer::No_Stream_Data::new_err(
                (String::from(id_track), String::from(save_path))
            )
        );
    }
    
    let mut encrypted_song = response.bytes().unwrap().to_vec();
    let total_chunks = (encrypted_song.len() as f32 / DEFAULT_BLOCK_STREAM as f32).ceil();
    let mut file = File::create(save_path).unwrap();
    let bf_key: Vec<u8> = gen_blowfish_key(id_track);
    let pt: BlowCbcDec = BlowCbcDec::new_from_slices(&bf_key, IV).unwrap();

    // Iterate through encrypted_song chunks with progress
    for (chunk_index, chunk) in encrypted_song.chunks_mut(DEFAULT_BLOCK_STREAM).enumerate() {
        if chunk.len() >= DEFAULT_BLOCK {
            let _ = pt.clone().decrypt_padded_mut::<NoPadding>(&mut chunk[..DEFAULT_BLOCK]);
        }
        let _ = file.write(chunk);
        
        // Calculate and report progress
        let progress = (chunk_index as f32 / total_chunks) * 100.0;
        progress_callback(progress);
    }
    
    // Report 100% completion
    progress_callback(100.0);
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (id_track, media_url, save_path, progress_callback=None))]
fn decrypt_track_py(
    py: Python<'_>,
    id_track: &str,
    media_url: &str,
    save_path: &str,
    progress_callback: Option<PyObject>,
) -> PyResult<()> {
    py.allow_threads(move || {
        decrypt_track(id_track, media_url, save_path, |progress| {
            if let Some(callback) = &progress_callback {
                Python::with_gil(|py| {
                    let _ = callback.call1(py, (progress,));
                });
            }
        })
    })
}

#[pymodule]
fn lm_deezer_bf_dec(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(decrypt_track_py, m)?)?;
    Ok(())
}
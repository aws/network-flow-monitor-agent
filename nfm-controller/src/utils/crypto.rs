use log::debug;

/// Make sure that a default crypto provider exists as Kube Client will depend on it.
pub fn ensure_default_crypto_provider_exists() {
    match rustls::crypto::CryptoProvider::get_default() {
        Some(_) => {
            debug!(
                "A default crypto provider is already assigned to the process, skipping creation."
            );
        }
        None => {
            debug!("No crypto provider exists for the process, creating one.");
            let default_provider = rustls::crypto::ring::default_provider();
            rustls::crypto::CryptoProvider::install_default(default_provider)
                .expect("Crypto Provider is empty");
        }
    }
}

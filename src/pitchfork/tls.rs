use crate::TIME_PROVIDER;
use chrono::{DateTime, NaiveDateTime};
use embedded_tls::pki::CertVerifier;
use embedded_tls::{
    Certificate, CryptoProvider, CryptoRngCore, SignatureScheme, TlsCipherSuite, TlsClock,
    TlsError, UnsecureProvider,
};
use signature::SignerMut;

pub struct PitchforkTlsClock;

impl TlsClock for PitchforkTlsClock {
    fn now() -> Option<u64> {
        let time_provider = TIME_PROVIDER.try_get()?;
        let now = time_provider.now().ok()?;
        let now: NaiveDateTime = now.into();
        Some(
            now.signed_duration_since(DateTime::UNIX_EPOCH.naive_utc())
                .num_seconds() as u64,
        )
    }
}

pub struct PitchforkCryptoProvider<'a, CipherSuite: TlsCipherSuite, RNG> {
    inner_provider: UnsecureProvider<'a, CipherSuite, RNG>,
    verifier: Option<CertVerifier<'a, CipherSuite, PitchforkTlsClock, 4096>>,
}

impl<'a, CipherSuite: TlsCipherSuite, RNG: CryptoRngCore>
    PitchforkCryptoProvider<'a, CipherSuite, RNG>
{
    pub fn new(rng: RNG) -> PitchforkCryptoProvider<'a, CipherSuite, RNG> {
        PitchforkCryptoProvider {
            inner_provider: UnsecureProvider::new::<CipherSuite>(rng),
            verifier: None,
        }
    }

    pub fn with_priv_key(mut self, priv_key: &'a [u8]) -> Self {
        self.inner_provider = self.inner_provider.with_priv_key(priv_key);
        self
    }

    pub fn with_cert(mut self, cert: Certificate<&'a [u8]>) -> Self {
        self.inner_provider = self.inner_provider.with_cert(cert);
        self
    }

    pub fn with_ca(mut self, ca: Certificate<&'a [u8]>) -> Self {
        self.verifier = Some(CertVerifier::new(ca));
        self
    }
}

impl<'a, CipherSuite: TlsCipherSuite, RNG: CryptoRngCore> CryptoProvider
    for PitchforkCryptoProvider<'a, CipherSuite, RNG>
{
    type CipherSuite = CipherSuite;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl CryptoRngCore {
        self.inner_provider.rng()
    }

    fn verifier(
        &mut self,
    ) -> Result<&mut impl embedded_tls::TlsVerifier<Self::CipherSuite>, embedded_tls::TlsError>
    {
        if let Some(verifier) = &mut self.verifier {
            Ok(verifier)
        } else {
            Err(TlsError::Unimplemented)
        }
    }

    fn signer(&mut self) -> Result<(impl SignerMut<Self::Signature>, SignatureScheme), TlsError> {
        self.inner_provider.signer()
    }

    fn client_cert(&mut self) -> Option<Certificate<impl AsRef<[u8]>>> {
        self.inner_provider.client_cert()
    }
}

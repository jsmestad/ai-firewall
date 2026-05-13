use rcgen::{CertificateParams, KeyPair, Issuer};
fn main() {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["CA".to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key_pair).unwrap();
    // How to sign a child?
}

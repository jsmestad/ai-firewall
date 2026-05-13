use rcgen::{CertificateParams, KeyPair};
fn main() {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["AI Firewall CA".to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key_pair).unwrap();
    println!("CA PEM generated successfully.");
}

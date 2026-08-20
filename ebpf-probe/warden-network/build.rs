use anyhow::{anyhow, Context as _};

fn main() -> aya_build::Result<()> {
    let cargo_metadata::Metadata { packages, .. } =
        cargo_metadata::MetadataCommand::new().no_deps().exec().context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "warden-network-ebpf")
        .ok_or_else(|| anyhow!("warden-network-ebpf package not found"))?;
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "warden-network-ebpf",
            root_dir: ebpf_package.manifest_path.parent().unwrap().as_str(),
            no_default_features: false,
            features: &[],
        }],
        aya_build::Toolchain::Nightly,
    )
}

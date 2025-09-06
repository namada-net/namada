use git2::{DescribeFormatOptions, DescribeOptions, Repository};

fn main() {
    // Discover the repository version, if it exists
    println!("cargo:rerun-if-changed=../../.git");
    let describe_opts = DescribeOptions::new();
    let mut describe_format = DescribeFormatOptions::new();
    describe_format.dirty_suffix("-dirty");
    let version = Repository::discover(".")
        .ok()
        .as_ref()
        .and_then(|repo| repo.describe(&describe_opts).ok())
        .and_then(|describe| describe.format(Some(&describe_format)).ok());
    if let Some(version) = version {
        println!("cargo:rustc-env=GIT_DESCRIBED={version}");
    }
}

use anyhow::Result;

#[derive(serde::Deserialize, Debug)]
struct WorkflowRuns {
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(serde::Deserialize, Debug)]
struct WorkflowRun {
    conclusion: Option<String>,
}

pub fn test() -> Result<()> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let crab = octocrab::Octocrab::builder().build()?;
        let url = format!("/repos/chipsalliance/caliptra-sw/actions/workflows/nightly-release.yml/runs?head_sha={}", "abc");
        let runs: WorkflowRuns = crab.get(url, None::<&()>).await?;
        println!("{:?}", runs);
        Ok::<(), anyhow::Error>(())
    })
}

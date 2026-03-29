/// Campaign test — exercises multi-ECU orchestration against the simulation.
///
/// Run the simulation first:
///   cd simulations/multi-ecu && ./start.sh
///
/// Then run this test:
///   cargo run --example campaign_test
///
/// Test scenarios:
/// 1. Normal campaign: flash os1 + engine_ecu, commit all
/// 2. A/B test: flash os1 v1.1.0, commit, then v1.0.0 (downgrade within same secver)
/// 3. CRL: bump security floor on os1
/// 4. Rollback test: flash os1, then rollback before commit

use sumo_sovd_orchestrator::campaign::{
    CampaignConfig, CampaignOrchestrator, EcuTarget,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let server_url = std::env::var("SOVD_URL")
        .unwrap_or_else(|_| "http://localhost:4000".to_string());

    // Load trust anchor from vm-mgr example keys
    let vmmgr_dir = std::env::var("VMMGR_DIR")
        .unwrap_or_else(|_| format!("{}/dev/vm-mgr", std::env::var("HOME").unwrap()));
    let trust_anchor = std::fs::read(format!("{vmmgr_dir}/example/keys/signing.pub"))
        .expect("trust anchor not found — run vm-mgr example/build first");

    let orchestrator = CampaignOrchestrator::new(CampaignConfig {
        server_url,
        trust_anchor,
        security_level: 1,
    });

    // Load firmware packages
    let output_dir = format!("{vmmgr_dir}/example/output");

    println!("=== Campaign Test ===\n");

    // --- Test 1: Single-ECU flash (os1 v1.0.0) ---
    println!("--- Test 1: Flash os1 v1.0.0 ---");
    let os1_v100 = std::fs::read(format!("{output_dir}/os1-v1.0.0.suit"))
        .expect("os1-v1.0.0.suit not found");

    let result = orchestrator
        .flash_all(vec![EcuTarget {
            component_id: "os1".into(),
            gateway_id: None,
            package: os1_v100.clone(),
        }])
        .await;

    match result {
        Ok(phase) => {
            println!("  Flash phase complete — {} ECUs in trial", phase.ecus.len());
            for ecu in &phase.ecus {
                println!("    {} → {:?}", ecu.component_id, ecu.state);
            }

            // Commit
            println!("  Committing...");
            orchestrator.commit_all(&phase.ecus).await.expect("commit failed");
            println!("  Committed!\n");
        }
        Err(e) => {
            println!("  FAILED: {e}\n");
        }
    }

    // --- Test 2: A/B test (flash v1.1.0 then back to v1.0.0) ---
    println!("--- Test 2: A/B test — v1.1.0 then v1.0.0 ---");
    let os1_v110 = std::fs::read(format!("{output_dir}/os1-v1.1.0.suit"))
        .expect("os1-v1.1.0.suit not found");

    let result = orchestrator
        .flash_all(vec![EcuTarget {
            component_id: "os1".into(),
            gateway_id: None,
            package: os1_v110,
        }])
        .await;

    match result {
        Ok(phase) => {
            println!("  v1.1.0 in trial — committing...");
            orchestrator.commit_all(&phase.ecus).await.expect("commit failed");
            println!("  Committed v1.1.0");

            // Now go back to v1.0.0 (same secver, should work)
            let result2 = orchestrator
                .flash_all(vec![EcuTarget {
                    component_id: "os1".into(),
                    gateway_id: None,
                    package: os1_v100.clone(),
                }])
                .await;

            match result2 {
                Ok(phase2) => {
                    println!("  v1.0.0 in trial — committing...");
                    orchestrator.commit_all(&phase2.ecus).await.expect("commit failed");
                    println!("  Committed v1.0.0 — A/B test passed!\n");
                }
                Err(e) => println!("  FAILED to downgrade: {e}\n"),
            }
        }
        Err(e) => println!("  FAILED: {e}\n"),
    }

    // --- Test 3: Rollback test ---
    println!("--- Test 3: Flash then rollback ---");
    let os1_v120 = std::fs::read(format!("{output_dir}/os1-v1.2.0.suit"))
        .expect("os1-v1.2.0.suit not found");

    let result = orchestrator
        .flash_all(vec![EcuTarget {
            component_id: "os1".into(),
            gateway_id: None,
            package: os1_v120,
        }])
        .await;

    match result {
        Ok(phase) => {
            println!("  v1.2.0 in trial — rolling back...");
            orchestrator.rollback_all(&phase.ecus).await.expect("rollback failed");
            println!("  Rolled back!\n");
        }
        Err(e) => println!("  FAILED: {e}\n"),
    }

    // --- Test 4: CRL floor bump ---
    println!("--- Test 4: CRL security floor bump ---");
    let crl = std::fs::read(format!("{output_dir}/os1-crl-secver2.suit"))
        .expect("os1-crl-secver2.suit not found");

    let result = orchestrator
        .flash_all(vec![EcuTarget {
            component_id: "os1".into(),
            gateway_id: None,
            package: crl,
        }])
        .await;

    match result {
        Ok(phase) => {
            println!("  CRL applied — committing...");
            orchestrator.commit_all(&phase.ecus).await.expect("commit failed");
            println!("  Floor raised to secver=2");

            // Now v1.0.0 (secver=1) should be rejected
            println!("  Trying v1.0.0 (should be rejected)...");
            match orchestrator
                .flash_all(vec![EcuTarget {
                    component_id: "os1".into(),
                    gateway_id: None,
                    package: os1_v100,
                }])
                .await
            {
                Ok(_) => println!("  ERROR: v1.0.0 should have been rejected!\n"),
                Err(e) => println!("  Correctly rejected: {e}\n"),
            }
        }
        Err(e) => println!("  FAILED: {e}\n"),
    }

    println!("=== Campaign Test Complete ===");
}

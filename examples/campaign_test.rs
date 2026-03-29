/// Campaign integration test — manages its own simulation lifecycle.
///
/// Starts fresh infrastructure, runs all tests, cleans up.
///
/// Usage:
///   cargo run --example campaign_test
///
/// Environment:
///   VMMGR_DIR   — vm-mgr repo (default: ~/dev/vm-mgr)
///   SOVDD_DIR   — SOVDd repo (default: ~/dev/SOVDd)
///   SIM_DIR     — simulation dir (default: ../simulations/multi-ecu)

use std::process::{Command, Child};
use std::time::Duration;

use sumo_sovd_orchestrator::campaign::{
    CampaignConfig, CampaignOrchestrator, EcuTarget, EcuState,
};
use sumo_sovd_orchestrator::security_helper::SecurityHelperConfig;
use sumo_sovd_orchestrator::UpdateType;

fn load_suit(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

struct SimulationGuard {
    children: Vec<Child>,
}

impl SimulationGuard {
    fn start(sim_dir: &str) -> Self {
        // Reset any stale state
        let _ = Command::new("bash")
            .arg(format!("{sim_dir}/reset.sh"))
            .output();

        // Start simulation
        let child = Command::new("bash")
            .arg(format!("{sim_dir}/start.sh"))
            .spawn()
            .expect("failed to start simulation");

        // Wait for services to come up
        std::thread::sleep(Duration::from_secs(8));

        Self { children: vec![child] }
    }
}

impl Drop for SimulationGuard {
    fn drop(&mut self) {
        // Kill simulation
        for child in &mut self.children {
            let _ = child.kill();
        }
        let _ = Command::new("bash")
            .arg("-c")
            .arg("fuser -k 4000/tcp 4001/tcp 9100/tcp 2>/dev/null; pkill -9 -f 'example-ecu|sovdd|vm-sovd|sovd-security-helper' 2>/dev/null; rm -f /tmp/sumo-sovd-sim-nv.bin")
            .output();
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let vmmgr_dir = std::env::var("VMMGR_DIR")
        .unwrap_or_else(|_| format!("{}/dev/vm-mgr", std::env::var("HOME").unwrap()));
    let sovdd_dir = std::env::var("SOVDD_DIR")
        .unwrap_or_else(|_| format!("{}/dev/SOVDd", std::env::var("HOME").unwrap()));
    let sim_dir = std::env::var("SIM_DIR")
        .unwrap_or_else(|_| format!("{}/dev/sumo-sovd/simulations/multi-ecu", std::env::var("HOME").unwrap()));

    let server_url = "http://localhost:4000".to_string();
    let trust_anchor = std::fs::read(format!("{vmmgr_dir}/example/keys/signing.pub"))
        .expect("trust anchor not found — run vm-mgr example/build first");
    let output_dir = format!("{vmmgr_dir}/example/output");
    let sovdd_fw_dir = format!("{sovdd_dir}/simulations/supplier_ota/firmware");
    let gw = Some("vehicle_gateway".to_string());

    let orchestrator = CampaignOrchestrator::new(CampaignConfig {
        server_url,
        trust_anchor,
        security_level: 1,
        security_helper: SecurityHelperConfig {
            url: "http://localhost:9100".to_string(),
            token: "dev-secret-123".to_string(),
        },
    });

    // Start fresh simulation
    println!("Starting simulation...");
    let _sim = SimulationGuard::start(&sim_dir);
    println!("Simulation running.\n");

    let mut passed = 0;
    let mut failed = 0;

    // ================================================================
    // Test 1: Flash os1 v1.0.0 + commit
    // ================================================================
    print_test("1: Flash os1 v1.0.0 and commit");
    match orchestrator.flash_all(vec![EcuTarget {
        component_id: "os1".into(),
        gateway_id: gw.clone(),
        package: load_suit(&format!("{output_dir}/os1-v1.0.0.suit")),
    }]).await {
        Ok(phase) => {
            assert_state(&phase.ecus, "os1", EcuState::Activated);
            orchestrator.commit_all(&phase.ecus).await.expect("commit");
            print_pass("v1.0.0 flashed and committed");
            passed += 1;
        }
        Err(e) => { print_fail(&format!("{e}")); failed += 1; }
    }

    // ================================================================
    // Test 2: A/B test — flash v1.1.0, commit, then back to v1.0.0
    // ================================================================
    print_test("2: A/B test — v1.1.0 then back to v1.0.0");
    match orchestrator.flash_all(vec![EcuTarget {
        component_id: "os1".into(),
        gateway_id: gw.clone(),
        package: load_suit(&format!("{output_dir}/os1-v1.1.0.suit")),
    }]).await {
        Ok(phase) => {
            orchestrator.commit_all(&phase.ecus).await.expect("commit v1.1.0");
            match orchestrator.flash_all(vec![EcuTarget {
                component_id: "os1".into(),
                gateway_id: gw.clone(),
                package: load_suit(&format!("{output_dir}/os1-v1.0.0.suit")),
            }]).await {
                Ok(phase2) => {
                    orchestrator.commit_all(&phase2.ecus).await.expect("commit v1.0.0");
                    print_pass("downgrade v1.1.0 → v1.0.0 works (same security floor)");
                    passed += 1;
                }
                Err(e) => { print_fail(&format!("downgrade failed: {e}")); failed += 1; }
            }
        }
        Err(e) => { print_fail(&format!("{e}")); failed += 1; }
    }

    // ================================================================
    // Test 3: Flash v1.2.0 then rollback
    // ================================================================
    print_test("3: Flash v1.2.0 then rollback");
    match orchestrator.flash_all(vec![EcuTarget {
        component_id: "os1".into(),
        gateway_id: gw.clone(),
        package: load_suit(&format!("{output_dir}/os1-v1.2.0.suit")),
    }]).await {
        Ok(phase) => {
            assert_state(&phase.ecus, "os1", EcuState::Activated);
            orchestrator.rollback_all(&phase.ecus).await.expect("rollback");
            print_pass("v1.2.0 flashed then rolled back");
            passed += 1;
        }
        Err(e) => { print_fail(&format!("{e}")); failed += 1; }
    }

    // ================================================================
    // Test 4: Reinstall same version
    // ================================================================
    print_test("4: Reinstall same version (v1.0.0)");
    match orchestrator.flash_all(vec![EcuTarget {
        component_id: "os1".into(),
        gateway_id: gw.clone(),
        package: load_suit(&format!("{output_dir}/os1-v1.0.0.suit")),
    }]).await {
        Ok(phase) => {
            orchestrator.commit_all(&phase.ecus).await.expect("commit");
            print_pass("reinstall same version works");
            passed += 1;
        }
        Err(e) => { print_fail(&format!("{e}")); failed += 1; }
    }

    // ================================================================
    // Test 5: Multi-ECU campaign (os1 + engine_ecu)
    // ================================================================
    print_test("5: Multi-ECU campaign (os1 + engine_ecu)");
    let engine_fw_path = format!("{sovdd_fw_dir}/engine_ecu_fw_v2.0.0.bin");
    if std::path::Path::new(&engine_fw_path).exists() {
        match orchestrator.flash_all(vec![
            EcuTarget {
                component_id: "os1".into(),
                gateway_id: gw.clone(),
                package: load_suit(&format!("{output_dir}/os1-v1.3.0.suit")),
            },
            EcuTarget {
                component_id: "engine_ecu".into(),
                gateway_id: gw.clone(),
                package: std::fs::read(&engine_fw_path).unwrap(),
            },
        ]).await {
            Ok(phase) => {
                for ecu in &phase.ecus {
                    println!("    {} → {:?}", ecu.component_id, ecu.state);
                }
                orchestrator.commit_all(&phase.ecus).await.expect("commit multi-ECU");
                print_pass("os1 + engine_ecu flashed and committed together");
                passed += 1;
            }
            Err(e) => { print_fail(&format!("{e}")); failed += 1; }
        }
    } else {
        println!("  SKIP: engine_ecu firmware not found");
    }

    // ================================================================
    // Test 6: CRL — MUST BE LAST (permanently blocks secver < 2)
    // ================================================================
    print_test("6: CRL security floor bump (secver < 2 blocked)");
    match orchestrator.flash_all(vec![EcuTarget {
        component_id: "os1".into(),
        gateway_id: gw.clone(),
        package: load_suit(&format!("{output_dir}/os1-crl-secver2.suit")),
    }]).await {
        Ok(phase) => {
            let os1 = phase.ecus.iter().find(|e| e.component_id == "os1").unwrap();
            if os1.update_type != UpdateType::Policy {
                print_fail(&format!("expected Policy, got {:?}", os1.update_type));
                failed += 1;
            } else {
                orchestrator.commit_all(&phase.ecus).await.expect("commit CRL");
                print_pass("CRL applied (floor raised to 2)");

                // v1.0.0 should be rejected
                match orchestrator.flash_all(vec![EcuTarget {
                    component_id: "os1".into(),
                    gateway_id: gw.clone(),
                    package: load_suit(&format!("{output_dir}/os1-v1.0.0.suit")),
                }]).await {
                    Ok(_) => { print_fail("v1.0.0 should have been rejected!"); failed += 1; }
                    Err(_) => {
                        // v1.2.0-secver2 should work
                        match orchestrator.flash_all(vec![EcuTarget {
                            component_id: "os1".into(),
                            gateway_id: gw.clone(),
                            package: load_suit(&format!("{output_dir}/os1-v1.2.0-secver2-full.suit")),
                        }]).await {
                            Ok(phase3) => {
                                orchestrator.commit_all(&phase3.ecus).await.expect("commit v1.2.0");
                                print_pass("v1.0.0 rejected, v1.2.0 accepted after CRL");
                                passed += 1;
                            }
                            Err(e) => { print_fail(&format!("v1.2.0 should work: {e}")); failed += 1; }
                        }
                    }
                }
            }
        }
        Err(e) => { print_fail(&format!("{e}")); failed += 1; }
    }

    // ================================================================
    // Summary (simulation stops automatically via SimulationGuard Drop)
    // ================================================================
    println!("\n{}", "=".repeat(60));
    println!("  {} passed, {} failed", passed, failed);
    if failed > 0 {
        std::process::exit(1);
    }
}

fn print_test(name: &str) { println!("\n--- Test {name} ---"); }
fn print_pass(msg: &str) { println!("  PASS: {msg}"); }
fn print_fail(msg: &str) { println!("  FAIL: {msg}"); }

fn assert_state(ecus: &[sumo_sovd_orchestrator::campaign::EcuStatus], comp: &str, expected: EcuState) {
    let ecu = ecus.iter().find(|e| e.component_id == comp)
        .unwrap_or_else(|| panic!("ECU {comp} not found"));
    assert_eq!(ecu.state, expected, "ECU {comp} expected {expected:?} got {:?}", ecu.state);
}

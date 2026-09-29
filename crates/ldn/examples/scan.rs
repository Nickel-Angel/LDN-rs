//! 扫描附近的 LDN 网络并打印（对应 Python 版 examples/scan.py）。
//!
//! ```bash
//! cargo build --example scan
//! sudo target/debug/examples/scan ~/.switch/prod.keys [phy0]
//! ```

use ldn::{Keys, ScanParam};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let keys_path = args.next().ok_or("usage: scan <prod.keys> [phy]")?;
    let mut param = ScanParam::new(Keys::load(keys_path)?);
    if let Some(phy) = args.next() {
        param.phy = phy;
    }

    println!("Scanning for LDN networks...");
    let networks = ldn::scan(&param).await?;
    println!("Found {} network(s).", networks.len());
    for network in networks {
        println!(
            "  {} on channel {}: game {:016X}, scene {}, {}/{} players, protocol {}",
            network.address,
            network.channel,
            network.local_communication_id,
            network.scene_id,
            network.num_participants,
            network.max_participants,
            network.protocol.0,
        );
        for (i, p) in network
            .participants
            .iter()
            .enumerate()
            .filter(|(_, p)| p.connected)
        {
            println!(
                "    [{i}] {} ({})",
                String::from_utf8_lossy(&p.name),
                p.mac_address
            );
        }
    }
    Ok(())
}

//! 为《超级马力欧创作家 2》建一个 4 人房间，打印成员进出（对应 Python 版 examples/host.py）。
//!
//! ```bash
//! cargo build --example host
//! sudo target/debug/examples/host ~/.switch/prod.keys
//! ```
//! 真 Switch 能在房间列表里看到它，但加入后游戏层（Pia）没有人应答，这与 Python 示例一致。

use ldn::{CreateNetworkParam, Event, HostConfig, Keys, Protocol};

const NICKNAME: &str = "Hello!";

/// 游戏自定义的应用数据：Pia 头 + SMM2 头（昵称）+ 全零 Mii，格式照搬 Python 示例。
fn application_data() -> Vec<u8> {
    let random = ldn::event::random_bytes::<24>();
    let mut d = Vec::new();
    d.extend_from_slice(&random[0..4]); // session id
    d.extend_from_slice(&0u32.to_le_bytes()); // CRC-32
    d.extend_from_slice(&[5, 24, 0, 0]); // system communication version, header size
    d.extend_from_slice(&random[4..8]); // session param
    d.extend_from_slice(&[0; 8]);
    d.extend_from_slice(&random[8..16]); // network service account id
    let mut name: Vec<u16> = NICKNAME.encode_utf16().collect();
    name.resize(11, 0);
    d.extend(name.iter().flat_map(|c| c.to_le_bytes()));
    d.extend_from_slice(&[0; 2 + 88 + 24]);
    d
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = Keys::load(std::env::args().nth(1).ok_or("usage: host <prod.keys>")?)?;

    let mut config = HostConfig::new(Protocol::V1);
    config.local_communication_id = 0x0100_9B90_006D_C000;
    config.scene_id = 1;
    config.max_participants = 4;
    config.application_data = application_data();
    config.name = NICKNAME.as_bytes().to_vec();
    config.app_version = 7;
    config.password = b"LunchPack2DefaultPhrase".to_vec();

    println!("Creating network on channel {}.", config.channel);
    let mut network = ldn::create_network(CreateNetworkParam::new(keys, config)).await?;
    println!("Listening for events (Ctrl-C to stop).");

    let result = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            event = network.next_event() => match event {
                Ok(Event::Join { participant: p, .. }) => {
                    println!("{} joined the network ({} / {})", String::from_utf8_lossy(&p.name), p.mac_address, p.ip_address)
                }
                Ok(Event::Leave { participant: p, .. }) => {
                    println!("{} left the network ({} / {})", String::from_utf8_lossy(&p.name), p.mac_address, p.ip_address)
                }
                Ok(_) => {}
                Err(e) => break Err(e),
            },
        }
    };
    network.close().await?;
    Ok(result?)
}

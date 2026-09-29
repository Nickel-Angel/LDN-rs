//! 加入扫描到的第一个 LDN 网络，打印事件直到被断开或按 Ctrl-C（对应 Python 版 examples/join.py）。
//!
//! ```bash
//! cargo build --example join
//! sudo target/debug/examples/join ~/.switch/prod.keys <房间密码> [用户名]
//! ```
//! 密码由游戏决定，例如《超级马力欧创作家 2》是 `LunchPack2DefaultPhrase`。

use ldn::{ConnectParam, Event, Keys, ScanParam};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let keys = Keys::load(
        args.next()
            .ok_or("usage: join <prod.keys> <password> [name]")?,
    )?;
    let password = args.next().ok_or("missing password")?;
    let name = args.next().unwrap_or_else(|| "Rust".into());

    let networks = ldn::scan(&ScanParam::new(keys.clone())).await?;
    let network = networks.into_iter().next().ok_or("no network found")?;
    println!(
        "Joining {} (game {:016X})",
        network.address, network.local_communication_id
    );

    let mut param = ConnectParam::new(keys, network.clone());
    param.join.password = password.into_bytes();
    param.join.name = name.into_bytes();
    param.join.app_version = network.app_version;

    let mut sta = ldn::connect(param).await?;
    let me = sta.participant();
    println!(
        "Joined as {} ({}), broadcast {}",
        String::from_utf8_lossy(&me.name),
        me.ip_address,
        sta.broadcast_ip()
    );

    let result = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            event = sta.next_event() => match event {
                Ok(Event::Disconnected { reason }) => {
                    println!("Disconnected (reason {reason})");
                    break Ok(());
                }
                Ok(event) => println!("{event:?}"),
                Err(e) => break Err(e),
            },
        }
    };
    sta.close().await?;
    Ok(result?)
}

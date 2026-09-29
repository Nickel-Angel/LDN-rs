//! 需要真实无线网卡的集成测试，默认忽略。
//!
//! ```bash
//! # 只读：查询 nl80211 与 wiphy，普通用户即可（机器上要有加载了 cfg80211 的网卡）
//! cargo test -p ldn-wlan --test hardware -- --ignored list_wiphys
//! # 建删 monitor 接口并收帧，需要 root，且应先停掉 NetworkManager
//! sudo -E env LDN_TEST_PHY=phy0 $(which cargo) test -p ldn-wlan --test hardware -- --ignored monitor
//! ```

use std::time::Duration;

use ldn_wlan::Factory;

#[tokio::test]
#[ignore = "needs a wireless card (cfg80211)"]
async fn list_wiphys() {
    let factory = Factory::new().await.expect("nl80211 not available");
    let wiphys = factory.wiphys().await.unwrap();
    println!("{wiphys:?}");
    assert!(!wiphys.is_empty());
}

#[tokio::test]
#[ignore = "needs root and a monitor-capable card; set LDN_TEST_PHY"]
async fn monitor_receives_frames_on_channel_6() {
    let phy = std::env::var("LDN_TEST_PHY").unwrap_or_else(|_| "phy0".into());
    let factory = Factory::new().await.unwrap();
    let monitor = factory.create_monitor(&phy, "ldn-test-mon").await.unwrap();
    monitor.set_channel(6).await.unwrap();
    // 2.4GHz 信道 6 上几乎总有 Beacon；5 秒内收到任意一帧即可。
    let frame = tokio::time::timeout(Duration::from_secs(5), monitor.recv()).await;
    monitor.close().await.unwrap();
    assert!(frame.expect("no frame within 5s").is_ok());
}

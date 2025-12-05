use bloody_falcon::config::{AppConfig, ProviderConfig};
use bloody_falcon::core::engine::Engine;
use httpmock::prelude::*;

#[tokio::test]
async fn engine_hits_mock_provider() {
    let server = MockServer::start();
    let _hit = server.mock(|when, then| {
        when.method(GET).path("/user/tester");
        then.status(200);
    });

    let cfg = AppConfig {
        timeout_ms: 2000,
        max_concurrent_requests: 2,
        cache_ttl_seconds: 10,
        user_agent: "bf-test".to_string(),
        disk_cache_enabled: false,
        disk_cache_path: "data/cache.json".into(),
        providers: vec![ProviderConfig {
            name: "mock".into(),
            enabled: true,
            base_url: format!("{}/user/{{username}}", server.base_url()),
        }],
    };

    let engine = Engine::new(cfg).unwrap();
    let res = engine.scan_username("tester", true).await.unwrap();
    assert_eq!(res.hits, 1);
    assert_eq!(res.platforms, vec!["mock"]);
}

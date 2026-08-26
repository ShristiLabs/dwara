//! Unit tests for `extensions::analytics` (relocated from src).

use dwara_core::extensions::analytics::*;

#[tokio::test]
async fn records_events_in_order() {
    let sink = InMemoryAnalyticsSink::new(8);
    let mut first = Event::request_now();
    first.route = Some("r1".into());
    sink.record(first.clone()).await.unwrap();
    sink.record(Event::request_now()).await.unwrap();
    let events = sink.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], first);
}

#[tokio::test]
async fn full_ring_drops_oldest_and_keeps_capacity() {
    let sink = InMemoryAnalyticsSink::new(2);
    let oldest = tagged("oldest");
    sink.record(oldest.clone()).await.unwrap();
    sink.record(tagged("mid")).await.unwrap();
    sink.record(tagged("newest")).await.unwrap();
    let events = sink.events();
    assert_eq!(events.len(), 2, "size must stay at capacity");
    assert!(
        !events.contains(&oldest),
        "oldest event must be dropped, not the newest"
    );
    assert_eq!(events[0].attributes[0].0, "tag");
    assert_eq!(events[0].attributes[0].1, "mid");
    assert_eq!(events[1].attributes[0].1, "newest");
}

#[tokio::test]
async fn snapshot_reflects_latest_recorded_event() {
    let sink = InMemoryAnalyticsSink::new(8);
    assert!(sink.events().is_empty());
    let latest = tagged("latest");
    sink.record(latest.clone()).await.unwrap();
    assert_eq!(sink.events(), vec![latest]);
}

#[test]
fn request_now_builds_request_event_with_recent_timestamp() {
    let before = now_ms();
    let event = Event::request_now();
    let after = now_ms();
    assert_eq!(event.kind, "request");
    assert!(event.timestamp_ms >= before && event.timestamp_ms <= after);
    assert_eq!(event.route, None);
    assert!(event.attributes.is_empty());
}

fn tagged(tag: &str) -> Event {
    let mut event = Event::request_now();
    event.attributes = vec![("tag".to_owned(), tag.to_owned())];
    event
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

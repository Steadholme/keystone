//! Service-principal identity-only contract: no login or credential surface, atomic lifecycle
//! mutations, and faithful per-principal audit ordering on both storage backends.

use keystone::store::{
    InMemoryStore, PgStore, ServicePrincipalError, ServicePrincipalEventAction, Store,
};
use sqlx::postgres::PgPoolOptions;

const NOW: u64 = 2_000_000_000;
const ACTOR: &str = "operator:test";
const FAULT_ACTOR: &str = "operator:fault";

async fn assert_lifecycle_contract(store: &dyn Store, slug: &str) {
    let principal = store
        .create_service_principal(slug, "Internal system", ACTOR, NOW)
        .await
        .expect("principal creation");
    assert_eq!(principal.slug, slug);
    assert_eq!(principal.subject, format!("service:{slug}"));
    assert!(!principal.disabled);
    assert_eq!(
        store
            .create_service_principal(slug, "Duplicate", ACTOR, NOW + 1)
            .await
            .unwrap_err(),
        ServicePrincipalError::AlreadyExists
    );
    assert!(store
        .set_service_principal_disabled(slug, true, ACTOR, NOW + 2)
        .await
        .expect("disable"));
    assert!(!store
        .set_service_principal_disabled(slug, true, ACTOR, NOW + 3)
        .await
        .expect("idempotent disable"));
    let disabled = store
        .get_service_principal(slug)
        .await
        .expect("disabled lookup")
        .expect("principal exists");
    assert!(disabled.disabled);
    assert_eq!(disabled.updated_at, NOW + 2);
    assert!(store
        .set_service_principal_disabled(slug, false, ACTOR, NOW + 4)
        .await
        .expect("enable"));
    assert!(!store
        .set_service_principal_disabled(slug, false, ACTOR, NOW + 5)
        .await
        .expect("idempotent enable"));

    let events = store
        .list_service_principal_events(slug)
        .await
        .expect("event list");
    assert_eq!(
        events.iter().map(|event| event.action).collect::<Vec<_>>(),
        vec![
            ServicePrincipalEventAction::Created,
            ServicePrincipalEventAction::Disabled,
            ServicePrincipalEventAction::Enabled,
        ]
    );
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(events.iter().all(|event| event.actor == ACTOR));
    assert!(events
        .iter()
        .all(|event| event.subject == format!("service:{slug}")));
}

async fn assert_timestamp_boundary_contract(store: &dyn Store, slug: &str) {
    let max = i64::MAX as u64;
    store
        .create_service_principal(slug, "Timestamp boundary", ACTOR, max)
        .await
        .expect("creation at i64::MAX");
    assert_eq!(
        store
            .set_service_principal_disabled(slug, true, ACTOR, max + 1)
            .await
            .unwrap_err(),
        ServicePrincipalError::Invalid
    );
    assert!(store
        .set_service_principal_disabled(slug, true, ACTOR, max)
        .await
        .expect("disable at i64::MAX"));
    assert_eq!(
        store
            .create_service_principal(&format!("{slug}-overflow"), "Overflow", ACTOR, max + 1,)
            .await
            .unwrap_err(),
        ServicePrincipalError::Invalid
    );
}

async fn assert_sequence_is_independent_of_wall_clock(store: &dyn Store, slug: &str) {
    store
        .create_service_principal(slug, "Sequence target", ACTOR, NOW)
        .await
        .expect("sequence principal creation");
    store
        .set_service_principal_disabled(slug, true, ACTOR, NOW)
        .await
        .expect("same-time disable");
    store
        .set_service_principal_disabled(slug, false, ACTOR, NOW)
        .await
        .expect("same-time enable");
    let events = store
        .list_service_principal_events(slug)
        .await
        .expect("same-time events");
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(
        events.iter().map(|event| event.action).collect::<Vec<_>>(),
        vec![
            ServicePrincipalEventAction::Created,
            ServicePrincipalEventAction::Disabled,
            ServicePrincipalEventAction::Enabled,
        ]
    );
    assert!(events.iter().all(|event| event.occurred_at == NOW));
}

#[tokio::test]
async fn memory_store_service_principal_lifecycle() {
    let store = InMemoryStore::new();
    assert_lifecycle_contract(&store, "system-memory").await;
    assert_timestamp_boundary_contract(&store, "system-memory-boundary").await;
    assert_sequence_is_independent_of_wall_clock(&store, "system-memory-sequence").await;
    assert_eq!(
        store
            .create_service_principal("Invalid:Slug", "Invalid", ACTOR, NOW)
            .await
            .unwrap_err(),
        ServicePrincipalError::Invalid
    );
}

#[cfg(debug_assertions)]
#[tokio::test]
async fn memory_event_failure_rolls_back_each_mutation() {
    let store = InMemoryStore::new();
    store.fail_next_service_principal_event_for_test();
    assert_eq!(
        store
            .create_service_principal("system-fault", "Fault target", ACTOR, NOW)
            .await
            .unwrap_err(),
        ServicePrincipalError::Backend
    );
    assert!(store
        .get_service_principal("system-fault")
        .await
        .expect("principal lookup")
        .is_none());
    store
        .create_service_principal("system-fault", "Fault target", ACTOR, NOW + 1)
        .await
        .expect("principal creation after fault");
    store.fail_next_service_principal_event_for_test();
    assert_eq!(
        store
            .set_service_principal_disabled("system-fault", true, ACTOR, NOW + 2)
            .await
            .unwrap_err(),
        ServicePrincipalError::Backend
    );
    assert!(
        !store
            .get_service_principal("system-fault")
            .await
            .expect("principal lookup")
            .expect("principal")
            .disabled
    );
    assert_eq!(
        store
            .list_service_principal_events("system-fault")
            .await
            .expect("events")
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1],
        "failed mutation appends no event and consumes no sequence"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; run with: cargo test --test service_principal_store postgres_store_parity_and_event_failure_rollback -- --ignored --exact"]
async fn postgres_store_parity_and_event_failure_rollback() {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL is required for this explicitly ignored PostgreSQL test");
    let store = PgStore::connect(&database_url)
        .await
        .expect("connect test PostgreSQL");
    store.migrate().await.expect("service-principal migration");
    store.migrate().await.expect("idempotent migration");
    let inspect = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("connect inspection pool");
    let credential_table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('service_principal_credentials')::text")
            .fetch_one(&inspect)
            .await
            .expect("inspect credential-table absence");
    assert!(
        credential_table.is_none(),
        "identity-only release has no service credential table"
    );

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let slug = format!("system-{suffix}");
    let function = format!("fail_service_principal_event_{suffix}");
    let trigger = format!("fail_service_principal_event_trigger_{suffix}");
    sqlx::query(&format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.principal_slug='{slug}' AND NEW.actor='{FAULT_ACTOR}' THEN \
         RAISE EXCEPTION 'forced_service_principal_event_failure'; END IF; RETURN NEW; END $$"
    ))
    .execute(&inspect)
    .await
    .expect("install scoped event fault function");
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT ON service_principal_events \
         FOR EACH ROW EXECUTE FUNCTION {function}()"
    ))
    .execute(&inspect)
    .await
    .expect("install scoped event fault trigger");
    assert_eq!(
        store
            .create_service_principal(&slug, "PostgreSQL system", FAULT_ACTOR, NOW)
            .await
            .unwrap_err(),
        ServicePrincipalError::Backend
    );
    let principal_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM service_principals WHERE slug=$1)")
            .bind(&slug)
            .fetch_one(&inspect)
            .await
            .expect("inspect rolled-back create");
    assert!(!principal_exists, "event failure rolls back principal row");
    store
        .create_service_principal(&slug, "PostgreSQL system", ACTOR, NOW + 1)
        .await
        .expect("regular create while scoped trigger exists");
    assert_eq!(
        store
            .set_service_principal_disabled(&slug, true, FAULT_ACTOR, NOW + 2)
            .await
            .unwrap_err(),
        ServicePrincipalError::Backend
    );
    assert!(
        !store
            .get_service_principal(&slug)
            .await
            .expect("principal lookup")
            .expect("principal")
            .disabled
    );

    sqlx::query(&format!(
        "DROP TRIGGER {trigger} ON service_principal_events"
    ))
    .execute(&inspect)
    .await
    .expect("remove scoped event fault trigger");
    sqlx::query(&format!("DROP FUNCTION {function}()"))
        .execute(&inspect)
        .await
        .expect("remove scoped event fault function");
    let parity_slug = format!("system-parity-{suffix}");
    assert_lifecycle_contract(&store, &parity_slug).await;
    let boundary_slug = format!("system-boundary-{suffix}");
    assert_timestamp_boundary_contract(&store, &boundary_slug).await;
    let sequence_slug = format!("system-sequence-{suffix}");
    assert_sequence_is_independent_of_wall_clock(&store, &sequence_slug).await;

    for cleanup_slug in [&slug, &parity_slug, &boundary_slug, &sequence_slug] {
        sqlx::query("DELETE FROM service_principal_events WHERE principal_slug=$1")
            .bind(cleanup_slug)
            .execute(&inspect)
            .await
            .expect("clean test events");
        sqlx::query("DELETE FROM service_principals WHERE slug=$1")
            .bind(cleanup_slug)
            .execute(&inspect)
            .await
            .expect("clean test principal");
    }
}

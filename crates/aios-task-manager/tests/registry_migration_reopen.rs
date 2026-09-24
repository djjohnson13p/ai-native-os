//! Shared control-plane schema compatibility across registry migrations.

use aios_registry::{RegistryStore, registry_snapshot_id};
use aios_task_manager::TaskManager;
use rusqlite::Connection;
use serde_json::json;
use std::fs;

#[test]
fn task_manager_reopens_after_additive_registry_migrations() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    drop(TaskManager::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
        ))
        .unwrap();
    connection.execute(
        "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0012_semantic_registry_store','semantic-registry-store-v0.1','2026-09-21T00:00:00Z')",
        [],
    ).unwrap();
    connection
        .execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0013-provider-registry.sql"
        ))
        .unwrap();
    connection.execute(
        "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0013_provider_registry','provider-registry-v0.1','2026-09-21T00:00:00Z')",
        [],
    ).unwrap();
    drop(connection);
    drop(TaskManager::open(&path).unwrap());
}

#[test]
fn historical_validation_keeps_its_snapshot_after_default_switch_and_offline_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("control.db");
    let first_bundle = temp.path().join("first-bundle");
    let second_bundle = temp.path().join("second-bundle");
    fs::create_dir(&first_bundle).unwrap();
    fs::create_dir(&second_bundle).unwrap();
    for (name, contents) in [
        (
            "registry-snapshot.json",
            include_str!("../../../examples/aios-ir/registry-snapshot.json"),
        ),
        (
            "type-contracts.json",
            include_str!("../../../examples/aios-ir/type-contracts.json"),
        ),
        (
            "capability-contracts.json",
            include_str!("../../../examples/aios-ir/capability-contracts.json"),
        ),
    ] {
        fs::write(first_bundle.join(name), contents).unwrap();
    }
    let empty_snapshot_id = registry_snapshot_id("0.1", &[], &[]).unwrap().to_string();
    fs::write(
        second_bundle.join("registry-snapshot.json"),
        serde_json::to_vec(&json!({
            "schema_version": "0.1",
            "snapshot_id": empty_snapshot_id,
            "type_contracts": [],
            "capability_contracts": [],
            "created_at": "2026-09-22T00:00:00Z"
        }))
        .unwrap(),
    )
    .unwrap();

    let mut manager = TaskManager::open(&database).unwrap();
    let first_id = {
        let (first_id, second_id) = {
            let mut store = manager.registry_store_writer().unwrap();
            let first_id = store.admit_bundle(&first_bundle).unwrap();
            let second_id = store.admit_bundle(&second_bundle).unwrap();
            assert_ne!(first_id, second_id);
            store
                .activate_default("user", "u1", None, &first_id)
                .unwrap();
            (first_id, second_id)
        };
        let connection = Connection::open(&database).unwrap();
        connection.execute(
            "INSERT INTO validation_results \
             (validation_result_id,valid,semantic_hash,registry_snapshot_id,validator_id,validator_version,result_json,validated_at) \
             VALUES ('historical-validation',1,?1,?2,'validator:test','0.1','{}','2026-09-22T00:00:00Z')",
            rusqlite::params![
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                first_id
            ],
        ).unwrap();
        manager
            .registry_store_writer()
            .unwrap()
            .activate_default("user", "u1", Some(1), &second_id)
            .unwrap();
        first_id
    };
    drop(manager);

    fs::remove_dir_all(&first_bundle).unwrap();
    fs::remove_dir_all(&second_bundle).unwrap();
    drop(TaskManager::open(&database).unwrap());
    let mut connection = Connection::open(&database).unwrap();
    let retained_id: String = connection.query_row(
        "SELECT registry_snapshot_id FROM validation_results WHERE validation_result_id='historical-validation'",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(retained_id, first_id);
    let store = RegistryStore::initialize(&mut connection).unwrap();
    assert!(
        store
            .open_snapshot(&retained_id)
            .unwrap()
            .resolve_capability("artifact.hash@1")
            .unwrap()
            .is_some()
    );
    assert_ne!(
        store
            .default_snapshot("user", "u1")
            .unwrap()
            .unwrap()
            .snapshot_id,
        retained_id
    );
}

#[test]
fn task_manager_rejects_incomplete_stamped_registry_migration() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    drop(TaskManager::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
        ))
        .unwrap();
    connection.execute(
        "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0012_semantic_registry_store','semantic-registry-store-v0.1','2026-09-21T00:00:00Z')",
        [],
    ).unwrap();
    connection
        .execute_batch("DROP TRIGGER immutable_registry_snapshot_entries_delete")
        .unwrap();
    drop(connection);
    assert!(TaskManager::open(&path).is_err());
}

#[test]
fn task_manager_rejects_incomplete_stamped_provider_migration() {
    for dropped_object in [
        "DROP TRIGGER provider_evidence_immutable_delete",
        "DROP INDEX ix_provider_conformance_latest",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        drop(TaskManager::open(&path).unwrap());
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0013-provider-registry.sql"
            ))
            .unwrap();
        connection.execute(
            "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0013_provider_registry','provider-registry-v0.1','2026-09-21T00:00:00Z')",
            [],
        ).unwrap();
        connection.execute_batch(dropped_object).unwrap();
        drop(connection);
        assert!(TaskManager::open(&path).is_err(), "{dropped_object}");
    }
}

//! Ticket system integration tests.

use plausiden_shield::auth::rbac::Role;
use plausiden_shield::auth::session;
use plausiden_shield::db::Database;
use plausiden_shield::tickets::{self, CreateTicket, UpdateTicket};

async fn setup_db_with_user() -> (Database, i64) {
    let db = Database::open_memory().unwrap();
    let user_id = session::create_user(&db, "testuser", "pw", Role::Admin)
        .await
        .unwrap();
    (db, user_id)
}

#[tokio::test]
async fn create_and_list_tickets() {
    let (db, user_id) = setup_db_with_user().await;

    let id = tickets::create(
        &db,
        user_id,
        &CreateTicket {
            title: "Server is slow".to_string(),
            description: "CPU at 100%".to_string(),
            priority: Some("high".to_string()),
            category: Some("performance".to_string()),
        },
    )
    .await
    .unwrap();
    assert!(id > 0);

    let all = tickets::list(&db, None).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].title, "Server is slow");
    assert_eq!(all[0].priority, "high");
    assert_eq!(all[0].category, "performance");
    assert_eq!(all[0].status, "open");
}

#[tokio::test]
async fn get_single_ticket() {
    let (db, user_id) = setup_db_with_user().await;

    let id = tickets::create(
        &db,
        user_id,
        &CreateTicket {
            title: "Test ticket".to_string(),
            description: "Description".to_string(),
            priority: None,
            category: None,
        },
    )
    .await
    .unwrap();

    let ticket = tickets::get(&db, id).await.unwrap();
    assert!(ticket.is_some());
    let ticket = ticket.unwrap();
    assert_eq!(ticket.title, "Test ticket");
    assert_eq!(ticket.priority, "medium"); // default
    assert_eq!(ticket.category, "general"); // default
}

#[tokio::test]
async fn get_nonexistent_ticket_returns_none() {
    let (db, _) = setup_db_with_user().await;
    let ticket = tickets::get(&db, 999).await.unwrap();
    assert!(ticket.is_none());
}

#[tokio::test]
async fn update_ticket_status() {
    let (db, user_id) = setup_db_with_user().await;

    let id = tickets::create(
        &db,
        user_id,
        &CreateTicket {
            title: "Bug".to_string(),
            description: "Fix it".to_string(),
            priority: None,
            category: None,
        },
    )
    .await
    .unwrap();

    tickets::update(
        &db,
        id,
        &UpdateTicket {
            status: Some("in_progress".to_string()),
            priority: None,
            assigned_to: None,
        },
    )
    .await
    .unwrap();

    let ticket = tickets::get(&db, id).await.unwrap().unwrap();
    assert_eq!(ticket.status, "in_progress");
}

#[tokio::test]
async fn resolve_sets_resolved_at() {
    let (db, user_id) = setup_db_with_user().await;

    let id = tickets::create(
        &db,
        user_id,
        &CreateTicket {
            title: "Issue".to_string(),
            description: "".to_string(),
            priority: None,
            category: None,
        },
    )
    .await
    .unwrap();

    tickets::update(
        &db,
        id,
        &UpdateTicket {
            status: Some("resolved".to_string()),
            priority: None,
            assigned_to: None,
        },
    )
    .await
    .unwrap();

    let ticket = tickets::get(&db, id).await.unwrap().unwrap();
    assert!(ticket.resolved_at.is_some());
}

#[tokio::test]
async fn add_and_get_comments() {
    let (db, user_id) = setup_db_with_user().await;

    let ticket_id = tickets::create(
        &db,
        user_id,
        &CreateTicket {
            title: "Ticket".to_string(),
            description: "".to_string(),
            priority: None,
            category: None,
        },
    )
    .await
    .unwrap();

    tickets::add_comment(&db, ticket_id, user_id, "First comment")
        .await
        .unwrap();
    tickets::add_comment(&db, ticket_id, user_id, "Second comment")
        .await
        .unwrap();

    let comments = tickets::get_comments(&db, ticket_id).await.unwrap();
    assert_eq!(comments.len(), 2);
    assert_eq!(comments[0].body, "First comment");
    assert_eq!(comments[1].body, "Second comment");
}

#[tokio::test]
async fn list_with_status_filter() {
    let (db, user_id) = setup_db_with_user().await;

    tickets::create(
        &db,
        user_id,
        &CreateTicket {
            title: "Open one".to_string(),
            description: "".to_string(),
            priority: None,
            category: None,
        },
    )
    .await
    .unwrap();

    let id2 = tickets::create(
        &db,
        user_id,
        &CreateTicket {
            title: "Will close".to_string(),
            description: "".to_string(),
            priority: None,
            category: None,
        },
    )
    .await
    .unwrap();

    tickets::update(
        &db,
        id2,
        &UpdateTicket {
            status: Some("closed".to_string()),
            priority: None,
            assigned_to: None,
        },
    )
    .await
    .unwrap();

    let open = tickets::list(&db, Some("open")).await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].title, "Open one");

    let closed = tickets::list(&db, Some("closed")).await.unwrap();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].title, "Will close");
}

#[tokio::test]
async fn update_priority_and_assignment() {
    let (db, user_id) = setup_db_with_user().await;

    let id = tickets::create(
        &db,
        user_id,
        &CreateTicket {
            title: "Task".to_string(),
            description: "".to_string(),
            priority: None,
            category: None,
        },
    )
    .await
    .unwrap();

    tickets::update(
        &db,
        id,
        &UpdateTicket {
            status: None,
            priority: Some("critical".to_string()),
            assigned_to: Some(user_id),
        },
    )
    .await
    .unwrap();

    let ticket = tickets::get(&db, id).await.unwrap().unwrap();
    assert_eq!(ticket.priority, "critical");
    assert_eq!(ticket.assigned_to, Some(user_id));
}

//! Ticketing system — internal issue tracking and knowledge base.
#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use rusqlite::OptionalExtension;

use crate::db::Database;

#[derive(Debug, Clone, Serialize)]
pub struct Ticket {
    pub id: i64,
    pub title: String,
    pub description: String,
    pub status: String,
    pub priority: String,
    pub category: String,
    pub created_by: i64,
    pub assigned_to: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
    pub resolved_at: Option<String>,
    pub closed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTicket {
    pub title: String,
    pub description: String,
    pub priority: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTicket {
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assigned_to: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TicketComment {
    pub id: i64,
    pub ticket_id: i64,
    pub user_id: i64,
    pub body: String,
    pub created_at: String,
}

/// Create a new ticket.
pub async fn create(db: &Database, user_id: i64, req: &CreateTicket) -> Result<i64> {
    let title = req.title.clone();
    let desc = req.description.clone();
    let priority = req.priority.clone().unwrap_or_else(|| "medium".to_string());
    let category = req
        .category
        .clone()
        .unwrap_or_else(|| "general".to_string());

    db.call(move |conn| {
        conn.execute(
            "INSERT INTO tickets (title, description, priority, category, created_by) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![title, desc, priority, category, user_id],
        )
        .context("Failed to create ticket")?;
        Ok(conn.last_insert_rowid())
    })
    .await
}

/// List tickets with optional status filter.
pub async fn list(db: &Database, status_filter: Option<&str>) -> Result<Vec<Ticket>> {
    let filter = status_filter.map(|s| s.to_string());

    db.call(move |conn| {
        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match &filter {
            Some(s) => (
                "SELECT id, title, description, status, priority, category, \
                 created_by, assigned_to, created_at, updated_at, resolved_at, closed_at \
                 FROM tickets WHERE status = ?1 ORDER BY created_at DESC",
                vec![Box::new(s.clone())],
            ),
            None => (
                "SELECT id, title, description, status, priority, category, \
                 created_by, assigned_to, created_at, updated_at, resolved_at, closed_at \
                 FROM tickets ORDER BY created_at DESC",
                vec![],
            ),
        };

        let mut stmt = conn.prepare(sql)?;
        let tickets = stmt
            .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                Ok(Ticket {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    description: row.get(2)?,
                    status: row.get(3)?,
                    priority: row.get(4)?,
                    category: row.get(5)?,
                    created_by: row.get(6)?,
                    assigned_to: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                    resolved_at: row.get(10)?,
                    closed_at: row.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(tickets)
    })
    .await
}

/// Update ticket fields.
pub async fn update(db: &Database, ticket_id: i64, req: &UpdateTicket) -> Result<()> {
    let status = req.status.clone();
    let priority = req.priority.clone();
    let assigned = req.assigned_to;

    db.call(move |conn| {
        if let Some(s) = &status {
            conn.execute(
                "UPDATE tickets SET status = ?1, updated_at = datetime('now') WHERE id = ?2",
                rusqlite::params![s, ticket_id],
            )?;

            // Set timestamps for status transitions.
            if s == "resolved" {
                conn.execute(
                    "UPDATE tickets SET resolved_at = datetime('now') WHERE id = ?1",
                    rusqlite::params![ticket_id],
                )?;
            } else if s == "closed" {
                conn.execute(
                    "UPDATE tickets SET closed_at = datetime('now') WHERE id = ?1",
                    rusqlite::params![ticket_id],
                )?;
            }
        }
        if let Some(p) = &priority {
            conn.execute(
                "UPDATE tickets SET priority = ?1, updated_at = datetime('now') WHERE id = ?2",
                rusqlite::params![p, ticket_id],
            )?;
        }
        if let Some(a) = assigned {
            conn.execute(
                "UPDATE tickets SET assigned_to = ?1, updated_at = datetime('now') WHERE id = ?2",
                rusqlite::params![a, ticket_id],
            )?;
        }
        Ok(())
    })
    .await
}

/// Get a single ticket by ID.
pub async fn get(db: &Database, ticket_id: i64) -> Result<Option<Ticket>> {
    db.call(move |conn| {
        let ticket = conn
            .query_row(
                "SELECT id, title, description, status, priority, category, \
                 created_by, assigned_to, created_at, updated_at, resolved_at, closed_at \
                 FROM tickets WHERE id = ?1",
                rusqlite::params![ticket_id],
                |row| {
                    Ok(Ticket {
                        id: row.get(0)?,
                        title: row.get(1)?,
                        description: row.get(2)?,
                        status: row.get(3)?,
                        priority: row.get(4)?,
                        category: row.get(5)?,
                        created_by: row.get(6)?,
                        assigned_to: row.get(7)?,
                        created_at: row.get(8)?,
                        updated_at: row.get(9)?,
                        resolved_at: row.get(10)?,
                        closed_at: row.get(11)?,
                    })
                },
            )
            .optional()
            .context("Ticket lookup failed")?;
        Ok(ticket)
    })
    .await
}

/// Get comments for a ticket.
pub async fn get_comments(db: &Database, ticket_id: i64) -> Result<Vec<TicketComment>> {
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, ticket_id, user_id, body, created_at \
             FROM ticket_comments WHERE ticket_id = ?1 ORDER BY created_at ASC",
        )?;
        let comments = stmt
            .query_map(rusqlite::params![ticket_id], |row| {
                Ok(TicketComment {
                    id: row.get(0)?,
                    ticket_id: row.get(1)?,
                    user_id: row.get(2)?,
                    body: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(comments)
    })
    .await
}

/// Add a comment to a ticket.
pub async fn add_comment(db: &Database, ticket_id: i64, user_id: i64, body: &str) -> Result<i64> {
    let body = body.to_string();
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO ticket_comments (ticket_id, user_id, body) VALUES (?1, ?2, ?3)",
            rusqlite::params![ticket_id, user_id, body],
        )?;
        Ok(conn.last_insert_rowid())
    })
    .await
}

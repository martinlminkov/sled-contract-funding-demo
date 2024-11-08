use chrono::{Duration, NaiveDateTime};
use serde::{Deserialize, Serialize};
use serde_json;
use sled::{Db, IVec};
use std::collections::HashMap;
use std::error::Error;

// Define the data schema as Rust structs
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Request {
    request_id: String,
    user_id: String,
    address: String,
    description: String,
    network: String,
    amount: f64,
    status: String,            // Pending, Cancelled, Completed
    created_at: u64,           // Unix timestamp
    processed_at: Option<u64>, // Unix timestamp or None
    transaction_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct User {
    user_id: String,
    slack_id: String,
    addresses: Vec<String>,
    created_at: u64,
    updated_at: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct AddressEntry {
    address: String,
    network: String,
    associated_users: Vec<String>,
    last_funded_at: u64,
    created_at: u64,
    updated_at: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct Reclaim {
    reclaim_id: String,
    address: String,
    network: String,
    associated_users: Vec<String>,
    status: String, // Pending, Completed
    initiated_at: u64,
    updated_at: u64,
    completed_at: Option<u64>,
}

// Helper function to get current Unix timestamp
fn current_timestamp() -> u64 {
    chrono::Utc::now().timestamp() as u64
}

fn main() -> Result<(), Box<dyn Error>> {
    // Open or create a sled database
    let db: Db = sled::open("my_db")?;

    // For demo purposes, we'll insert some sample data
    insert_sample_data(&db)?;

    // Perform analytics operations
    // 1. Retrieve funding statistics over a period
    funding_statistics(&db, 30)?;

    // 2. Detect anomalies
    detect_anomalies(&db)?;

    // 3. Retrieve funding request history for a specific user
    user_funding_history(&db, "user_1")?;

    // 4. List users with the most funding requests
    top_requesters(&db, 3)?;

    // Close the database
    db.flush()?;

    Ok(())
}

fn insert_sample_data(db: &Db) -> Result<(), Box<dyn Error>> {
    // Sample users
    let users = vec![
        User {
            user_id: "user_1".to_string(),
            slack_id: "U123456".to_string(),
            addresses: vec!["0xABCDEF...".to_string()],
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
        },
        User {
            user_id: "user_2".to_string(),
            slack_id: "U789012".to_string(),
            addresses: vec!["0xABCDEF...".to_string()], // Shared address
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
        },
        User {
            user_id: "user_3".to_string(),
            slack_id: "U345678".to_string(),
            addresses: vec!["0x123456...".to_string()],
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
        },
    ];

    // Insert users into the database
    for user in users {
        let serialized_user = serde_json::to_vec(&user)?;
        let user_key = format!("user:{}", user.user_id);
        db.insert(user_key.as_bytes(), serialized_user)?;
    }

    // Sample requests
    let requests = vec![
        Request {
            request_id: "req_1".to_string(),
            user_id: "user_1".to_string(),
            address: "0xABCDEF...".to_string(),
            description: "Deploying contract".to_string(),
            network: "Ethereum".to_string(),
            amount: 2.0,
            status: "Completed".to_string(),
            created_at: current_timestamp() - 86400 * 10, // 10 days ago
            processed_at: Some(current_timestamp() - 86400 * 9),
            transaction_hash: Some("0xHash1".to_string()),
        },
        Request {
            request_id: "req_2".to_string(),
            user_id: "user_2".to_string(),
            address: "0xABCDEF...".to_string(), // Shared address
            description: "Testing contract".to_string(),
            network: "Ethereum".to_string(),
            amount: 1.5,
            status: "Completed".to_string(),
            created_at: current_timestamp() - 86400 * 8, // 8 days ago
            processed_at: Some(current_timestamp() - 86400 * 7),
            transaction_hash: Some("0xHash2".to_string()),
        },
        Request {
            request_id: "req_3".to_string(),
            user_id: "user_3".to_string(),
            address: "0x123456...".to_string(),
            description: "Security audit".to_string(),
            network: "Ethereum".to_string(),
            amount: 0.5,
            status: "Completed".to_string(),
            created_at: current_timestamp() - 86400 * 5, // 5 days ago
            processed_at: Some(current_timestamp() - 86400 * 4),
            transaction_hash: Some("0xHash3".to_string()),
        },
        Request {
            request_id: "req_4".to_string(),
            user_id: "user_1".to_string(),
            address: "0xABCDEF...".to_string(),
            description: "Large funding".to_string(),
            network: "Ethereum".to_string(),
            amount: 200.0, // Large amount
            status: "Completed".to_string(),
            created_at: current_timestamp() - 86400 * 1, // 1 day ago
            processed_at: Some(current_timestamp()),
            transaction_hash: Some("0xHash4".to_string()),
        },
    ];

    // Insert requests into the database
    for request in requests {
        let serialized_request = serde_json::to_vec(&request)?;
        let request_key = format!("request:{}", request.request_id);
        db.insert(request_key.as_bytes(), serialized_request)?;
    }

    Ok(())
}

fn funding_statistics(db: &Db, days: i64) -> Result<(), Box<dyn Error>> {
    println!("--- Funding Statistics (Last {} Days) ---", days);

    let prefix = b"request:";
    let iter = db.scan_prefix(prefix);

    let mut total_requests = 0;
    let mut total_amount = 0.0;
    let mut network_stats: HashMap<String, (usize, f64)> = HashMap::new();

    let since_timestamp = chrono::Utc::now()
        .checked_sub_signed(Duration::days(days))
        .unwrap()
        .timestamp() as u64;

    for item in iter {
        let (_, value) = item?;
        let request: Request = serde_json::from_slice(&value)?;

        if request.created_at >= since_timestamp {
            total_requests += 1;
            total_amount += request.amount;

            let entry = network_stats
                .entry(request.network.clone())
                .or_insert((0, 0.0));
            entry.0 += 1; // Increment request count
            entry.1 += request.amount; // Add amount
        }
    }

    for (network, (count, amount)) in &network_stats {
        let average = if *count > 0 {
            amount / *count as f64
        } else {
            0.0
        };
        println!(
            "Network: {}\n- Total Requests: {}\n- Total Amount: {:.2}\n- Average Amount: {:.2}\n",
            network, count, amount, average
        );
    }

    println!(
        "Overall Totals:\n- Total Requests: {}\n- Total Amount: {:.2}\n",
        total_requests, total_amount
    );

    Ok(())
}

fn detect_anomalies(db: &Db) -> Result<(), Box<dyn Error>> {
    println!("--- Anomaly Detection Results ---");

    // Detect shared addresses
    let prefix = b"request:";
    let iter = db.scan_prefix(prefix);

    let mut address_users: HashMap<String, Vec<String>> = HashMap::new();
    let mut large_requests: Vec<(String, String, f64)> = Vec::new();

    for item in iter {
        let (_, value) = item?;
        let request: Request = serde_json::from_slice(&value)?;

        // Collect users per address
        let users = address_users
            .entry(request.address.clone())
            .or_insert(Vec::new());
        if !users.contains(&request.user_id) {
            users.push(request.user_id.clone());
        }

        // Detect large requests (e.g., amount > threshold)
        if request.amount >= 100.0 {
            large_requests.push((
                request.user_id.clone(),
                request.network.clone(),
                request.amount,
            ));
        }
    }

    // Shared Addresses
    println!("- Shared Addresses:");
    for (address, users) in &address_users {
        if users.len() > 1 {
            println!(
                "  - Address: {} used by {:?}",
                address,
                users.iter().map(|u| format!("@{}", u)).collect::<Vec<_>>()
            );
        }
    }

    // Large Requests
    println!("\n- Large Requests:");
    for (user_id, network, amount) in &large_requests {
        println!(
            "  - @{} requested {:.2} on network {}",
            user_id, amount, network
        );
    }

    Ok(())
}

fn user_funding_history(db: &Db, user_id: &str) -> Result<(), Box<dyn Error>> {
    println!("--- Funding History for @{} ---", user_id);

    let prefix = b"request:";
    let iter = db.scan_prefix(prefix);

    let mut requests: Vec<Request> = Vec::new();
    let mut addresses: Vec<String> = Vec::new();

    for item in iter {
        let (_, value) = item?;
        let request: Request = serde_json::from_slice(&value)?;

        if request.user_id == user_id {
            requests.push(request.clone());
            if !addresses.contains(&request.address) {
                addresses.push(request.address.clone());
            }
        }
    }

    println!("- Total Requests: {}", requests.len());
    if let Some(last_request) = requests.iter().max_by_key(|r| r.created_at) {
        let datetime = NaiveDateTime::from_timestamp(last_request.created_at as i64, 0).to_string();
        println!(
            "- Last Request: {:.2} {} on {}",
            last_request.amount, last_request.network, datetime
        );
    }

    println!("- Addresses Used:");
    for address in addresses {
        println!("  - {}", address);
    }

    Ok(())
}

fn top_requesters(db: &Db, limit: usize) -> Result<(), Box<dyn Error>> {
    println!("--- Top {} Requesters ---", limit);

    let prefix = b"request:";
    let iter = db.scan_prefix(prefix);

    let mut user_request_counts: HashMap<String, usize> = HashMap::new();

    for item in iter {
        let (_, value) = item?;
        let request: Request = serde_json::from_slice(&value)?;

        *user_request_counts
            .entry(request.user_id.clone())
            .or_insert(0) += 1;
    }

    // Sort users by request count
    let mut sorted_users: Vec<(String, usize)> = user_request_counts.into_iter().collect();

    sorted_users.sort_by(|a, b| b.1.cmp(&a.1));

    for (i, (user_id, count)) in sorted_users.iter().take(limit).enumerate() {
        println!("{}. @{} - {} requests", i + 1, user_id, count);
    }

    Ok(())
}

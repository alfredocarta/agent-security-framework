use chrono::Utc;
use uuid::Uuid;

pub fn new_session_id() -> String {
    let now = Utc::now();
    let hex = &Uuid::new_v4().simple().to_string()[..6];
    format!("{}{}", now.format("%Y%m%d_%H%M%S_"), hex)
}

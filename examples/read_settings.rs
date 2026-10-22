use rusqlite::Connection;

fn main() {
    let conn = Connection::open(r"C:\Users\Dan\AppData\Roaming\TS3Client\settings.db").unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .unwrap();
    let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
    for row in rows {
        println!("Table: {}", row.unwrap());
    }
}

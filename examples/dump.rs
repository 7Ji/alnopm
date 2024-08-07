use alnopm::{self, Db, Dbs};

fn main() {
    let args = std::env::args();
    let mut has_db = false;
    for db_name in args.skip(1) {
        let db = match Db::try_from_path(&db_name) {
            Ok(db) => db,
            Err(e) => {
                print!("Failed to parse DB, error: {}", e);
                panic!()
            },
        };
        println!("DB {}: {:?}", db_name, db);
        has_db = true;
    }
    if ! has_db {
        for db in Dbs::try_from_path("/var/lib/pacman/sync").expect("Failed to read all DBs").map {
            println!("DB {}: {:?}", db.0, db.1)
        }
    }
}
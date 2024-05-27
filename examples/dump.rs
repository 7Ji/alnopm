use alnopm::{self, Db, Dbs};

fn main() {
    let args = std::env::args();
    let mut has_db = false;
    for db_name in args.skip(1) {
        let db = Db::try_from_path(&db_name).expect("Failed to read DB");
        println!("DB {}: {:?}", db_name, db);
        has_db = true;
    }
    if ! has_db {
        for db in Dbs::try_from_path("/var/lib/pacman/sync").expect("Failed to read all DBs").dbs {
            println!("DB {}: {:?}", db.0, db.1)
        }
    }
}
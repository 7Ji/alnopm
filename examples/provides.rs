fn main() {
    let want = std::env::args().nth(1).expect("No package name given");
    for (db_name, db) in alnopm::Dbs::try_from_path("/var/lib/pacman/sync").expect("Failed to read all DBs").dbs.iter() {
        for pkg in db.packages.iter() {
            for provide in pkg.provides.iter() {
                if provide.name == want {
                    println!("{}/{}", db_name, pkg.name);
                }
            }
        }
    }
}
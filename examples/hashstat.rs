fn main() {
    let dbs = alnopm::Dbs::try_from_path("/var/lib/pacman/sync").expect("Failed to read all DBs");
    for (db_name , db) in dbs.map.iter() {
        let mut pgp = 0;
        let mut md5 = 0;
        for pkg in db.packages.iter() {
            if pkg.md5sum.is_some() {
                md5 += 1
            }
            if ! pkg.pgpsig.is_empty() {
                pgp += 1
            }
        }
        let total = db.packages.len();
        println!("{}: pgp {} / {}, md5sum {} / {}",
            db_name,
            pgp, total,
            md5, total
        )
    }
}
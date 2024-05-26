# Arch Linux NO Pacman Manager

Parsing Arch Linux repo DB files, without alpm dependency.

By not linking with libalpm, alnopm could parse Arch repo DBs on any platform, any distro. And alnopm needs not to be updated along with libalpm.

The reason I wrote this is that I want a library that only parses Arch repo DBs and do not bring a whole libalpm dependency chain.
# Arch Linux NO Pacman Manager

Parsing Arch Linux repo DB files, without alpm dependency.

By not linking with libalpm, alnopm could parse Arch repo DBs on any platform, any distro. And alnopm needs not to be updated along with libalpm.

The reason I wrote this is that I want a library that only parses Arch repo DBs and do not bring a whole libalpm dependency chain.

## License
**git-mirrorer**, to mirror, archive and checkout git repos even across submodules

Copyright (C) 2024-present Guoxin "7Ji" Pu

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
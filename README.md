# PathOfBuilding-Updater
Updater for Path of Building

## Background:
See [this issue comment](
https://github.com/Openarl/PathOfBuilding/issues/28#issuecomment-317166126
)

**Update.exe:** This is used by the update system to update the runtime binaries.
It runs with administrator privileges to comply with Windows' UAC; that shouldn't be
required on other OSes. It contains a Lua interpreter which runs the script passed as
the first argument. In practice, the only script it will run is `UpdateApply.lua`.
To allow the LuaJIT binary to be updated, it uses a standard Lua interpreter (not the
JIT) which is embedded in the executable. The script's environment consists of the
standard Lua libraries, plus an extra API function `SpawnProcess` that starts the given
process and returns without waiting for the process to finish. It also lowers the
execution level so that the new process doesn't run with administrator privileges.
`UpdateApply.lua` uses this to restart the main application after the runtime files have
been updated.

## Licence
[MIT](https://opensource.org/licenses/mit-license.php)

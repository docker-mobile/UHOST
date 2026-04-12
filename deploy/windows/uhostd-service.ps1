$Binary = "C:\Program Files\Project-UHost\uhostd.exe"
$Args = "--config C:\ProgramData\Project-UHost\all-in-one.toml"
New-Service -Name "ProjectUHost" -BinaryPathName "$Binary $Args" -DisplayName "Project UHost" -StartupType Automatic

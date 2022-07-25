Start-Sleep -s 60

# Default Browser
if (test-path "$($env:LOCALAPPDATA)\Google\Chrome"){
    $browser = "firefox"
    $link = "https://kolbi.cz/SetDefaultBrowser.zip"
    cd $($env:TMP);$file = $($env:TMP)+"\"+(Split-Path $link -Leaf)
    (New-Object net.webclient).Downloadfile("$link", "$file"); Expand-Archive -path "SetDefaultBrowser.zip" -DestinationPath (split-path $file -parent) -Force
    $file = Join-path -path (split-path $file -Parent) -ChildPath "SetDefaultBrowser"; cd $file
    .\SetDefaultBrowser.exe $browser}

# Default pdf
$link = "https://raw.githubusercontent.com/DanysysTeam/PS-SFTA/master/SFTA.ps1"
$file = "C:\ProgramData\SFTA.ps1"
(New-Object net.webclient).Downloadfile("$link", "$file")
set-location "C:\ProgramData\";
powershell -ExecutionPolicy Bypass -command "& { . .\SFTA.ps1; Set-FTA 'AcroExch.Document.DC' '.pdf' }"

# Default video player


cmd /c assoc 

$exts=@(
"264",
"3ga",
"3gp",
"aac",
"avi",
"cda",
"dash",
"dvr",
"flac",
"ifo",
"m2t",
"m2ts",
"m3u8",
"m4v",
"mkv",
"mov",
"mp3",
"mp4",
"mpg",
"mts",
"ogg",
"ogv",
"opus",
"pls",
"rec",
"rmvb",
"snd",
"sub",
"ts",
"vob",
"webm",
"wma",
"wmv",
"zab")
foreach ($ext in $exts){
	$extfile=$ext+"file"
	$dotext="."+$ext
    cmd /c assoc $dotext=
	cmd /c assoc $dotext=$extfile
    cmd /c ftype $extfile=
	cmd /c "ftype $extfile=""C:\Program Files\VideoLAN\VLC\vlc.exe"" ""%1"""
}



# notepad++
$exts=@(
	"csv",
	"csproj",
	"json",
	"log",
	"md",
	"patch",
	"sql",
	"txt",
	"xml")
foreach ($ext in $exts){
	$extfile=$ext+"file".Replace(".","")
	$dotext="." + $ext
	cmd /c assoc $dotext=$extfile
    cmd /c "ftype $extfile=""C:\Program Files\Notepad++\notepad++.exe"" ""%1"""}



    


# https://github.com/notepad-plus-plus/notepad-plus-plus/issues/4981#issuecomment-483455692
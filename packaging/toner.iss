; Inno Setup script for Toner. Build the program folder first (packaging\build.ps1 does both steps).
#define AppName "Toner"
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{6E1B7C52-3D0A-4B7E-9C58-7A2F4E8D1B30}
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\Toner.exe
SetupIconFile=..\assets\toner.ico
OutputDir=..\build\installer
OutputBaseFilename=Toner-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Installs for the current user with no administrator prompt; the installer offers "all users" as a choice.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "startup"; Description: "Start Toner when I sign in to Windows (waits in the tray if background running is turned on)"; GroupDescription: "Options:"; Flags: unchecked

[Files]
Source: "..\build\dist\Toner\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\devices.example.*"; DestDir: "{app}\examples"; Flags: ignoreversion

[Icons]
Name: "{group}\Toner"; Filename: "{app}\Toner.exe"
Name: "{group}\Uninstall Toner"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Toner"; Filename: "{app}\Toner.exe"; Tasks: desktopicon
Name: "{userstartup}\Toner"; Filename: "{app}\Toner.exe"; Parameters: "--minimized"; Tasks: startup

[Run]
Filename: "{app}\Toner.exe"; Description: "Start Toner"; Flags: nowait postinstall skipifsilent
; An update that Toner started itself runs silently with /relaunch=1 and opens Toner again when it is done.
Filename: "{app}\Toner.exe"; Flags: nowait; Check: Relaunch

; Uninstalling removes the program only. The database, history, logs and saved passwords stay (in %APPDATA%\NetCheck and
; Windows Credential Manager), so a reinstall or upgrade picks up where it left off.

[Code]
function Relaunch: Boolean;
begin
  Result := ExpandConstant('{param:relaunch|0}') = '1';
end;

; Inno Setup script for Toner. Build the program folder first (packaging\build.ps1 does both steps).
;
; Two ways to set it up, chosen on the first page:
;   Install   Start Menu and desktop shortcuts, an entry in Installed apps, an uninstaller. Data lives in %APPDATA%\NetCheck.
;   Portable  Copies the program into a folder you choose and nothing else: no shortcuts, no registry entries, no uninstaller.
;             A marker file (portable.flag) makes Toner keep its data in a "data" folder beside the program, so the folder
;             can be carried on a USB drive. Silent runs choose with /MODE=portable (the in-app updater does).
#define AppName "Toner"
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{6E1B7C52-3D0A-4B7E-9C58-7A2F4E8D1B30}
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={code:DefaultDir}
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
; A portable copy leaves no trace on the computer.
Uninstallable=not IsPortable
CreateUninstallRegKey=not IsPortable
UsePreviousAppDir=not IsPortable

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Check: not IsPortable
Name: "startup"; Description: "Start Toner when I sign in to Windows (waits in the tray if background running is turned on)"; GroupDescription: "Options:"; Flags: unchecked; Check: not IsPortable

[Files]
Source: "..\build\dist\Toner\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\devices.example.*"; DestDir: "{app}\examples"; Flags: ignoreversion
Source: "portable.flag"; DestDir: "{app}"; Flags: ignoreversion; Check: IsPortable

[Icons]
Name: "{group}\Toner"; Filename: "{app}\Toner.exe"; Check: not IsPortable
Name: "{group}\Uninstall Toner"; Filename: "{uninstallexe}"; Check: not IsPortable
Name: "{autodesktop}\Toner"; Filename: "{app}\Toner.exe"; Tasks: desktopicon; Check: not IsPortable
Name: "{userstartup}\Toner"; Filename: "{app}\Toner.exe"; Parameters: "--minimized"; Tasks: startup; Check: not IsPortable

[Run]
Filename: "{app}\Toner.exe"; Description: "Start Toner"; Flags: nowait postinstall skipifsilent
; An update that Toner started itself runs silently with /relaunch=1 and opens Toner again when it is done.
Filename: "{app}\Toner.exe"; Flags: nowait; Check: Relaunch

; Uninstalling an installed copy removes the program only. The database, history, logs and saved passwords stay (in
; %APPDATA%\NetCheck and Windows Credential Manager), so a reinstall or upgrade picks up where it left off.
; A portable copy has no uninstaller: delete its folder, and its data folder goes with it.

[Code]
var
  ModePage: TWizardPage;
  InstallRadio, PortableRadio: TNewRadioButton;

function WantsPortable: Boolean;
begin
  Result := SameText(ExpandConstant('{param:mode|install}'), 'portable');
end;

function IsPortable: Boolean;
begin
  if PortableRadio = nil then
    Result := WantsPortable
  else
    Result := PortableRadio.Checked;
end;

function Relaunch: Boolean;
begin
  Result := ExpandConstant('{param:relaunch|0}') = '1';
end;

function DefaultDir(Param: String): String;
begin
  if IsPortable then
    Result := ExpandConstant('{userdocs}\Toner Portable')
  else
    Result := ExpandConstant('{autopf}\Toner');
end;

{ one choice: a radio button with a wrapped explanation under it }
function AddChoice(Page: TWizardPage; Top: Integer; Title, Explanation: String; Checked: Boolean): TNewRadioButton;
var
  Text: TNewStaticText;
begin
  Result := TNewRadioButton.Create(Page);
  Result.Parent := Page.Surface;
  Result.Left := 0;
  Result.Top := Top;
  Result.Width := Page.SurfaceWidth;
  Result.Caption := Title;
  Result.Font.Style := [fsBold];
  Result.Checked := Checked;
  Text := TNewStaticText.Create(Page);
  Text.Parent := Page.Surface;
  Text.Left := ScaleX(20);
  Text.Top := Top + ScaleY(22);
  Text.Width := Page.SurfaceWidth - ScaleX(20);
  Text.AutoSize := False;
  Text.WordWrap := True;
  Text.Height := ScaleY(56);
  Text.Caption := Explanation;
end;

procedure InitializeWizard;
begin
  ModePage := CreateCustomPage(wpWelcome, 'How do you want to set up Toner?',
    'Install it on this computer, or make a portable copy.');
  InstallRadio := AddChoice(ModePage, ScaleY(8), 'Install on this computer (recommended)',
    'Adds Start Menu and desktop shortcuts and an entry in Installed apps, can start with Windows, and can be ' +
    'uninstalled. Your data is kept in your user profile.', not WantsPortable);
  PortableRadio := AddChoice(ModePage, ScaleY(100), 'Portable: copy to a folder I choose',
    'Leaves nothing behind on this computer: no shortcuts, no registry entries, no uninstaller. Toner keeps its data in a ' +
    '"data" folder beside it, so the whole folder can go on a USB drive. Saved passwords stay on each computer.',
    WantsPortable);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  { the usual place for the kind chosen, unless a folder was given on the command line (/DIR=, as the updater does) }
  if (ModePage <> nil) and (CurPageID = ModePage.ID) and (ExpandConstant('{param:dir|}') = '') then
    WizardForm.DirEdit.Text := DefaultDir('');
end;
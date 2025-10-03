; ============================================
; Aegis Cloud Security Scanner
; Professional Windows Installer
; ============================================
; Created by: Subash Dananjaya Uduwaka
; Email: aegis.aws.scanner@gmail.com
; License: GPL-3.0
; ============================================

#define MyAppName "Aegis Cloud Security Scanner"
#define MyAppVersion "0.8"
#define MyAppPublisher "Subash Dananjaya Uduwaka"
#define MyAppURL "https://github.com/SubashUduwaka/cloud-security-scanner"
#define MyAppExeName "START_AEGIS.bat"
#define MyAppContact "aegis.aws.scanner@gmail.com"

[Setup]
; ============================================
; Application Information
; ============================================
AppId={{8F4A6D2E-9B3C-4E7A-A8D9-1F5E2C6B9A4D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
AppContact={#MyAppContact}
AppCopyright=Copyright (C) 2025 {#MyAppPublisher}
AppComments=Multi-Cloud Security Scanner for AWS, GCP, and Azure

; ============================================
; Installation Directories
; ============================================
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; User can choose where to install
DisableDirPage=no

; ============================================
; Output Configuration
; ============================================
OutputDir=installer_output
OutputBaseFilename=AegisCloudScanner_Professional_Setup_v{#MyAppVersion}
; If you have custom icons, uncomment these lines:
; SetupIconFile=installer_assets\setup_icon.ico
; UninstallDisplayIcon={app}\installer_assets\aegis_icon.ico

; ============================================
; Compression (Best compression)
; ============================================
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes
LZMANumBlockThreads=2

; ============================================
; Privileges & Security
; ============================================
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog commandline
AllowNoIcons=yes

; ============================================
; UI Configuration
; ============================================
WizardStyle=modern
DisableWelcomePage=no
; If you have custom wizard images, uncomment these:
; WizardImageFile=installer_assets\wizard_large.bmp
; WizardSmallImageFile=installer_assets\wizard_header.bmp
WizardResizable=yes
ShowLanguageDialog=yes

; ============================================
; License & Information
; ============================================
LicenseFile=LICENSE
InfoBeforeFile=INSTALLER_README.md
; InfoAfterFile=CHANGELOG.md

; ============================================
; Version Information
; ============================================
VersionInfoVersion={#MyAppVersion}.0.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup
VersionInfoTextVersion={#MyAppVersion}
VersionInfoCopyright=Copyright (C) 2025 {#MyAppPublisher}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

; ============================================
; Uninstall Configuration
; ============================================
UninstallDisplayName={#MyAppName}
UninstallFilesDir={app}\uninstall

; ============================================
; Miscellaneous
; ============================================
SetupLogging=yes
ChangesAssociations=no
ChangesEnvironment=yes
RestartIfNeededByRun=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full"; Description: "Full installation (Recommended)"
Name: "minimal"; Description: "Minimal installation"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "core"; Description: "Core Application Files"; Types: full minimal custom; Flags: fixed
Name: "docs"; Description: "Documentation (User Manual, Guides)"; Types: full
Name: "docker"; Description: "Docker Configuration Files"; Types: full
Name: "devdocs"; Description: "Developer Documentation"; Types: full

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1; Check: not IsAdminInstallMode

[Files]
; ============================================
; Core Application Files
; ============================================
Source: "app.py"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "config.py"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "wsgi.py"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "chatbot_knowledge.py"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "license_manager.py"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "migrate_user_schema.py"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "requirements.txt"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "START_AEGIS.bat"; DestDir: "{app}"; Flags: ignoreversion; Components: core

; ============================================
; Essential Documentation
; ============================================
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme; Components: core
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion; Components: docs
Source: "WINDOWS_INSTALLATION.md"; DestDir: "{app}"; Flags: ignoreversion; Components: docs
Source: "INSTALLER_README.md"; DestDir: "{app}"; Flags: ignoreversion; Components: docs
Source: "INSTALLER_ASSETS_NEEDED.md"; DestDir: "{app}"; Flags: ignoreversion; Components: docs
Source: "CONTRIBUTING.md"; DestDir: "{app}"; Flags: ignoreversion; Components: docs
Source: "SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion; Components: docs
Source: "CODE_OF_CONDUCT.md"; DestDir: "{app}"; Flags: ignoreversion; Components: docs

; ============================================
; Application Directories
; ============================================
Source: "templates\*"; DestDir: "{app}\templates"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: core
Source: "static\*"; DestDir: "{app}\static"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: core
Source: "scanners\*"; DestDir: "{app}\scanners"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: core
Source: "tools\*"; DestDir: "{app}\tools"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: core
Source: "licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: core
Source: "docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: docs

; ============================================
; Developer Documentation (Optional)
; ============================================
Source: ".github\*"; DestDir: "{app}\.github"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: devdocs

; ============================================
; Docker Files (Optional)
; ============================================
Source: "Dockerfile"; DestDir: "{app}"; Flags: ignoreversion; Components: docker
Source: "docker-compose.yml"; DestDir: "{app}"; Flags: ignoreversion; Components: docker

; ============================================
; GTK3 Runtime (For PDF Generation)
; ============================================
; NOTE: Download GTK3 Runtime from:
; https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
; Extract it and place files in gtk3_runtime folder, then uncomment:
; Source: "gtk3_runtime\*"; DestDir: "{app}\gtk3_runtime"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: core

[Icons]
; ============================================
; Start Menu Icons
; ============================================
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Comment: "Launch {#MyAppName}"; IconIndex: 0
Name: "{group}\User Manual"; Filename: "{app}\docs\USER_MANUAL.md"; Comment: "Open User Manual"
Name: "{group}\Installation Guide"; Filename: "{app}\WINDOWS_INSTALLATION.md"; Comment: "Windows Installation Instructions"
Name: "{group}\GitHub Repository"; Filename: "{#MyAppURL}"; Comment: "Visit GitHub Repository"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"; Comment: "Uninstall {#MyAppName}"

; ============================================
; Desktop Icon (Optional)
; ============================================
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon; Comment: "Launch {#MyAppName}"

; ============================================
; Quick Launch Icon (Optional - Legacy)
; ============================================
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: quicklaunchicon

[Run]
; ============================================
; Post-Installation Actions
; ============================================
; Optionally launch application after installation
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallDelete]
; ============================================
; Clean Up on Uninstall
; ============================================
Type: filesandordirs; Name: "{localappdata}\AegisCloudScanner"
Type: filesandordirs; Name: "{app}\__pycache__"
Type: filesandordirs; Name: "{app}\instance"

[Registry]
; ============================================
; Registry Entries (Optional)
; ============================================
; Add to Windows App Paths for easy command-line access
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\aegis.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName}"; Flags: uninsdeletekey

[Code]
{ ============================================ }
{ Custom Installer Code                      }
{ ============================================ }

var
  PythonInstallPage: TOutputMsgMemoWizardPage;
  PythonDetected: Boolean;
  PythonVersion: String;
  GTK3InstallPage: TOutputProgressWizardPage;

{* Check if Python is installed *}
function IsPythonInstalled(): Boolean;
var
  ResultCode: Integer;
  PythonOutput: AnsiString;
begin
  Result := Exec('python', '--version', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if Result and (ResultCode = 0) then
  begin
    // Python is installed
    PythonDetected := True;
  end
  else
  begin
    PythonDetected := False;
  end;
end;

{* Get Python version *}
function GetPythonVersion(): String;
var
  ResultCode: Integer;
  TempFile: String;
  Lines: TArrayOfString;
begin
  Result := 'Unknown';
  TempFile := ExpandConstant('{tmp}\python_version.txt');

  if Exec('cmd.exe', '/c python --version > "' + TempFile + '" 2>&1', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if LoadStringsFromFile(TempFile, Lines) then
    begin
      if GetArrayLength(Lines) > 0 then
        Result := Lines[0];
    end;
    DeleteFile(TempFile);
  end;
end;

{* Initialize Setup *}
function InitializeSetup(): Boolean;
begin
  Result := True;

  // Check Python installation
  if not IsPythonInstalled() then
  begin
    if MsgBox('Python is not detected on your system.' + #13#10#13#10 +
              '{#MyAppName} requires Python 3.8 or higher to function.' + #13#10#13#10 +
              'Would you like to:' + #13#10 +
              '  • Download Python now (Recommended)' + #13#10 +
              '  • Continue installation anyway (You will need to install Python manually)',
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      // Open Python download page
      ShellExec('open', 'https://www.python.org/downloads/', '', '', SW_SHOW, ewNoWait, ResultCode);
      MsgBox('After installing Python:' + #13#10 +
             '  1. Make sure to check "Add Python to PATH"' + #13#10 +
             '  2. Restart this installer' + #13#10#13#10 +
             'Installation will now exit.', mbInformation, MB_OK);
      Result := False;
      Exit;
    end;
  end
  else
  begin
    PythonVersion := GetPythonVersion();
  end;
end;

{* Initialize Wizard *}
procedure InitializeWizard();
begin
  // Create Python status page
  PythonInstallPage := CreateOutputMsgMemoPage(wpWelcome,
    'Python Detection', 'Checking Python installation on your system',
    'Setup has detected the following Python installation:' + #13#10 +
    'This will be used to run {#MyAppName}.',
    '');

  if PythonDetected then
  begin
    PythonInstallPage.RichEditViewer.Lines.Add('✓ Python Detected: ' + PythonVersion);
    PythonInstallPage.RichEditViewer.Lines.Add('✓ Installation can proceed normally');
    PythonInstallPage.RichEditViewer.Lines.Add('');
    PythonInstallPage.RichEditViewer.Lines.Add('After installation:');
    PythonInstallPage.RichEditViewer.Lines.Add('  • Launch Aegis from Desktop or Start Menu');
    PythonInstallPage.RichEditViewer.Lines.Add('  • First run will install Python dependencies (5-10 min)');
    PythonInstallPage.RichEditViewer.Lines.Add('  • Access the application at http://localhost:5000');
  end
  else
  begin
    PythonInstallPage.RichEditViewer.Lines.Add('⚠ Python Not Detected');
    PythonInstallPage.RichEditViewer.Lines.Add('');
    PythonInstallPage.RichEditViewer.Lines.Add('You will need to:');
    PythonInstallPage.RichEditViewer.Lines.Add('  1. Install Python 3.8+ from python.org');
    PythonInstallPage.RichEditViewer.Lines.Add('  2. Check "Add Python to PATH" during installation');
    PythonInstallPage.RichEditViewer.Lines.Add('  3. Run Aegis after Python is installed');
  end;
end;

{* Post-Installation Setup *}
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    // Show success message
    if PythonDetected then
    begin
      MsgBox('{#MyAppName} has been installed successfully!' + #13#10#13#10 +
             'Python Detected: ' + PythonVersion + #13#10#13#10 +
             'Installation Details:' + #13#10 +
             '  • Installation Path: ' + ExpandConstant('{app}') + #13#10 +
             '  • Virtual Environment: %LOCALAPPDATA%\AegisCloudScanner\venv' + #13#10 +
             '  • Access URL: http://localhost:5000' + #13#10#13#10 +
             'Click Finish to launch the application!',
             mbInformation, MB_OK);
    end
    else
    begin
      MsgBox('{#MyAppName} has been installed.' + #13#10#13#10 +
             '⚠ IMPORTANT: Python was not detected!' + #13#10#13#10 +
             'Before running Aegis:' + #13#10 +
             '  1. Install Python 3.8+ from python.org' + #13#10 +
             '  2. Check "Add Python to PATH"' + #13#10 +
             '  3. Restart your computer' + #13#10 +
             '  4. Launch Aegis from Start Menu',
             mbInformation, MB_OK);
    end;
  end;
end;

{* Uninstall Confirmation *}
function InitializeUninstall(): Boolean;
begin
  Result := True;
  if MsgBox('Are you sure you want to uninstall {#MyAppName}?' + #13#10#13#10 +
            'This will remove:' + #13#10 +
            '  • Application files' + #13#10 +
            '  • Virtual environment' + #13#10 +
            '  • User data and databases' + #13#10#13#10 +
            'Your Python installation will NOT be removed.',
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDNO then
  begin
    Result := False;
  end;
end;

{* Post-Uninstall *}
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    MsgBox('{#MyAppName} has been successfully uninstalled.' + #13#10#13#10 +
           'Thank you for using Aegis Cloud Security Scanner!' + #13#10#13#10 +
           'For feedback or support:' + #13#10 +
           'Email: {#MyAppContact}' + #13#10 +
           'GitHub: {#MyAppURL}',
           mbInformation, MB_OK);
  end;
end;

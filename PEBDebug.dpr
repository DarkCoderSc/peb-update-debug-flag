(*******************************************************************************


  Author:
    ->  Jean-Pierre LESUEUR (@DarkCoderSc)
        https://github.com/DarkCoderSc
        https://gist.github.com/DarkCoderSc
        https://www.phrozen.io/

  License:
    -> MIT


*******************************************************************************)

program PEBDebug;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  Windows,
  tlHelp32,
  Generics.Collections,
  UntPEBDebug in 'UntPEBDebug.pas';

type
  TArchitecture = (x86, x64, xUnknown);

{
  Detect target process architecture.
}
function IsProcessX64(AProcessId : Cardinal) : TArchitecture;
var AProcHandle   : THandle;
    AWow64Process : bool;
begin
  result := xUnknown;
  ///

  {
    If we are not in a 64Bit system then we are for sure in a 32Bit system
  }
  if (TOSVersion.Architecture = arIntelX86) then
    Exit();
  ///

  AProcHandle := OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, AProcessId);
  if AProcHandle = 0 then
    Exit;
  try
    isWow64Process(AProcHandle, AWow64Process);
    ///

    if AWow64Process then
      result := x86
    else
      result := x64;
  finally
    CloseHandle(AProcHandle);
  end;
end;

{
  Retrieve the list of running process for scanning PEB value.
}
function EnumProcess(AFilterSameArch : Boolean = False) : TDictionary<Integer {Process Id}, String {Process Name}>;
var ASnap         : THandle;
    AProcessEntry : TProcessEntry32;
    AProcessName  : String;

    procedure AppendEntry();
    begin
      if AFilterSameArch and ((IsProcessX64(GetCurrentProcessId())) <> (IsProcessX64(AProcessEntry.th32ProcessID))) then
        Exit();
      ///

      result.Add(AProcessEntry.th32ProcessID, AProcessEntry.szExeFile);
    end;

begin
  result := TDictionary<Integer, String>.Create();
  ///

  ASnap := CreateToolHelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if ASnap = INVALID_HANDLE_VALUE then
    Exit();
  try
    ZeroMemory(@AProcessEntry, SizeOf(TProcessEntry32));
    ///

    AProcessEntry.dwSize := SizeOf(TProcessEntry32);

    if NOT Process32First(ASnap, AProcessEntry) then
      Exit();

    AppendEntry();

    while True do begin
      ZeroMemory(@AProcessEntry, SizeOf(TProcessEntry32));
      ///

      AProcessEntry.dwSize := SizeOf(TProcessEntry32);

      if NOT Process32Next(ASnap, AProcessEntry) then
        break;

      AppendEntry();
    end;
  finally
    CloseHandle(ASnap);
  end;
end;

{
  Display Process Debug Status Feature.
}
procedure DoListProcessDebugStatus();
var ADebugStatus    : Boolean;
    AProcessName    : String;
    AProcessId      : Cardinal;
    AProcessList    : TDictionary<Integer, String>;
    ADebugStatusStr : String;
begin
  WriteLn('Process List (Only with same architecture) :');
  ///

  AProcessList := EnumProcess(True);
  try
    for AProcessId in AProcessList.Keys do begin
      if NOT AProcessList.TryGetValue(AProcessId, AProcessName) then
        continue;
      ///

      if GetProcessDebugStatus(AProcessId, ADebugStatus) then begin
        if ADebugStatus then
          ADebugStatusStr := 'True'
        else
          ADebugStatusStr := 'False';

        writeln(#09 + Format('* Debug=[%s], %s(%d)', [ADebugStatusStr, AProcessName, AProcessId]));
      end;
    end;
  finally
    if Assigned(AProcessList) then
      FreeAndNil(AProcessList);
  end;

  Writeln(#13#10);
end;

{
  Show different option of that tool
}
function DisplayMenu() : Integer;
var AChoice : String;
begin
  result := 0;
  ///

  WriteLn('Choose an option:');
  WriteLn('--------------------------------------------' + #13#10);

  WriteLn(#09 + '* [1] : List process debug flag');
  WriteLn(#09 + '* [2] : Set process debug flag to true');
  WriteLn(#09 + '* [3] : Set process debug flag to false');
  WriteLn(#09 + '* [4] : Quit');

  Writeln(#13#10);

  Write('Option : ');

  ReadLn(AChoice);

  Writeln(#13#10);

  if NOT TryStrToInt(AChoice, result) then
    result := 0;
end;

{
  Update Target Process Debug Flag
}
procedure UpdateTargetProcessDebugFlag(ADebugStatus : Boolean);
var AChoice    : String;
    AProcessId : Integer;
begin
  Write('Enter target process id :');

  ReadLn(AChoice);

  if NOT TryStrToInt(AChoice, AProcessId) then
    WriteLn('Invalid Process Id')
  else begin
    if AProcessId <= 0 then
      WriteLn('Invalid Process Id')
    else begin
      if SetProcessDebugStatus(AProcessId, ADebugStatus) then begin
        WriteLn('Done.');
      end else begin
        WriteLn('Failed. Possible reasons: "Non existing process id", "Not enough privilege", "Wrong architecture"');
      end;
    end;
  end;

  WriteLn('');
end;

var AChoice : Byte;

begin
  try
    while True do begin
      AChoice := DisplayMenu();
      ///

      case AChoice of
        1 : begin
          DoListProcessDebugStatus();
        end;

        2 : begin
          UpdateTargetProcessDebugFlag(True);
        end;

        3 : begin
          UpdateTargetProcessDebugFlag(False);
        end;

        4 : begin
          Break;
        end;
      end;
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

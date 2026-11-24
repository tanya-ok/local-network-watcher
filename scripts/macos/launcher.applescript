-- Dock launcher: starts the bundled server if it is not running, then shows the UI in a browser app window.
property baseURL : "http://127.0.0.1:4317/"
property startURL : "http://127.0.0.1:4317/#activity"

on serverUp()
	try
		do shell script "/usr/bin/curl --silent --fail --max-time 1 -o /dev/null " & quoted form of (baseURL & "api/settings")
		return true
	on error
		return false
	end try
end serverUp

on startServer()
	set binary to (POSIX path of (path to me)) & "Contents/Resources/local-network-watcher"
	set logFile to (POSIX path of (path to home folder)) & "Library/Logs/LocalNetworkWatcher.log"
	do shell script "/usr/bin/nohup " & quoted form of binary & " >> " & quoted form of logFile & " 2>&1 < /dev/null &"
	repeat 30 times
		if serverUp() then return true
		delay 0.5
	end repeat
	return false
end startServer

on raiseExisting()
	tell application "Brave Browser"
		repeat with w in windows
			set i to 0
			repeat with t in tabs of w
				set i to i + 1
				set u to ""
				try
					set u to URL of t
				end try
				if u starts with baseURL then
					try
						set minimized of w to false
					end try
					set active tab index of w to i
					set index of w to 1
					activate
					return true
				end if
			end repeat
		end repeat
	end tell
	return false
end raiseExisting

on run
	if not serverUp() then
		if not startServer() then
			display dialog "Local Network Watcher did not start. See ~/Library/Logs/LocalNetworkWatcher.log" buttons {"OK"} default button "OK" with icon caution
			return
		end if
	end if
	try
		do shell script "/usr/bin/open -Ra 'Brave Browser'"
	on error
		do shell script "/usr/bin/open " & quoted form of startURL
		return
	end try
	if application "Brave Browser" is running then
		repeat 3 times
			if raiseExisting() then return
			delay 0.5
		end repeat
	end if
	do shell script "/usr/bin/open -na 'Brave Browser' --args --app=" & quoted form of startURL
end run

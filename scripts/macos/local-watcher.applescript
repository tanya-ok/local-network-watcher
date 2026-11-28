-- Dock launcher for the local Local Network Watcher checkout.
property baseURL : "http://127.0.0.1:4317/"
property startURL : "http://127.0.0.1:4317/#map"
property startScript : "__PROJECT_ROOT__/scripts/macos/start-local-watcher.sh"

on run
	try
		do shell script "/bin/zsh " & quoted form of startScript
	on error errorMessage
		display dialog "Local Network Watcher could not start." & return & return & errorMessage buttons {"OK"} default button "OK" with icon caution
		return
	end try

	if application "Brave Browser" is not running then
		do shell script "open -a 'Brave Browser'"
		repeat 20 times
			delay 0.5
			try
				if (count of windows of application "Brave Browser") > 0 then exit repeat
			end try
		end repeat
		delay 1
	end if
	repeat 3 times
		if my raiseExisting() then return
		delay 0.7
	end repeat
	do shell script "open -na 'Brave Browser' --args --app=" & quoted form of startURL
end run

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

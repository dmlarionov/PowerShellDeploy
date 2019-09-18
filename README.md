# What it is?

The `helpers.psm1` is a PowerShell Module supporting deployment of software services to Linux and Windows, orchestrated by a build system.

I was doing my CI + CD in Jenkins, utilizing PowerShell everywhere, and I collected my own reusable functions in this helpers module. You can use it as is or as a code samples, if you are making yours.

# Features

- No matter what operating system is used (on build agent or on target system), because both (Linux and Windows) can run PowerShell.
- No matter what protocol (SSH or WinRM / PSRP) is used, but some batteries for SSH are in included.
- Manipulating configs.
- Updating SSH known_hosts.
- Checking .NET runtime (for .NET application deployment).
- Exporting functions to remote session.
- Creating credentials from login and password encoded in base-64 (for passing Jenkins Credentials).
- Granting log on as a service permission (for windows service deployment).
- Adding URL ACL to http.sys (for deployment of windows service, listening to HTTP).
- Creating windows service instance.
- Starting windows service with checking (for running process, status) and re-posting the possibly related records from application and system log (on target Windows machine) to output (build system log).
- Invoking sudo expressions and remote commands (on target Linux machine).
- Creating | removing and starting | stopping systemd services (on target Linux machine).
- Creating | removing and publishing | unpublishing firewalld services (on target Linux machine).


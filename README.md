# Linux-Privilege-Escalation-Automation-Toolkit
A python based automated toolkit used to scan SUID/SGID binaries, Root owned Processes, Cron jobs and weak file directories, generates a report that displays the findings to be used in reviewing and mitigating misconfigurations and assessing severity of escalations of files   

# Features
The application checks:
1. OS & Kernel Info
2. Current User Info
3. Root Owned Processes
4. SUID/SGID files
5. Cron Jobs
6. Running systemmd Services
7. World-Writable Files
8. Writable Direcotries
9. Path Variables

# Applications
The toolkit is used solely for scanning the all the files that may be exploited to access higher privileges in a user's system. The scanner thus is used can be used for :
> Vulnerability Assessment
> Analyzing high-risk files
> Identify misconfigured and vulnerable files and mitigate steps to implement fixes and patches

This project is limited to Linux based OS only

# Running
Clone the repo using 

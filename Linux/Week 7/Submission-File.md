### Task 1: Create a GPO: Disable Local Link Multicast Name Resolution (LLMNR)
 

### Task 2: Create a GPO: Account Lockout
 
 

### Task 3: Create a GPO: Enabling Verbose PowerShell Logging and Transcription

 

 


### Task 4: Create a Script: Enumerate Access Control Lists

$directory = Get-ChildItem .\
foreach ($item in $directory) {
  Get-Acl $item
}

### Bonus Task 5: Verify Your PowerShell Logging GPO

 
![image](https://user-images.githubusercontent.com/94209591/161419565-b080fabe-8228-4bdf-8e6b-3821f44d373b.png)

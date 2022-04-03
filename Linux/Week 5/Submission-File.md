## Week 5 Homework Submission File: Archiving and Logging Data

Please edit this file by adding the solution commands on the line below the prompt.

Save and submit the completed file for your homework submission.

---

### Step 1: Create, Extract, Compress, and Manage tar Backup Archives

1. Command to **extract** the `TarDocs.tar` archive to the current directory:
Current directory is ~/Projects/
	tar -xvf TarDocs.tar

2. Command to **create** the `Javaless_Doc.tar` archive from the `TarDocs/` directory, while excluding the `TarDocs/Documents/Java` directory:
tar cvvWf Javaless_Doc.tar TarDocs/ /home/sysadmin/TarDocs/Documents/Java
3. Command to ensure `Java/` is not in the new `Javaless_Docs.tar` archive:
tar cvf Javaless_Docs.tar –exclude=”*Java*” /home/sysadmin/Projects/TarDocs
**Bonus** 
- Command to create an incremental archive called `logs_backup_tar.gz` with only changed files to `snapshot.file` for the `/var/log` directory:

#### Critical Analysis Question

- Why wouldn't you use the options `-x` and `-c` at the same time with `tar`?

---Because -x is to extract a file, and -c is for creating a file.

### Step 2: Create, Manage, and Automate Cron Jobs

1. Cron job for backing up the `/var/log/auth.log` file:

0 6 * * 0 ./authlog_backup_script
“authlog_backup_script” contains:
#!/bin/bash

tar cf logs_backups.tar /var/log/auth.log
()end

### Step 3: Write Basic Bash Scripts

1. Brace expansion command to create the four subdirectories:
mkdir ~/backups/{freemem,diskuse,openlist,freedisk}

2. Paste your `system.sh` script edits below:

    ```bash
    #!/bin/bash
    
    free -h > ~/backups/freemem/free_mem.txt
    du -h > ~/backups/diskuse/disk_use.txt
    lsof.  ~/backups/openlist/open_list.txt
    df -h > ~/backups/freedisk/free_disk.txt 
3. Command to make the `system.sh` script executable:
chmod +x system.sh

**Optional**
- Commands to test the script and confirm its execution:
./system.sh

**Bonus**
- Command to copy `system` to system-wide cron directory:
cp ./system.sh /etc/cron.daily
---

### Step 4. Manage Log File Sizes
 
1. Run `sudo nano /etc/logrotate.conf` to edit the `logrotate` configuration file. 

    Configure a log rotation scheme that backs up authentication messages to the `/var/log/auth.log`.

    - Add your config file edits below:

    ```bash
# see "man logrotate" for details
# rotate log files weekly
weekly

# use the syslog group by default, since this is the owning group
# of /var/log/syslog.
su root syslog

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# no packages own wtmp, or btmp -- we'll rotate them here
/var/log/wtmp {
    missingok
    monthly
    create 0664 root utmp
    rotate 1
}

/var/log/btmp {
    missingok
    monthly
    create 0660 root utmp
    rotate 1
}

# system-specific logs may be configured here
/var/log/auth.log {
    rotate 7
    weekly
    missingok
    notifempty
    compress
    delaycompress
    endscript
}

    ```
---

### Bonus: Check for Policy and File Violations

1. Command to verify `auditd` is active:
service auditd status 
systemctl status auditd

2. Command to set number of retained logs and maximum log file size:
sudo nano /etc/audit/auditd.conf

    - Add the edits made to the configuration file below:

    ```bash
    # This file controls the configuration of the audit daemon
#

local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = RAW
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 35
num_logs = 7
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
##tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
distribute_network = no    
```

3. Command using `auditd` to set rules for `/etc/shadow`, `/etc/passwd` and `/var/log/auth.log`:
sudo nano /etc/audit/auditd.conf

    - Add the edits made to the `rules` file below:

    ```bash
    ## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 0

## Set failure mode to syslog
-f 1

-w /etc/shadow -p wra -k hashpass_audit
-w /etc/passwd -p wra -k userpass_audit
-w /var/log/auth.log -p wra -k authlog_audit

    ```

4. Command to restart `auditd`: sudo systemctl restart auditd

5. Command to list all `auditd` rules: sudo auditctl -l

6. Command to produce an audit report: sudo aureport -au

7. Create a user with `sudo useradd attacker` and produce an audit report that lists account modifications:
sysadmin@UbuntuDesktop:~$ sudo aureport -m

Account Modifications Report
=================================================
# date time auid addr term exe acct success event
=================================================
72. 01/04/2022 06:57:21 -1 ? ? /usr/sbin/useradd vboxadd no 237
73. 01/04/2022 06:57:21 -1 ? ? /usr/sbin/useradd vboxadd no 238
74. 01/04/2022 06:57:21 -1 ? ? /usr/sbin/useradd vboxadd no 239
75. 01/04/2022 06:57:21 -1 ? ? /usr/sbin/useradd vboxadd no 240
76. 01/06/2022 05:34:36 -1 ? ? /usr/sbin/useradd vboxadd no 237
77. 01/06/2022 05:34:36 -1 ? ? /usr/sbin/useradd vboxadd no 238
78. 01/06/2022 05:34:36 -1 ? ? /usr/sbin/useradd vboxadd no 239
79. 01/06/2022 05:34:36 -1 ? ? /usr/sbin/useradd vboxadd no 240
80. 01/12/2022 07:53:34 -1 ? ? /usr/sbin/useradd vboxadd no 237
81. 01/12/2022 07:53:34 -1 ? ? /usr/sbin/useradd vboxadd no 238
82. 01/12/2022 07:53:34 -1 ? ? /usr/sbin/useradd vboxadd no 239
83. 01/12/2022 07:53:34 -1 ? ? /usr/sbin/useradd vboxadd no 240
84. 01/15/2022 07:51:55 1000 UbuntuDesktop pts/0 /usr/sbin/useradd attacker yes 41268
85. 01/15/2022 07:51:55 1000 UbuntuDesktop pts/0 /usr/sbin/useradd ? yes 41269

8. Command to use `auditd` to watch `/var/log/cron`:

9. Command to verify `auditd` rules:

---

### Bonus (Research Activity): Perform Various Log Filtering Techniques

1. Command to return `journalctl` messages with priorities from emergency to error:

1. Command to check the disk usage of the system journal unit since the most recent boot:

1. Comand to remove all archived journal files except the most recent two:

1. Command to filter all log messages with priority levels between zero and two, and save output to `/home/sysadmin/Priority_High.txt`:

1. Command to automate the last command in a daily cronjob. Add the edits made to the crontab file below:

    ```bash
    [Your solution cron edits here]
    ```

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.


![image](https://user-images.githubusercontent.com/94209591/161419399-da4f9f59-6050-44dd-9a02-da88c3e98533.png)

=========================================
Introduction
=========================================
This script is designed to provide flexible ticketing integration between Nagios and Service-Now.

=========================================
Pre-Install Requirements
========================================= 
 - MySQL Database
 - Install the below Perl modules
	- DBI
	- XML::Simple
	- Soap::Lite
	- Config::INI::Reader
	- Getopt::Whatever
	- Digest::MD5
	- Config::IniFiles
 	- Service-Now SOAP API must be enabled, refer to Service-Now documentation for more details.

=========================================
Project State
=========================================
 - Requires Improvements - Stable

=========================================
Installation
=========================================
1. Copy the files contained within this zip file to your /usr/local/nagios/libexec/eventhandlers or /usr/local/nagios/libexec directory.
2. Log in to your database as an administrative user (probably root) then create the service-now ticketer database: CREATE DATABASE nagsnt;
3. Create a MySQL user for the nagios service-now ticketer database: CREATE USER 'nagsnt'@'nagios_ip_address' IDENTIFIED BY 'user_password';
4. Grant the user priveleges to the database:  GRANT ALL PRIVILEGES ON nagsnt.* TO 'nagsnt'@'nagios_ip_address';
5. Navigate to the directory you extracted the snt files on the Nagios server, open the config.ini file.
6. Read the configuration section below and set the option in the INI file, save and exit.
7. Run the table builder: ./sn_ticketer.pl --builddb

Optionally you can use the default field_map.ini settings but in the likely case you need to customize it do one of the following:

8. If you are familiar with the service-now page field formats then read the Field mapping section below, then open the field_map.ini and begin mapping.
OR
9a. If you are NOT familiar with the service-now page field formats then create a backup copy of field_map.ini
9b. Open field_map.ini and remove all the default [incident.do] configuration settings, save and exit.
9c. Run the map builder: ./sn_ticketer.pl --page='incident.do' --buildmap
9d. Open the field_map.ini, if everything went well it should now contain all of the available fields for creating incidents.
9e. Remove all of the fields you don't need and read the Field mapping section below to learn more about configuration.

=========================================
Upgrading
=========================================
1. When upgrading from an older version be sure to run ./sn_ticketer.pl --applypatches 
2. Once this completes, check your config.ini for new options and adjust accordingly.

=========================================
Configuration
=========================================
Feature explanation:
Proxy - The proxy settings are required if your connections to service-now traverse a proxy. 
At this stage only basic authentication is supported.

Ticket track - Ticket track controls the ageing of tickets in the database, it is recommended you leave this feature enabled. 
However there are circumstances where this may not be required.

Storm watch - Storm watch prevents Nagios from flooding the ticketing system in the event of an alert storm.
You can use the storm watch options to tune the total number of allowed tickets from all hosts and the number of allowed for a single host.

Logging - Allows you to set the log file location and related options.

Mandatory settings:
db_type - Currently mysql is the only supported and tested database type.
db_username - Username for the database connection.
db_password - Password for the database connection.
db_port - Port for the database connection.
db_address - IP address or hostname of the database server.
db_database - Name of the database you created during the installation.
 
sn_username - The username for the service-now user to read/write tickets as.
sn_password - The password for the service-now user.
sn_url - The URL for connecting to your service-now instance i.e mycompany.service-now.com.

Optional settings:
tt_type - Currently the only available ticket-track type is db (database).
tt_ttl - This is how many days a ticket will remain in archive status in the database after an OK status has been received for a host/service.
tt_dead_ticket - This is how many days a ticket will remain in the database before being moved to archive status if an OK status is never received for a host/service. 
tt_strip_passive_hash_numbers - Strip numbers from passive checks before hashing to help determine "like messages"
tt_strip_active_hash_numbers - Strip numbers from active checks before hashing to help determine "like messages"

sw_service_interval - The interval in minutes for sw_service_tickets.
sw_service_tickets - The number of tickets in the given interval a service must exceed before the ticketer will begin dropping alerts. 
sw_host_interval - The interval in minutes for sw_host_tickets.
sw_host_tickets - The number of tickets in the given interval a host or its services must exceed before the ticketer will begin dropping alerts. 
sw_total_interval - The interval in minutes for sw_total_tickets.
sw_total_tickets - The number of total tickets nagios is allowed to log in a given time interval before it begins dropping alerts.

proxy_username - Username for authenticating to the proxy.
proxy_password - Password for authenticating to the proxy.
proxy_port - Port for the proxy connection.
proxy_address - The IP address or hostname for the proxy connection.

log_path - The full path to the location of the log file.
log_rotate_dir - The path to the log rotate config directory.

=========================================
Field mapping
=========================================
The field map file is used by the sn_ticketer script to map the output of Nagios to input within service-now.
In order to allow for the greatest degree of flexibility there are a number of special characters you can use within the field map to generate dynamic input into service-now.

The field map file is formatted like an INI file where the section header is a service-now page, the key field values are service-now fields on that page and the value field is what you want populate those fields with.

There are some important rules when dealing with meta character to remember though:
1. White space between meta characters are not allowed.
2. The meta characters below are evaluated in the order they are listed, which means you can only nest them in a certain manner.

Standard meta characters:
$WORD$ - Any word entered between dollar signs becomes a valid argument that the script will accept on execution.
&EXPRESSION& - Using the ampersand you can specify a mathematical expression to evaluate.
%PAGE:FIELD:WORD% - The percent symbols are used for referencing the ID of another Service-Now page object.
Certain fields in Service-Now take the sys-id of other Service-Now objects as the input.

Special meta characters:
^ - Any Service-Now key field prepended with the carrot symbol is marked as a field to update when a ticket already exists and a host or service re-alerts.
@ - If the value field is prepended with the at symbol it will append the new information on update instead of overwriting it, which is the default action. 
The at meta-character also requires that the carrot is in use on that field.

=========================================
Usage
=========================================
Example field map definition:
[incident.do]
u_requestor = %sys_user_list.do:first_name:nagios%
category = $category$
subcategory = $subcategory$
^impact = $priority$
^urgency = $priority$
^priority = &$priority$+1&
assignment_group = $group$
short_description = "Nagios alert!"
^description = @$desc$

Example Nagios command definition:
define command {
       command_name		notify-host-by-snt
       command_line		$USER1$/eventhandlers/sn_ticketer.pl --page="incident.do" --host="$HOSTNAME$" --state="$HOSTSTATE$" --category="$_SERVICECATEGORY$" --subcategory="$_SERVICESUBCAT$" --priority="$_PRIORITY$" --group="$CONTACTALIAS$" --shortdesc="$HOSTNAME$ is $SERVICESTATE$" --desc="Host: $HOSTNAME$\nState:   $HOSTSTATE$\nTime: $LONGDATETIME$\nDescription: $HOSTOUTPUT$\n\n"
}

define command {
       command_name		notify-service-by-snt
       command_line		$USER1$/eventhandlers/sn_ticketer.pl --page="incident.do" --host="$HOSTNAME$" --service="$SERVICEDESC$" --state="$SERVICESTATE$" --category="$_SERVICECATEGORY$" --subcategory="$_SERVICESUBCAT$" --priority="$_PRIORITY$" --group="$CONTACTALIAS$" --shortdesc="$SERVICEDESC$ on $HOSTNAME$ is   $SERVICESTATE$" --desc="Host: $HOSTNAME$\nService: $SERVICEDESC$\nState: $SERVICESTATE$\nTime: $LONGDATETIME$\nDescription: $SERVICEOUTPUT$\n\n" $_SERVICEPASSIVE$
}

define contact {
        name                                    contact-service-now-ticketer
        alias                                   New service now ticketing script
        host_notifications_enabled              1
        service_notifications_enabled           1
        host_notification_period                24x7
        service_notification_period             24x7
        host_notification_options               d,u,r
        service_notification_options            w,u,c,r
        host_notification_commands              notify-host-by-snt
        service_notification_commands           notify-service-by-snt
        register                                0
        }

define contact {
        contact_name                            servers-service-now
        alias                                   SERVERS
        use                                     contact-service-now-ticketer
        }

PASSIVE SERVICE		
define service {
        service_description             		Windows server event log
        use                             		service-template
        hostgroup_name                  		windows-server
        contacts                        		servers-service-now
        _category                       		Application
        _subcat                         		Other
		_passive								--passive
        register                        		1
        }

ACTIVE SERVICE
define service {
        service_description             		Windows CPU
        use                             		service-template
        hostgroup_name                  		windows-server
        contacts                        		servers-service-now
		check_command							check_nt!CPULOAD!-l 5,80,90!!!!!!
        _category                       		Hardware
        _subcat                         		Other
        register                        		1
        }

Execution usage:
./sn_ticketer.pl --page="<Service-now page>" [--host="<hostname>" --passive --<customargs> [--service="<service name>" --state="<nagios state>"]] [--builddb] [--applypatches] [--logrotate] [--buildmap]

--page
    The page in the field map you wish to use for this alarm.
--host
	The host that triggered this alarm, required when ticket track is enabled.
--service
	Required option for ticket track to operate properly when the alarm is service related.
--state
	The host/service state. Setting this is highly recommended when using ticket track otherwise it won't operate properly.
--passive
	If this notification is related to passive data set this flag so that the ticket isn't kept alive.
--<customargs>
	Customargs are defined by using the \$\$ symbols in the fieldmap file. Please see the readme for more details.
--builddb
	Creates the database table required for ticket track operation.
--applypatches
	Applies database and config file patches to ensure compatability with latest sn_ticketer version.
--logrotate
	Create log rotate entry.
--buildmap
	Generate the field mappings for a given Service-Now page.
--help
	Display this help text.
	
=========================================
Patch notes
=========================================
v1.2:
- Now requires and loads XML::Simple to resolve some distro compatibility issues. (Thanks KL)
- When doing a builddb it now attempts simple authentication when talking to the WSDL. This must have been a security hole fixed in the Service-Now Dublin update. (Thanks KL)
- No longer bewildering writes the data-type of extracted fields when doing a builddb to nothing in particular. (Thanks KL)

v1.1:
- Fixed Storm Watch database string error preventing it from operating properly when dropping tickets. (thanks AM)
- Fixed the script being ignorant of the host UP state. (thanks AM)

v1.0:
- Removed unnecessary code.
- Fixed several bugs relating to Storm Watch logic.
- *NEW* sw_service_* feature that checks the total tickets for an individual service and suppresses if necessary.
- sw_host_* will now ignore a particular service if it is being too noisy when determining if all the tickets from a particular host need to be suppressed.
- sw_total_* will now ignore hosts/services that are being too noisy when determining if it needs to suppress tickets.
- *NEW* logrotate feature added to assist with creating a log rotate entry.
- *NEW* patching feature added to assist when upgrading from old versions to new versions.
- *NEW* Ticket Track now hashes incoming messages, this is used to prevent duplicate tickets or updating tickets too regularly.
- Updated some of the default settings in config.ini to be more typical for new installs.

v0.2:
- Corrected Storm Watch behaviour so that it does a better job of preventing unwanted noise.
- Improved logging text to be more useful.
- Added additional logic to database clean up.

v0.1:
- First release

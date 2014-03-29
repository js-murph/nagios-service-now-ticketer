#!/usr/bin/perl

use strict;
use warnings;
use DBI;
use SOAP::Lite;
use Config::INI::Reader;
use Config::IniFiles;
use Cwd 'abs_path';
use File::Basename;
use File::Path;
use Getopt::Whatever;
use IO::Handle;
use LWP::UserAgent;
use Digest::MD5 'md5_hex';

sub process_alert {
	# Configure basic variables and assignments.
	my ($hrMainConf, $hrFieldMap) = @_;
	my $strAction = "new";
	my ($strSysID, $soapCommand, @soapParams);
	my $strMessageHash;

	foreach my $key (keys %ARGV) {
		$strMessageHash .= $ARGV{$key};
	}

	if (defined $ARGV{'passive'} && $hrMainConf->{'ticket_track'}->{'tt_strip_passive_hash_numbers'} && $hrMainConf->{'main'}->{'enable_tickettrack'}) {
		$strMessageHash =~ s/[0-9]//g;
	} elsif (!(defined $ARGV{'passive'}) && $hrMainConf->{'ticket_track'}->{'tt_strip_active_hash_numbers'} && $hrMainConf->{'main'}->{'enable_tickettrack'}) {
		$strMessageHash =~ s/[0-9]//g;
	}

	$strMessageHash = md5_hex($strMessageHash);
	snt_log("Message hash for this alert is: $strMessageHash");

	# Generate the service-now connection handle.
	my $soapSnHandle = sn_connect($hrMainConf, $ARGV{'page'});

	# Test to see if this host/service or Nagios is being too noisy and should be ignored
	if ($hrMainConf->{'main'}->{'enable_tickettrack'} && $hrMainConf->{'main'}->{'enable_stormwatch'}) {
		my $dbHandle = db_connect($hrMainConf);
		my $bWriteHoldDown = 0;
		my ($dbQuery, $dbResults, $bMax);

		if (defined $hrMainConf->{'storm_watch'}->{'sw_service_interval'} && defined $hrMainConf->{'storm_watch'}->{'sw_service_tickets'}) {
			if ($ARGV{'service'}) {
				$dbQuery = "SELECT id FROM tbl_sn_ticket_tracker WHERE hostname = ? AND servicename = ? AND date_modified > DATE_SUB(NOW(), INTERVAL ? MINUTE)";
				$dbResults = $dbHandle->prepare($dbQuery);
				$dbResults->execute($ARGV{'host'},$ARGV{'service'},$hrMainConf->{'storm_watch'}->{'sw_service_interval'});
			}
			
			if ($dbResults->rows >= $hrMainConf->{'storm_watch'}->{'sw_service_tickets'}) {
				snt_log("Service: $ARGV{'service'} has tried to log too many tickets");
				$dbResults->finish();
				$bWriteHoldDown = 1;
			}
		} 
		
		if (defined $hrMainConf->{'storm_watch'}->{'sw_host_interval'} && defined $hrMainConf->{'storm_watch'}->{'sw_host_tickets'} && !$bWriteHoldDown) {
			$dbQuery = "SELECT id FROM tbl_sn_ticket_tracker WHERE hostname = ? AND servicename IS NULL AND date_modified > DATE_SUB(NOW(), INTERVAL ? MINUTE) UNION ALL SELECT id FROM tbl_sn_ticket_tracker WHERE hostname = ? AND SERVICENAME IS NOT NULL AND NOT sys_id = 'dropped_ticket' AND date_modified > DATE_SUB(NOW(), INTERVAL ? MINUTE)";
			$dbResults = $dbHandle->prepare($dbQuery);
			$dbResults->execute($ARGV{'host'},$hrMainConf->{'storm_watch'}->{'sw_host_interval'},$ARGV{'host'},$hrMainConf->{'storm_watch'}->{'sw_host_interval'});
			
			if ($dbResults->rows >= $hrMainConf->{'storm_watch'}->{'sw_host_tickets'}) {
				snt_log("Host: $ARGV{'host'} has tried to log too many tickets");
				$dbResults->finish();
				$bWriteHoldDown = 1;	
			}
		}

		if (defined $hrMainConf->{'storm_watch'}->{'sw_total_interval'} && defined $hrMainConf->{'storm_watch'}->{'sw_total_tickets'} && !$bWriteHoldDown) {
			$dbQuery = "SELECT id FROM tbl_sn_ticket_tracker WHERE date_modified > DATE_SUB(NOW(), INTERVAL ? MINUTE) AND NOT sys_id = 'dropped_ticket'";
			$dbResults = $dbHandle->prepare($dbQuery);
			$dbResults->execute($hrMainConf->{'storm_watch'}->{'sw_total_interval'});
		
			if ($dbResults->rows >= $hrMainConf->{'storm_watch'}->{'sw_total_tickets'}) {
				snt_log("The total number of tickets logged in the last $hrMainConf->{'storm_watch'}->{'sw_total_interval'} minutes is too high!");
				$dbResults->finish();
				$bWriteHoldDown = 1;
			}
        }

		if ($bWriteHoldDown) {
			if (!$ARGV{'service'}) {
				$dbQuery = "INSERT INTO tbl_sn_ticket_tracker(hostname,date_created,date_modified,sys_id,archived) VALUES (?, NOW(),NOW(), 'dropped_ticket', 'true', ?)";
				$dbResults = $dbHandle->prepare($dbQuery);
				$dbResults->execute($ARGV{'host'},$strMessageHash);
				$dbResults->finish();
				snt_log("Host: ARGV{'host'} has tried to log too many tickets, suppressing this alert");
			} else {
				$dbQuery = "INSERT INTO tbl_sn_ticket_tracker(hostname,servicename,date_created,date_modified,sys_id,archived) VALUES (?, ?, NOW(),NOW(), 'dropped_ticket', 'true', ?)";
				$dbResults = $dbHandle->prepare($dbQuery);
				$dbResults->execute($ARGV{'host'},$ARGV{'service'},$strMessageHash);
				$dbResults->finish();
				snt_log("Host: $ARGV{'host'} with service: $ARGV{'service'} has tried to log too many tickets, supressing this alert");
			}
			$dbHandle->disconnect();
			exit;
		}
		
		$dbResults->finish();
		$dbHandle->disconnect();
	}
	
	# If ticket track is enabled then check for an existing SN ID for this alarm, via either database or flat file depending on conf.
	if ($hrMainConf->{'main'}->{'enable_tickettrack'}) {
		if ($hrMainConf->{'ticket_track'}->{'tt_type'} eq "db") {
			my $dbHandle = db_connect($hrMainConf);
			my ($dbQuery, $dbResults);
			snt_log("Ticket track enabled using database.");
			if (defined $ARGV{'passive'}) {
				if (!$ARGV{'service'}) {
					$dbQuery = "SELECT message_hash FROM tbl_sn_ticket_tracker WHERE hostname = ? AND servicename IS NULL AND archived = 'true' ORDER BY date_modified DESC";
					$dbResults = $dbHandle->prepare($dbQuery);
					$dbResults->execute($ARGV{'host'});
				} else {
					$dbQuery = "SELECT message_hash FROM tbl_sn_ticket_tracker WHERE hostname = ? AND servicename = ? AND archived = 'true' ORDER BY date_modified DESC";
					$dbResults = $dbHandle->prepare($dbQuery);
					$dbResults->execute($ARGV{'host'},$ARGV{'service'});
				}
				my $dbRow = $dbResults->fetchrow_hashref();
				my $strLastHash = $$dbRow{'message_hash'};
				
				if ($strLastHash && ($strLastHash eq $strMessageHash)) {
					snt_log("Last message is the same as this message, no need to update ticket.");
					exit;
				} else {
					if ($ARGV{'state'} eq "OK" || $ARGV{'state'} eq "UP") {
						snt_log("State is OK and no current ticket exists, no need to create new ticket");
						exit;
					} else {
						snt_log("New message does not match last message. Opening new ticket.");
					}
				}
			} else {
				if (!$ARGV{'service'}) {
					$dbQuery = "SELECT sys_id,message_hash FROM tbl_sn_ticket_tracker WHERE hostname = ? AND servicename IS NULL AND archived = 'false'";
					$dbResults = $dbHandle->prepare($dbQuery);
					$dbResults->execute($ARGV{'host'});
				} else {
					$dbQuery = "SELECT sys_id,message_hash FROM tbl_sn_ticket_tracker WHERE hostname = ? AND servicename = ? AND archived = 'false'";
					$dbResults = $dbHandle->prepare($dbQuery);
					$dbResults->execute($ARGV{'host'},$ARGV{'service'});
				}

				my $dbRow = $dbResults->fetchrow_hashref();
				$strSysID = $$dbRow{'sys_id'};
				my $strLastHash = $$dbRow{'message_hash'};
				
				if ($strLastHash && ($strLastHash eq $strMessageHash)) {
					snt_log("Last message is the same as this message, no need to update ticket.");
					exit;
				}

				# If an SN ID is found and the auto-close feature is enabled then decide if ticket needs to be closed
				if ($strSysID) {
					snt_log("Existing ticket found, updating.");
					$strAction = "update";
				} elsif ($ARGV{'state'} eq "OK" || $ARGV{'state'} eq "UP") {
					snt_log("State is OK and no current ticket exists, no need to create new ticket");
					exit;
				}
			
				$dbResults->finish();
				$dbHandle->disconnect();
			}
		} else {
			snt_log("Unknown ticket track type set. Unable to continue.");
			exit;
		}
	} elsif ($ARGV{'state'} eq "OK" || $ARGV{'state'} eq "UP") {
		snt_log("State is OK and tt is disabled, no need to create ticket");
		exit;
	}

	# Create a new ticket if no existing ticket exists or ticket track is disabled
	if ($strAction eq "new") {
	 	$soapCommand = SOAP::Data->name('insert')->attr({xmlns => 'http://www.service-now.com/'});
		foreach my $fieldKey (keys %{$hrFieldMap->{$ARGV{'page'}}}) {
			my $strTemp = $hrFieldMap->{$ARGV{'page'}}->{$fieldKey};
			$fieldKey =~ s/^\^//;
			$strTemp =~ s/^\@//;

			my @matches = ($strTemp =~ m/\$(\S*)\$/g);
			foreach(@matches) {
				my $matchTemp = $_;
				if ($ARGV{$matchTemp}) {
					$strTemp =~ s/\$$matchTemp\$/$ARGV{$matchTemp}/g;
				} else {
					$strTemp =~ s/\$$matchTemp\$//g;
				}
			}
			
			@matches = ($strTemp =~ m/\&(\S*)\&/g);
			foreach(@matches) {
				my $matchTemp = $_;
					$matchTemp = eval $matchTemp;
					$strTemp =~ s/\&(\S*)\&/$matchTemp/;
			}

			@matches = ($strTemp =~ m/\%(\S*)\%/g);
			foreach(@matches) {
				my $matchTemp = $_;
				my ($page, $field, $val) = split(':', $matchTemp);
				my $soapSnUserHandle = sn_connect($hrMainConf, $page);
				my $soapGetKeys = SOAP::Data->name('getKeys') -> attr({xmlns => 'http://www.service-now.com/'});
				my @soapGetKeysParams = (SOAP::Data->name($field => $val));
				my $soapKey = $soapSnUserHandle->call($soapGetKeys => @soapGetKeysParams);
				
				if ($soapKey->fault) {
					my $soapError = $soapKey->fault->{'faultcode'} . " " . $soapKey->fault->{'faultstring'} . " " . $soapKey->fault->{'detail'};
					snt_log($soapError);
					exit;
				}
				
				my $soapResult = $soapKey->result;
				$strTemp =~ s/\%$matchTemp\%/$soapResult/g;
			}

			$strTemp =~ s/\\n/\n/gs;
			snt_log("Inserting $strTemp into $fieldKey.");
			push(@soapParams, SOAP::Data->name($fieldKey => $strTemp));
		}
	
	# If SN ID was found by ticket track then update the ticket instead of creating a new one.	
	} elsif ($strAction eq "update") {
		$soapCommand = SOAP::Data->name('update')->attr({xmlns => 'http://www.service-now.com/'});
		@soapParams = ( SOAP::Data->name(sys_id => $strSysID));
		
		foreach my $currentField (keys %{$hrFieldMap->{$ARGV{'page'}}}) {
			if (!($currentField =~ m/^\^/)) {
				next;
			} 
			
			my $strTemp = $hrFieldMap->{$ARGV{'page'}}->{$currentField};
			$currentField =~ s/^\^//;
			my $strUpdate = "";
			if ($strTemp =~ m/^\@/) {
				my $soapSnGetHandle = sn_connect($hrMainConf, $ARGV{'page'});
				my $soapGet = SOAP::Data->name('get')->attr({xmlns => 'http://www.service-now.com/'});
				my @soapGetParams = (SOAP::Data->name(sys_id => $strSysID));
				my %soapGetResults = %{$soapSnGetHandle->call($soapGet => @soapGetParams)->body->{'getResponse'}};
				$strUpdate = $soapGetResults{$currentField} . "\n";
			}

			$strTemp =~ s/^\@//;

			my @matches = ($strTemp =~ m/\$(\S*)\$/g);
			foreach(@matches) {
					my $matchTemp = $_;
					if ($ARGV{$matchTemp}) {
							$strTemp =~ s/\$$matchTemp\$/$ARGV{$matchTemp}/g;
					} else {
							$strTemp =~ s/\$$matchTemp\$//g;
					}
			}

			@matches = ($strTemp =~ m/\&(\S*)\&/g);
			foreach(@matches) {
				my $matchTemp = $_;
				my $newMatchTemp = eval $matchTemp;
				$strTemp =~ s/\&(\S*)\&/$newMatchTemp/;
			}

			@matches = ($strTemp =~ m/\%(\S*)\%/g);
			foreach(@matches) {
				my $matchTemp = $_;
				my ($page, $field, $val) = split(':', $matchTemp);
				my $soapSnUserHandle = sn_connect($hrMainConf, $page);
				my $soapGetKeys = SOAP::Data->name('getKeys') -> attr({xmlns => 'http://www.service-now.com/'});
				my @soapGetKeysParams = (SOAP::Data->name($field => $val));
				my $soapKey = $soapSnUserHandle->call($soapGetKeys => @soapGetKeysParams);

				if ($soapKey->fault) {
					my $soapError = $soapKey->fault->{'faultcode'} . " " . $soapKey->fault->{'faultstring'} . " " . $soapKey->fault->{'detail'};
					snt_log($soapError);
					exit;
				}
				
				my $soapResult = $soapKey->result;
				$strTemp =~ s/\%$matchTemp\%/$soapResult/g;
			}

			$strUpdate = $strUpdate . $strTemp;
			$strUpdate =~ s/\\n/\n/gs;
			snt_log("Inserting $strUpdate into $currentField.");
			push(@soapParams, SOAP::Data->name($currentField => $strUpdate));
		}
	
	# If auto-close determined the ticket needs to be closed, then close it.
	} elsif ($strAction eq "close") {
		# tt will determine if ticket should be closed
	} else {
		snt_log("Invalid action somehow set, unable to continue.");
		exit;
	}
	
	# Post data to service-now
	my $soapReturn = $soapSnHandle->call($soapCommand => @soapParams);

	if ($soapReturn->fault) {
		my $soapError = $soapReturn->fault->{'faultcode'} . " " . $soapReturn->fault->{'faultstring'} . " " . $soapReturn->fault->{'detail'};
		snt_log($soapError);
		exit;	
	}
	
	# Retrieve SN ID if it isn't already set.
	if(!$strSysID) {
		$strSysID = $soapReturn->body->{'insertResponse'}->{'sys_id'};
	}

	# If ticket track is enabled update the database.
	if ($hrMainConf->{'main'}->{'enable_tickettrack'}) {
		if ($hrMainConf->{'ticket_track'}->{'tt_type'} eq "db") {
			my $dbHandle = db_connect($hrMainConf);
            my ($dbQuery, $dbResults, $bArchive);

			if ($strAction eq "new") {
				if (exists $ARGV{'passive'}) {
					$bArchive = "true";
				} else {
					$bArchive = "false";
				}

				if (!$ARGV{'service'}) {
                    $dbQuery = "INSERT INTO tbl_sn_ticket_tracker(hostname,date_created,date_modified,sys_id,archived,message_hash) VALUES (?, NOW(),NOW(), ?, ?, ?)";
                    $dbResults = $dbHandle->prepare($dbQuery);
                    $dbResults->execute($ARGV{'host'},$strSysID,$bArchive,$strMessageHash);
					$dbResults->finish();
					snt_log("Creating DB Entry for $ARGV{'host'} with SN ID: $strSysID.");
                } else {
                    $dbQuery = "INSERT INTO tbl_sn_ticket_tracker(hostname,servicename,date_created,date_modified,sys_id,archived,message_hash) VALUES (?, ?, NOW(),NOW(), ?, ?, ?)";
                    $dbResults = $dbHandle->prepare($dbQuery);
                    $dbResults->execute($ARGV{'host'},$ARGV{'service'},$strSysID,$bArchive,$strMessageHash);
					$dbResults->finish();
					snt_log("Creating DB entry for $ARGV{'host'}:$ARGV{'service'} with SN ID: $strSysID.");
                }
			} elsif ($strAction eq "update" && (uc($ARGV{'state'}) eq "OK" || uc($ARGV{'state'}) eq "UP")) {
				$dbQuery = "UPDATE tbl_sn_ticket_tracker SET archived = 'true', date_modified = NOW(), message_hash = '$strMessageHash' WHERE sys_id = ?";
				$dbResults = $dbHandle->prepare($dbQuery);
				$dbResults->execute($strSysID);
				$dbResults->finish();
				snt_log("Archiving the ticket related to SN ID: $strSysID.");
            } elsif ($strAction eq "update") {
				$dbQuery = "UPDATE tbl_sn_ticket_tracker SET date_modified = NOW(), message_hash = '$strMessageHash' WHERE sys_id = ?";
				$dbResults = $dbHandle->prepare($dbQuery);
                $dbResults->execute($strSysID);
                $dbResults->finish();
				snt_log("Ticket related to SN ID: $strSysID has been updated.");
			}

			$dbHandle->disconnect();	
		} else {
			snt_log("We got somewhere we shouldn't have... the tt type somehow magically changed mid-execution. Exiting...");
			exit;
		}
    }
}

sub sn_connect {
	# Connect to service-now, the proxy connection is very simple and only attempts basic auth.
	# Note: Should probably find a way to test this handle... but it's proving difficult...
	my $hrMainConf = shift;
	my $strPage = shift;
	my $soapSnHandle;
	if ($hrMainConf->{'main'}->{'enable_proxy'}) {
		my $strProxyAuth = "";
		if (defined $hrMainConf->{'proxy'}->{'proxy_username'}) {
			$strProxyAuth = "$hrMainConf->{'proxy'}->{'proxy_username'}:$hrMainConf->{'proxy'}->{'proxy_password'}\@";
        }
		$soapSnHandle = SOAP::Lite -> proxy("https://$hrMainConf->{'servicenow'}->{'sn_username'}:$hrMainConf->{'servicenow'}->{'sn_password'}\@$hrMainConf->{'servicenow'}->{'sn_url'}/$strPage?SOAP", proxy => ['https' => "http://$strProxyAuth$hrMainConf->{'proxy'}->{'proxy_address'}:$hrMainConf->{'proxy'}->{'proxy_port'}"]);
	} else {
		$soapSnHandle = SOAP::Lite -> proxy("https://$hrMainConf->{'servicenow'}->{'sn_username'}:$hrMainConf->{'servicenow'}->{'sn_password'}\@$hrMainConf->{'servicenow'}->{'sn_url'}/$strPage?SOAP");
	}
	
	# snt_log("Service-Now SOAP handle created.");
	return $soapSnHandle;
}

sub db_connect {
	# Connect to the tt database, only used if the ticket track option is enabled and set to db
	my $hrMainConf = shift;
	
	my $dbHandle = DBI->connect("dbi:$hrMainConf->{'database'}->{'db_type'}:database=$hrMainConf->{'database'}->{'db_database'};host=$hrMainConf->{'database'}->{'db_address'};port=$hrMainConf->{'database'}->{'db_port'}", $hrMainConf->{'database'}->{'db_username'}, $hrMainConf->{'database'}->{'db_password'});
	
	if ($dbHandle->state) {
		snt_log("Unable to connect to database: $dbHandle->err $dbHandle->errstr");
		exit;
	}
	
	# snt_log("Database handle created.");
	return $dbHandle;
}

sub snt_log {
	# This is a simple logging and output sub.
	my $strMessage = shift;
	print "$strMessage\n";
	if (LOG->opened()) {
		(my $second, my $minute, my $hour, my $dayOfMonth, my $month, my $yearOffset, my $dayOfWeek, my $dayOfYear, my $daylightSavings) = localtime();
		my $year = 1900 + $yearOffset;
        $month++;
        my $dtDate = "$dayOfMonth/$month/$year $hour:$minute:$second";
		print LOG "$dtDate $strMessage\n";
	}
}

sub build_database {
	# Create the database table for ticket track to use when the --builddb option is used
	my $hrMainConf = shift;
	my $dbHandle = db_connect($hrMainConf);
	
	my $dbResults = $dbHandle->prepare("CREATE TABLE IF NOT EXISTS tbl_sn_ticket_tracker (id INTEGER(11) PRIMARY KEY auto_increment, hostname VARCHAR(255) NOT NULL, servicename VARCHAR(255) default NULL, date_created DATETIME NOT NULL, date_modified DATETIME NOT NULL, sys_id VARCHAR(255) NOT NULL, archived VARCHAR(5) NOT NULL, message_hash VARCHAR(255) NOT NULL)");
	$dbResults->execute();

	if ($dbHandle->state) {
		my $errMessage = "Unable to create table: " . $dbHandle->err . " " . $dbHandle->errstr;
		snt_log($errMessage);
		exit;
	}
	
	$dbResults->finish();
	$dbHandle->disconnect();
	snt_log("Database table created succesfully.");
	exit;
}

sub apply_patches {
	# Apply any required changes to configuration files or the database for new versions of sn_ticketer.
	# Patch 0.2 -> 0.3 changes
	my $hrMainConf = shift;
	my $dbHandle = db_connect($hrMainConf);
	
	my $dbQuery = "SHOW COLUMNS FROM tbl_sn_ticket_tracker LIKE 'message_hash'";
	my $dbResults = $dbHandle->prepare($dbQuery);
	$dbResults->execute();

	if ($dbResults->rows < 1) {
		$dbQuery = "ALTER TABLE tbl_sn_ticket_tracker ADD message_hash VARCHAR(255) NOT NULL";
		$dbResults = $dbHandle->prepare($dbQuery);
		$dbResults->execute();
		
		if ($dbHandle->state) {
			my $errMessage = "Unable to add column: " . $dbHandle->err . " " . $dbHandle->errstr;
			snt_log($errMessage);
			exit;
		}
		snt_log("message_hash column created");		
	} else {
		snt_log("message_hash column already exists");
	}
	
	$dbResults->finish();
	$dbHandle->disconnect();

	my $cwd = abs_path($0);
	$cwd = dirname($cwd);
	my $iniHandle = Config::IniFiles->new(-file => "$cwd/config.ini") or die snt_log("Unable to read main config.ini: $!");
	if (!$iniHandle->exists('log','log_rotate_dir')) {
		$iniHandle->newval('log','log_rotate_dir','/etc/logrotate.d/');
		snt_log("Creating config entry for log rotate dir");
	}

	if (!$iniHandle->exists('storm_watch','sw_service_interval')) {
		$iniHandle->newval('storm_watch','sw_service_interval','5');
		snt_log("Creating config entry for stormwatch service interval");
	}

	if (!$iniHandle->exists('storm_watch','sw_service_tickets')) {
		$iniHandle->newval('storm_watch','sw_service_tickets','3');
		snt_log("Creating config entry for stormwatch service max tickets");
        }

	if (!$iniHandle->exists('ticket_track','tt_strip_passive_hash_numbers')) {
		$iniHandle->newval('ticket_track','tt_strip_passive_hash_numbers','1');
		snt_log("Creating config entry for stripping numbers before hashing input on passive ticket input");
    }

	if (!$iniHandle->exists('ticket_track','tt_strip_active_hash_numbers')) {
        $iniHandle->newval('ticket_track','tt_strip_active_hash_numbers','0');
        snt_log("Creating config entry for stripping numbers before hashing input on active ticket input");
    }
	
	$iniHandle->RewriteConfig;
	exit;
}

sub build_map {
	my ($hrMainConf, $hrFieldMap) = @_;
	if (exists $hrFieldMap->{$ARGV{'page'}}) {
		snt_log("Page mapping already exists in field map config, stopping import.");
		exit;	
	}
	my $xmlContent;
	my $httpUa = new LWP::UserAgent;
	if ($hrMainConf->{'main'}->{'enable_proxy'}) {
		my $strProxyAuth = "";
		if (defined $hrMainConf->{'proxy'}->{'proxy_username'}) {
			$strProxyAuth = "$hrMainConf->{'proxy'}->{'proxy_username'}:$hrMainConf->{'proxy'}->{'proxy_password'}\@"; 
		}
		$httpUa->proxy(['http','https'], "http://$strProxyAuth$hrMainConf->{'proxy'}->{'proxy_address'}:$hrMainConf->{'proxy'}->{'proxy_port'}");
	}

	$httpUa->protocols_allowed(['http','https']);
	my $strUrl = "https://$hrMainConf->{'servicenow'}->{'sn_url'}/$ARGV{'page'}?WSDL";
	snt_log("Connecting to: " . $strUrl);
	my $httpReq = new HTTP::Request 'POST' => $strUrl;
	my $httpRet = $httpUa->request($httpReq) or die snt_log("Unable to read site: $!");

	if ($httpRet->is_success) {
		$xmlContent = $httpUa->request($httpReq)->content;
	} else {
		snt_log("Connection to Service-Now Failed: " . $httpRet->status_line);
		exit;
	}

	my $hrSnFields = XMLin($xmlContent, KeyAttr => { 'xsd:element' => 'name'});
	my %hshSnFields = %{$hrSnFields->{'wsdl:types'}->{'xsd:schema'}->{'xsd:element'}->{'insert'}->{'xsd:complexType'}->{'xsd:sequence'}->{'xsd:element'}};
	
	open(FIELDMAP,">>$hrMainConf->{'main'}->{'field_map_path'}");
	print FIELDMAP "\n";
	print FIELDMAP "[" . $ARGV{'page'} . "]\n";
	foreach my $key (keys %hshSnFields) {
		my $strDataType = $hshSnFields{$key}{'type'};
		$strDataType =~ s/xsd://;
		print FIELDMAP "; $strDataType\n";
		print FIELDMAP $key . " = " . "\$" . $key . "\$\n";
		$hrFieldMap->{$ARGV{'page'}}->{$key} = " ;$strDataType";
	}
	close(FIELDMAP);
	exit;
}

sub cleanup_db {
	snt_log("Cleaning up archived DB entries older than TTL");
	# Remove tickets from DB older than ttl
	my $hrMainConf = shift;
	my $dbHandle = db_connect($hrMainConf);
	my ($dbQuery, $dbResults, $intMaxInterval);
	
	if ($hrMainConf->{'storm_watch'}->{'sw_host_interval'} > $hrMainConf->{'storm_watch'}->{'sw_total_interval'}) {
		$intMaxInterval = $hrMainConf->{'storm_watch'}->{'sw_host_interval'}
	} else {
		$intMaxInterval = $hrMainConf->{'storm_watch'}->{'sw_total_interval'}
	}

	$dbQuery = "DELETE FROM tbl_sn_ticket_tracker WHERE sys_id = 'dropped_ticket' AND date_created < DATE_SUB(NOW(), INTERVAL ? MINUTE)";
	$dbResults = $dbHandle->prepare($dbQuery);
	$dbResults->execute($intMaxInterval);

	if ($hrMainConf->{'ticket_track'}->{'tt_dead_ticket'}) {
		$dbQuery = "DELETE FROM tbl_sn_ticket_tracker WHERE date_created < DATE_SUB(NOW(), INTERVAL ? DAY)";
        $dbResults = $dbHandle->prepare($dbQuery);
        $dbResults->execute($hrMainConf->{'ticket_track'}->{'tt_dead_ticket'});
	}

	if ($hrMainConf->{'ticket_track'}->{'tt_ttl'}) {
		$dbQuery = "DELETE FROM tbl_sn_ticket_tracker WHERE archived = 'true' AND date_created < DATE_SUB(NOW(), INTERVAL ? DAY)";
        $dbResults = $dbHandle->prepare($dbQuery);
        $dbResults->execute($hrMainConf->{'ticket_track'}->{'tt_ttl'});
	}
}

sub cleanup_logs {
	my $hrMainConf = shift;
	snt_log("Attempting to create logrotate entry.");
	
	if (!defined $hrMainConf->{'log'}->{'log_rotate_dir'}) {
		snt_log("No log rotate directory defined in sn_ticketer config.ini, please define one first");
	} elsif (-d $hrMainConf->{'log'}->{'log_rotate_dir'}) {
		$hrMainConf->{'log'}->{'log_rotate_dir'} =~ s/\s+$//;
		if (!$hrMainConf->{'log'}->{'log_rotate_dir'} =~ m/\/$/) {
			$hrMainConf->{'log'}->{'log_rotate_dir'} = $hrMainConf->{'log'}->{'log_rotate_dir'} . "/";
		}

		open(LOGROTATE,">$hrMainConf->{'log'}->{'log_rotate_dir'}" . "sn_ticketer") or die snt_log("Unable to open logrotate file:$!\n");
		print LOGROTATE "$hrMainConf->{'log'}->{'log_path'} {\n";
    	print LOGROTATE "\tmissingok\n";
		print LOGROTATE "}";
		close(LOGROTATE);
		snt_log("Created log rotate entry.");
	} else {
		snt_log("Unable to find log rotate directory, please check the path in the sn_ticketer config.ini");
	}

	exit;
}

sub help {
	my $strVersion = "v1.0 b190413";
        print "\nsn_ticketer version: $strVersion\n";
        print "By John Murphy <john.murphy\@roshamboot.org>, GNU GPL License\n";
        print "\nUsage: ./sn_ticketer.pl --page=\"<Service-now page>\" [--host=\"<hostname>\" --passive --<customargs> [--service=\"<service name>\" --state=\"<nagios state>\"]] [--builddb] [--applypatches] [--logrotate] [--buildmap]\n\n";
        print <<EOL;
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

EOL
	exit;
}

##############################################
##
## BEGIN MAIN
##
##############################################

if (exists $ARGV{'help'}) {
        help();
} 

my $cwd = abs_path($0);
$cwd = dirname($cwd);

# Load main config file
my $hrMainConf = Config::INI::Reader->read_file($cwd . '/config.ini') or die "Unable to open main config file: $!\n";
my $hrFieldMap;

# Build database or patch configuration.
if (exists $ARGV{'builddb'}) {
	build_database($hrMainConf);
} elsif (exists $ARGV{'applypatches'}) {
	apply_patches($hrMainConf);
} elsif (exists $ARGV{'logrotate'}) {
	cleanup_logs($hrMainConf);
}

if (!$ARGV{'page'}) {
	help();
}

if ($hrMainConf->{'main'}->{'enable_logging'}) {
	my $strLog = $hrMainConf->{'log'}->{'log_path'};
	open LOG, ">>$strLog" or print "Unable to open log file: $!\n";
	print LOG "\n\n****************************************\n";
}

# Ticket track requires at least the host field be set to operate
if ($hrMainConf->{'main'}->{'enable_tickettrack'}) {
	if ((!$ARGV{'host'}) && (!exists $ARGV{'buildmap'})) {
		help();
	}
	cleanup_db($hrMainConf);
}

# Load field mapping file
if (defined $hrMainConf->{'main'}->{'field_map_path'}) {
	$hrFieldMap = Config::INI::Reader->read_file($hrMainConf->{'main'}->{'field_map_path'});
} elsif (-e $cwd . '/field_map.ini') {
	$hrMainConf->{'main'}->{'field_map_path'} = $cwd . '/field_map.ini';
	$hrFieldMap = Config::INI::Reader->read_file($hrMainConf->{'main'}->{'field_map_path'});
} else {
	snt_log("Error: Can't find field map file unable to continue.");
	exit;
}

snt_log("Config loaded.");

if (exists $ARGV{'buildmap'}) {
	build_map($hrMainConf,$hrFieldMap);	
}

# A service-now page must be specified to interact with.
if (!$hrFieldMap->{$ARGV{'page'}}) {
	snt_log("Error: The page you have specified does not exist in the field map.");
	exit;
}

# Begin processing the alarm.
process_alert($hrMainConf,$hrFieldMap);

snt_log("Completed succesfully.");
if ($hrMainConf->{'main'}->{'enable_logging'}) {
	close LOG;
}
exit;

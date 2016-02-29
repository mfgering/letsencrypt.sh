#!/usr/bin/env php
<?php
$handler = $argv[1];
$sub_domain = $argv[2];
$token_filename = $argv[3];
$token_value = $argv[4];
$xmlapi = null;
$exit_code = 0;

switch($handler) {
	case 'deploy_challenge':
		deploy_challenge($sub_domain, $token_filename, $token_value);
		break;
	case 'clean_challenge':
		clean_challenge($sub_domain, $token_filename, $token_value);
		break;
	case 'deploy_cert':
		deploy_cert($sub_domain, $token_filename, $token_value);
		break;
}
exit($exit_code);


function deploy_challenge($sub_domain, $token_filename, $token_value) {
	global $exit_code;
	$zone_name = zone_for($sub_domain);
	if($zone_name) {
		set_acme_challenge($zone_name, $sub_domain, $token_value);
	} else {
		$exit_code = 1;
	}
}

function clean_challenge($sub_domain, $token_filename, $token_value) {
	global $exit_code;
	$xmlapi = get_xmlapi();
  $zone = $xmlapi->dumpzone($zone_name);
  if($zone->result->status == 1) {
  	$zone_name = zone_for($sub_domain);
  	if($zone_name) {
  		$acme_rec = get_acme_challenge_rec($zone, $sub_domain);
  		if($acme_rec) {
  			$xmlapi->removezonerecord($zone_name, (string) $acme_rec->Line);
  		}
  	} else {
  		$exit_code = 1;
  	}  	 
  } else {
    print "Could not get the zone: ".$zone->result->statusmsg."\n";
    $exit_code = 1;
  }
}

function deploy_cert($sub_domain, $token_filename, $token_value) {
	global $exit_code;
	print "deploy_cert not implemented\n";
	//$exit_code = 1;
}

function get_xmlapi() {
	global $xmlapi;
	if(!$xmlapi) {
		include "xmlapi.php";
		$dns_server = "localhost";
		$xmlapi = new xmlapi($dns_server);
		$xmlapi->set_debug(true);
		$access_hash = file_get_contents('/root/.accesshash');
		$xmlapi->hash_auth("root", $access_hash);
	}
	return $xmlapi;
}

function set_acme_challenge($zone_name, $sub_domain, $token_value) {
  global $exit_code;
	$xmlapi = get_xmlapi();
  $zone = $xmlapi->dumpzone($zone_name);
  if($zone->result->status == 1) {
    $acme_rec = get_acme_challenge_rec($zone, $sub_domain);
    if($acme_rec) {
      $result = $xmlapi->editzonerecord($zone_name, (string) $acme_rec->Line,
        array('txtdata' => $token_value));
      if($result->result->status == 1) {
        print("DNS updated\n");
      } else {
        print("DNS update failed: ".$result->result->statusmsg."\n");
        $exit_code = 1;
      }
    } else {
      $result = $xmlapi->addzonerecord($zone_name, 
        ['name' =>  "_acme-challenge.$sub_domain.",
         'class' => 'IN',
         'ttl' => '300',
         'txtdata' => $token_value,
         'type' => 'TXT',
        ]);
      if($result->result->status == 1) {
        print("DNS record added.\n");
      } else {
        print("DNS add record failed: ".$result->result->statusmsg."\n");
        $exit_code = 1;
      }
    }
  } else {
    print "Could not get the zone: ".$zone->result->statusmsg."\n";
    $exit_code = 1;
  }
}

function get_acme_challenge_rec($zone, $sub_domain) {
  $acme_rec = null;
  $name = "_acme-challenge.$sub_domain.";
  foreach($zone->result->record as $zone_rec) {
    if($zone_rec->type == 'TXT' && $zone_rec->name == $name) {
      $acme_rec = $zone_rec;
      break;
    }
  }
  return $acme_rec;
}

function zone_for($sub_domain, $named_conf_file='/etc/named.conf') {
	$longest_zone = null;
  $handle = fopen($named_conf_file, 'r');
  if($handle) {
  	$zones = [];
  	$in_external = false;
  	while(($line = fgets($handle)) !== false) {
  		if(!$in_external) {
  			if(preg_match('/^\s*view\s+.*external/', $line)) {
  				$in_external = true;
  				continue;
  			}
  		} else {
				if(preg_match('/^\s*zone\s+[\\"](.*?)[\\"]/', $line, $matches)) {
					$zone = $matches[1];
					$zones[] = $zone;
					if(ends_with($sub_domain, $zone) && strlen($zone) > $longest_zone) {
						$longest_zone = $zone;
					}
				} elseif (preg_match('/^\s*view\s+/', $line)) {
					break;
				}
  		}
  	}
  	print "Zone is $longest_zone\n";
  } else {
  	print "Error opening file $named_conf_file\n";
  }
  return $longest_zone;
}

function ends_with($haystack, $needle) {
	// search forward starting from end minus needle length characters
	return $needle === "" || (($temp = strlen($haystack) - strlen($needle)) >= 0 && strpos($haystack, $needle, $temp) !== false);
}
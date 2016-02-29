#!/usr/bin/env php
<?php
include "xmlapi.php";
$handler = $argv[1];
$sub_domain = $argv[2];
$token_filename = $argv[3];
$token_value = $argv[4];

//TODO: add code to find-zone

$dns_server = "localhost";
$xmlapi = new xmlapi($dns_server);
$xmlapi->set_debug(true);
$access_hash = file_get_contents('/root/.accesshash');
$xmlapi->hash_auth("root", $access_hash);
$exit_code = 0;
set_acme_challenge('bp.gattishouse.com', 'mail.bp.gattishouse.com', 'foobar');

exit($exit_code);

function set_acme_challenge($zone_name, $sub_domain, $token_value) {
  global $xmlapi, $exit_code;
  $zone = $xmlapi->dumpzone($zone_name);
  if($zone->result->status == 1) {
    $acme_rec = get_acme_challenge($zone, $sub_domain);
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

function get_acme_challenge($zone, $sub_domain) {
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

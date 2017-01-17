<?php
  if (!session_id()) session_start();
  if (isset($_SESSION['altIDs'])){
    $alts = json_decode($_SESSION['altIDs'], true);
    if(isset($_REQUEST['altLocations'])) {
      $altLocations = $_REQUEST['altLocations'];
      $updated = array();
      foreach ($altLocations as $altLocation) {
        $altLocation = json_decode(json_encode($altLocation));
        foreach($alts as $alt) {
          $alt = json_decode($alt);
          if ($alt->charID == $altLocation->id) {
            if (isset($altLocation->location->solarSystem)) {
              $alt->systemID = $altLocation->location->solarSystem->id;
              $alt->systemName = $altLocation->location->solarSystem->name;
              if (isset($altLocation->location->station)) {
                $alt->stationID = $altLocation->location->station->id;
                $alt->stationName = $altLocation->location->station->name;
              } elseif (isset($altLocation->location->structure)){
                $alt->stationID = $altLocation->location->structure->id;
                $alt->stationName = $altLocation->location->structure->name;
              } else {
                $alt->stationID = null;
                $alt->stationName = null;
              }
              $updated[] = json_encode($alt, JSON_FORCE_OBJECT);
            } else {
              $alt->systemID = null;
              $alt->systemName = null;
              $alt->stationID = null;
              $alt->stationName = null;
              $updated[] = json_encode($alt, JSON_FORCE_OBJECT);
            }
          }
        }
      }
      $_SESSION['altIDs'] = json_encode($updated, JSON_FORCE_OBJECT);
    }
  } 

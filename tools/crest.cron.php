<?php

ini_set('display_errors', 'On');

require('../db.inc.php');
require('../crest.class.php');

$crest = new CREST();
$output = null;

// Get active character CREST info
$query = 'SELECT DISTINCT c.characterID, accessToken, refreshToken, tokenExpire FROM crest INNER JOIN characters c ON c.characterID = crest.characterID INNER JOIN active a ON a.userID = c.userID';
$stmt = $mysql->prepare($query);
$stmt->execute();
$result = $stmt->fetchAll(PDO::FETCH_CLASS);

foreach ($result AS $char) {
    if (strtotime($char->tokenExpire) < time()) {
        // Get a new access token
        $crest->refresh($char->refreshToken);

        $query = 'UPDATE crest SET accessToken = :accessToken, refreshToken = :refreshToken, tokenExpire = :tokenExpire WHERE characterID = :characterID';
        $stmt = $mysql->prepare($query);
        $stmt->bindValue(':accessToken', $crest->accessToken, PDO::PARAM_STR);
        $stmt->bindValue(':refreshToken', $crest->refreshToken, PDO::PARAM_STR);
        $stmt->bindValue(':tokenExpire', $crest->tokenExpire, PDO::PARAM_STR);
        $stmt->bindValue(':characterID', $char->characterID, PDO::PARAM_STR);
        $stmt->execute();

        $char->accessToken = $crest->accessToken;
    }

    $location = $crest->characterLocation($char->accessToken, $char->characterID);

    var_dump('<pre>', $location);

    $query = 'INSERT INTO crest_location (characterID, systemID, systemName, stationID, stationName) VALUES (:characterID, :systemID, :systemName, :stationID, :stationName) ON DUPLICATE KEY UPDATE systemID = :systemID, systemName = :systemName, stationID = :stationID, stationName = :stationName';
    $stmt = $mysql->prepare($query);
    $stmt->bindValue(':characterID', $char->characterID, PDO::PARAM_INT);
    $stmt->bindValue(':systemID', $location->systemID, PDO::PARAM_STR);
    $stmt->bindValue(':systemName', $location->systemName, PDO::PARAM_STR);
    $stmt->bindValue(':stationID', $location->stationID, PDO::PARAM_STR);
    $stmt->bindValue(':stationName', $location->stationName, PDO::PARAM_STR);
    $stmt->execute();
}

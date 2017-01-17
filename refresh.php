<?php
//	======================================================
//	File:		signatures.php
//	Author:		Josh Glassmaker (Daimian Mercer)
//
//	======================================================

// Verify access via Tripwire signon
if (!session_id()) session_start();

if(!isset($_SESSION['userID']) || $_SESSION['ip'] != $_SERVER['REMOTE_ADDR']) {
	session_destroy();
	exit();
}

header('Content-Type: application/json');
$startTime = microtime(true);

require('db.inc.php');
require('security.inc.php');
require('crest.class.php');

/**
// *********************
// Check and update session
// *********************
*/
$query = 'SELECT characterID, characterName, corporationID, corporationName, admin FROM characters WHERE userID = :userID';
$stmt = $mysql->prepare($query);
$stmt->bindValue(':userID', $_SESSION['userID'], PDO::PARAM_INT);
$stmt->execute();
if ($row = $stmt->fetchObject()) {
	$_SESSION['characterID'] = $row->characterID;
	$_SESSION['characterName'] = $row->characterName;
	$_SESSION['corporationID'] = $row->corporationID;
	$_SESSION['corporationName'] = $row->corporationName;
	$_SESSION['admin'] = $row->admin;
}

/**
// *********************
// Mask Check
// *********************
**/
$checkMask = explode('.', $_SESSION['mask']);
if ($checkMask[1] == 0 && $checkMask[0] != 0) {
	// Check custom mask
	$query = 'SELECT masks.maskID FROM masks INNER JOIN groups ON masks.maskID = groups.maskID WHERE masks.maskID = :maskID AND ((ownerID = :characterID AND ownerType = 1373) OR (ownerID = :corporationID AND ownerType = 2) OR (eveID = :characterID AND eveType = 1373) OR (eveID = :corporationID AND eveType = 2))';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':characterID', $_SESSION['characterID'], PDO::PARAM_INT);
	$stmt->bindValue(':corporationID', $_SESSION['corporationID'], PDO::PARAM_INT);
	$stmt->bindValue(':maskID', $_SESSION['mask'], PDO::PARAM_STR);

	if ($stmt->execute() && $stmt->fetchColumn(0) != $_SESSION['mask'])
		$_SESSION['mask'] = $_SESSION['corporationID'] . '.2';
} else if ($checkMask[1] == 1 && $checkMask[0] != $_SESSION['characterID']) {
	// Force current character mask
	$_SESSION['mask'] = $_SESSION['characterID'] . '.1';
} else if ($checkMask[1] == 2 && $checkMask[0] != $_SESSION['corporationID']) {
	// Force current corporation mask
	$_SESSION['mask'] = $_SESSION['corporationID'] . '.2';
}


/**
// *********************
// CREST Location
// *********************
*/
if ($_REQUEST['mode'] == 'init' || (isset($_REQUEST['crest']['tokenExpire']) && strtotime($_REQUEST['crest']['tokenExpire']) < time('-1 minute'))) {
	$query = 'SELECT accessToken, refreshToken, tokenExpire FROM crest WHERE characterID = :characterID';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':characterID', $_SESSION['characterID'], PDO::PARAM_INT);
	$stmt->execute();
	if ($row = $stmt->fetchObject()) {
		if (strtotime($row->tokenExpire) < time('-1 minute')) {
			// Get a new access token
			$crest = new CREST();

			if ($crest->refresh($row->refreshToken)) {
				$query = 'UPDATE crest SET accessToken = :accessToken, refreshToken = :refreshToken, tokenExpire = :tokenExpire WHERE characterID = :characterID';
				$stmt = $mysql->prepare($query);
				$stmt->bindValue(':accessToken', $crest->accessToken, PDO::PARAM_STR);
				$stmt->bindValue(':refreshToken', $crest->refreshToken, PDO::PARAM_STR);
				$stmt->bindValue(':tokenExpire', $crest->tokenExpire, PDO::PARAM_STR);
				$stmt->bindValue(':characterID', $_SESSION['characterID'], PDO::PARAM_STR);
				$stmt->execute();

				$output['crest']['accessToken'] = $crest->accessToken;
				$_SESSION['accessToken'] = $crest->accessToken;
				$output['crest']['tokenExpire'] = $crest->tokenExpire;
			} else {
				$query = 'DELETE FROM crest WHERE characterID = :characterID';
				$stmt = $mysql->prepare($query);
				$stmt->bindValue(':characterID', $_SESSION['characterID'], PDO::PARAM_INT);
				$stmt->execute();
			}
		} else {
			$output['crest']['accessToken'] = $row->accessToken;
			$_SESSION['accessToken'] = $crest->accessToken;
			$output['crest']['tokenExpire'] = $row->tokenExpire;
		}
	}
}

if (isset($_REQUEST['crest']['systemID']) && !empty($_REQUEST['crest']['systemID'])) {
	$headers['systemID'] = isset($_REQUEST['crest']['systemID']) ? $_REQUEST['crest']['systemID'] : null;
	$headers['systemName'] = isset($_REQUEST['crest']['systemName']) ? $_REQUEST['crest']['systemName'] : null;
	$headers['stationID'] = isset($_REQUEST['crest']['stationID']) ? $_REQUEST['crest']['stationID'] : null;
	$headers['stationName'] = isset($_REQUEST['crest']['stationName']) ? $_REQUEST['crest']['stationName'] : null;
	$headers['characterID'] = isset($_REQUEST['crest']['characterID']) ? $_REQUEST['crest']['characterID'] : null;
	$headers['characterName'] = isset($_REQUEST['crest']['characterName']) ? $_REQUEST['crest']['characterName'] : null;

	$output['EVE'] = $_REQUEST['crest'];
}

/**
// *********************
// EVE IGB Headers
// *********************
*/
if (isset($_SERVER['HTTP_EVE_TRUSTED']) && $_SERVER['HTTP_EVE_TRUSTED'] == 'Yes') {
	$headers['systemID'] = 			xssafe($_SERVER['HTTP_EVE_SOLARSYSTEMID']);
	$headers['systemName'] = 		xssafe($_SERVER['HTTP_EVE_SOLARSYSTEMNAME']);
	$headers['constellationID'] = 	isset($_SERVER['HTTP_EVE_CONSTELLATIONID'])?xssafe($_SERVER['HTTP_EVE_CONSTELLATIONID']):null;
	$headers['constellationName'] =	isset($_SERVER['HTTP_EVE_CONSTELLATIONNAME'])?xssafe($_SERVER['HTTP_EVE_CONSTELLATIONNAME']):null;
	$headers['regionID'] = 			xssafe($_SERVER['HTTP_EVE_REGIONID']);
	$headers['regionName'] = 		xssafe($_SERVER['HTTP_EVE_REGIONNAME']);
	$headers['stationID'] =			isset($_SERVER['HTTP_EVE_STATIONID'])?xssafe($_SERVER['HTTP_EVE_STATIONID']):null;
	$headers['stationName'] =		isset($_SERVER['HTTP_EVE_STATIONNAME'])?xssafe($_SERVER['HTTP_EVE_STATIONNAME']):null;
	$headers['characterID'] =		isset($_SERVER['HTTP_EVE_CHARID'])?xssafe($_SERVER['HTTP_EVE_CHARID']):null;
	$headers['characterName'] =		isset($_SERVER['HTTP_EVE_CHARNAME'])?xssafe($_SERVER['HTTP_EVE_CHARNAME']):null;
	$headers['corporationID'] =		isset($_SERVER['HTTP_EVE_CORPID'])?xssafe($_SERVER['HTTP_EVE_CORPID']):null;
	$headers['corporationName'] =	isset($_SERVER['HTTP_EVE_CORPNAME'])?xssafe($_SERVER['HTTP_EVE_CORPNAME']):null;
	$headers['allianceID'] =		isset($_SERVER['HTTP_EVE_ALLIANCEID'])?xssafe($_SERVER['HTTP_EVE_ALLIANCEID']):null;
	$headers['allianceName'] =		isset($_SERVER['HTTP_EVE_ALLIANCENAME'])?xssafe($_SERVER['HTTP_EVE_ALLIANCENAME']):null;
	$headers['shipID'] =			isset($_SERVER['HTTP_EVE_SHIPID'])?xssafe($_SERVER['HTTP_EVE_SHIPID']):null;
	$headers['shipName'] =			isset($_SERVER['HTTP_EVE_SHIPNAME'])?xssafe($_SERVER['HTTP_EVE_SHIPNAME']):null;
	$headers['shipTypeID'] =		isset($_SERVER['HTTP_EVE_SHIPTYPEID'])?xssafe($_SERVER['HTTP_EVE_SHIPTYPEID']):null;
	$headers['shipTypeName'] =		isset($_SERVER['HTTP_EVE_SHIPTYPENAME'])?xssafe($_SERVER['HTTP_EVE_SHIPTYPENAME']):null;

	$output['EVE'] = $headers;

	// Monitor current INGAME position
	if (isset($_SESSION['currentSystem']) && $_SESSION['currentSystem'] != $headers['systemName']) {
		$_SESSION['currentSystem'] = $headers['systemName'];

		$query = 'INSERT INTO systemVisits (systemID, userID) VALUES (:systemID, :userID) ON DUPLICATE KEY UPDATE date = NOW()';
		$stmt = $mysql->prepare($query);
		$stmt->bindValue(':userID', $_SESSION['userID'], PDO::PARAM_INT);
		$stmt->bindValue(':systemID', $headers['systemID'], PDO::PARAM_INT);
		$stmt->execute();

		$query = 'UPDATE userStats SET systemsVisited = systemsVisited + 1 WHERE userID = :userID';
		$stmt = $mysql->prepare($query);
		$stmt->bindValue(':userID', $_SESSION['userID'], PDO::PARAM_INT);
		$stmt->execute();
	} else {
		$_SESSION['currentSystem'] = $headers['systemName'];
	}
} else if (!isset($_REQUEST['crest']['systemID'])) {
	$query = 'SELECT characterID, characterName, systemID, systemName, shipID, shipName, shipTypeID, shipTypeName, stationID, stationName FROM active WHERE userID = :userID AND maskID = :maskID AND characterID = :characterID';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':userID', $_SESSION['userID'], PDO::PARAM_INT);
	$stmt->bindValue(':maskID', $_SESSION['mask'], PDO::PARAM_STR);
	$stmt->bindValue(':characterID', $_SESSION['characterID'], PDO::PARAM_STR);
	$stmt->execute();

	if ($row = $stmt->fetchObject())
		$output['EVE'] = $row;
}

session_write_close();

/**
// *********************
// Core variables
// *********************
*/
$ip				= isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : die();
$instance		= isset($_REQUEST['instance']) ? $_REQUEST['instance'] : 0;
$version		= isset($_SERVER['SERVER_NAME'])? explode('.', $_SERVER['SERVER_NAME'])[0] : die();
$userID			= isset($_SESSION['userID']) ? $_SESSION['userID'] : die();
$maskID			= isset($_SESSION['mask']) ? $_SESSION['mask'] : die();
$characterID 	= isset($_SESSION['characterID']) ? $_SESSION['characterID'] : 0;
$characterName 	= isset($headers['characterName']) ? $headers['characterName'] : null;
$systemID 		= isset($headers['systemID']) ? $headers['systemID'] : null;
$systemName 	= isset($headers['systemName']) ? $headers['systemName'] : null;
$shipID 		= isset($headers['shipID']) ? $headers['shipID'] : null;
$shipName 		= isset($headers['shipName']) ? $headers['shipName'] : null;
$shipTypeID 	= isset($headers['shipTypeID']) ? $headers['shipTypeID'] : null;
$shipTypeName 	= isset($headers['shipTypeName']) ? $headers['shipTypeName'] : null;
$stationID 		= isset($headers['stationID']) ? $headers['stationID'] : null;
$stationName 	= isset($headers['stationName']) ? $headers['stationName'] : null;
$activity 		= isset($_REQUEST['activity']) ? json_encode($_REQUEST['activity']) : null;
$refresh 		= array('sigUpdate' => false, 'chainUpdate' => false);

/**
// *********************
// Active Tracking
// *********************
*/
// Notification
$query = 'SELECT notify FROM active WHERE instance = :instance AND notify IS NOT NULL';
$stmt = $mysql->prepare($query);
$stmt->bindValue(':instance', $instance, PDO::PARAM_STR);
$stmt->execute();
$stmt->rowCount() ? $output['notify'] = $stmt->fetchColumn() : null;

$query = 'SELECT characters.characterName, activity FROM active INNER JOIN characters ON active.userID = characters.userID WHERE maskID = :maskID AND instance <> :instance AND activity IS NOT NULL AND activity <> ""';
$stmt = $mysql->prepare($query);
$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
$stmt->bindValue(':instance', $instance, PDO::PARAM_STR);
$stmt->execute();
$stmt->rowCount() ? $output['activity'] = $stmt->fetchAll(PDO::FETCH_OBJ) : null;


// *********************
// Signatures update
// *********************

require('signatures.php');
$signatures = new signatures();
if (isset($_REQUEST['request'])) {
	array_walk_recursive($_REQUEST['request'], "xss_filter");
	$data = json_decode(json_encode($_REQUEST['request']));

	if ($data) {
		if (property_exists($data, 'signatures') && property_exists($data->signatures, 'rename') && $data->signatures->rename != null)
			$output['result'] = $signatures->rename($data->signatures->rename);

		if (property_exists($data, 'signatures') && property_exists($data->signatures, 'delete') && $data->signatures->delete != null)
			$output['result'] = $signatures->delete($data->signatures->delete);

		if (property_exists($data, 'signatures') && property_exists($data->signatures, 'add') && $data->signatures->add != null)
			$output['result'] = $signatures->add($data->signatures->add);

		if (property_exists($data, 'signatures') && property_exists($data->signatures, 'update') && $data->signatures->update != null)
			$output['result'] = $signatures->update($data->signatures->update);
	}
}

// *********************
// Active Tracking II: So things don't break edition~Aurorah
// *********************

$query = 'INSERT INTO active (ip, instance, session, userID, maskID, characterID, characterName, systemID, systemName, shipID, shipName, shipTypeID, shipTypeName, stationID, stationName, activity, version)
			VALUES (:ip, :instance, :session, :userID, :maskID, :characterID, :characterName, :systemID, :systemName, :shipID, :shipName, :shipTypeID, :shipTypeName, :stationID, :stationName, :activity, :version)
			ON DUPLICATE KEY UPDATE
			maskID = :maskID, characterName = :characterName, systemID = :systemID, systemName = :systemName, shipID = :shipID, shipName = :shipName, shipTypeID = :shipTypeID, shipTypeName = :shipTypeName, stationID = :stationID, stationName = :stationName, activity = :activity, version = :version, time = NOW(), notify = NULL';
$stmt = $mysql->prepare($query);
$stmt->bindValue(':ip', $ip, PDO::PARAM_STR);
$stmt->bindValue(':instance', $instance, PDO::PARAM_STR);
$stmt->bindValue(':session', session_id(), PDO::PARAM_STR);
$stmt->bindValue(':userID', $userID, PDO::PARAM_INT);
$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
$stmt->bindValue(':characterID', $characterID, PDO::PARAM_INT);
$stmt->bindValue(':characterName', $characterName, PDO::PARAM_STR);
$stmt->bindValue(':systemID', $systemID, PDO::PARAM_INT);
$stmt->bindValue(':systemName', $systemName, PDO::PARAM_STR);
$stmt->bindValue(':shipID', $shipID, PDO::PARAM_INT);
$stmt->bindValue(':shipName', $shipName, PDO::PARAM_STR);
$stmt->bindValue(':shipTypeID', $shipTypeID, PDO::PARAM_INT);
$stmt->bindValue(':shipTypeName', $shipTypeName, PDO::PARAM_STR);
$stmt->bindValue(':stationID', $stationID, PDO::PARAM_INT);
$stmt->bindValue(':stationName', $stationName, PDO::PARAM_STR);
$stmt->bindValue(':activity', $activity, PDO::PARAM_STR);
$stmt->bindValue(':version', $version, PDO::PARAM_STR);
$stmt->execute();

/**
// *********************
// Undo / Redo
// *********************
*/
if (isset($_REQUEST['undo'])) {
	$query = "SELECT * FROM _history_signatures WHERE status NOT IN ('undo:add', 'undo:update', 'undo:delete') AND userID = :userID AND mask = :mask AND (systemID = :systemID OR connectionID = :systemID) AND time = (SELECT time FROM _history_signatures WHERE status NOT IN ('undo:add', 'undo:update', 'undo:delete') AND userID = :userID AND mask = :mask AND (systemID = :systemID OR connectionID = :systemID) AND DATE_ADD(time, INTERVAL 4 HOUR) > NOW() ORDER BY time DESC LIMIT 1)";
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':userID', $userID, PDO::PARAM_STR);
	$stmt->bindValue(':mask', $maskID, PDO::PARAM_STR);
	$stmt->bindValue(':systemID', $_REQUEST['systemID'], PDO::PARAM_STR);
	$stmt->execute();

	foreach ($stmt->fetchAll(PDO::FETCH_OBJ) AS $row) {
		if ($row->status == 'add') {
			$query = "UPDATE _history_signatures SET status = 'undo:add', time = NOW() WHERE historyID = :historyID";
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':historyID', $row->historyID, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = 1';
			$stmt = $mysql->prepare($query);
			$stmt->execute();

			$query = 'DELETE FROM signatures WHERE id = :id';
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':id', $row->id, PDO::PARAM_INT);
			$stmt->execute();

			$query = 'SET @disable_trigger = NULL';
			$stmt = $mysql->prepare($query);
			$stmt->execute();

		} else if ($row->status == 'update') {
			$query = "SELECT * FROM _history_signatures WHERE id = :id AND status NOT IN ('undo:add', 'undo:update', 'undo:delete') AND userID = :userID AND mask = :mask AND time = (SELECT time FROM _history_signatures WHERE id = :id AND status NOT IN ('undo:add', 'undo:update', 'undo:delete') AND userID = :userID AND mask = :mask ORDER BY time DESC LIMIT 1,1)";
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':id', $row->id, PDO::PARAM_INT);
			$stmt->bindValue(':userID', $userID, PDO::PARAM_STR);
			$stmt->bindValue(':mask', $maskID, PDO::PARAM_STR);
			$stmt->execute();
			$restore = $stmt->fetchObject();

			$query = "UPDATE _history_signatures SET status = 'undo:update', time = NOW() WHERE historyID = :historyID";
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':historyID', $row->historyID, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = 1';
			$stmt = $mysql->prepare($query);
			$stmt->execute();

			$query = 'UPDATE signatures SET signatureID = :signatureID, system = :system, systemID = :systemID, type = :type, class = :class, classBM = :classBM, typeBM = :typeBM, nth = :nth, sig2ID = :sig2ID, sig2Type = :sig2Type, class2 = :class2, class2BM = :class2BM, type2BM = :type2BM, nth2 = :nth2, connection = :connection, connectionID = :connectionID, life = :life, lifeTime = :lifeTime, lifeLeft = :lifeLeft, lifeLength = :lifeLength, mass = :mass, name = :name, userID = :userID, time = NOW() WHERE id = :id';
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':id', $restore->id, PDO::PARAM_STR);
			$stmt->bindValue(':signatureID', $restore->signatureID, PDO::PARAM_STR);
			$stmt->bindValue(':system', $restore->system, PDO::PARAM_STR);
			$stmt->bindValue(':systemID', $restore->systemID, PDO::PARAM_STR);
			$stmt->bindValue(':type', $restore->type, PDO::PARAM_STR);
			$stmt->bindValue(':class', $restore->class, PDO::PARAM_STR);
			$stmt->bindValue(':classBM', $restore->classBM, PDO::PARAM_STR);
			$stmt->bindValue(':typeBM', $restore->typeBM, PDO::PARAM_STR);
			$stmt->bindValue(':nth', $restore->nth, PDO::PARAM_STR);
			$stmt->bindValue(':sig2ID', $restore->sig2ID, PDO::PARAM_STR);
			$stmt->bindValue(':sig2Type', $restore->sig2Type, PDO::PARAM_STR);
			$stmt->bindValue(':class2', $restore->class2, PDO::PARAM_STR);
			$stmt->bindValue(':class2BM', $restore->class2BM, PDO::PARAM_STR);
			$stmt->bindValue(':type2BM', $restore->type2BM, PDO::PARAM_STR);
			$stmt->bindValue(':nth2', $restore->nth2, PDO::PARAM_STR);
			$stmt->bindValue(':connection', $restore->connection, PDO::PARAM_STR);
			$stmt->bindValue(':connectionID', $restore->connectionID, PDO::PARAM_STR);
			$stmt->bindValue(':life', $restore->life, PDO::PARAM_STR);
			$stmt->bindValue(':lifeTime', $restore->lifeTime, PDO::PARAM_STR);
			$stmt->bindValue(':lifeLeft', $restore->lifeLeft, PDO::PARAM_STR);
			$stmt->bindValue(':lifeLength', $restore->lifeLength, PDO::PARAM_STR);
			$stmt->bindValue(':mass', $restore->mass, PDO::PARAM_STR);
			$stmt->bindValue(':name', $restore->name, PDO::PARAM_STR);
			$stmt->bindValue(':userID', $restore->userID, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = NULL';
			$stmt = $mysql->prepare($query);
			$stmt->execute();
		} else if ($row->status == 'delete') {
			$query = "UPDATE _history_signatures SET status = 'undo:delete', time = NOW() WHERE historyID = :historyID";
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':historyID', $row->historyID, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = 1';
			$stmt = $mysql->prepare($query);
			$stmt->execute();

			$query = 'INSERT INTO signatures SET id = :id, signatureID = :signatureID, system = :system, systemID = :systemID, type = :type, class = :class, classBM = :classBM, typeBM = :typeBM, nth = :nth, sig2ID = :sig2ID, sig2Type = :sig2Type, class2 = :class2, class2BM = :class2BM, type2BM = :type2BM, nth2 = :nth2, connection = :connection, connectionID = :connectionID, life = :life, lifeTime = :lifeTime, lifeLeft = :lifeLeft, lifeLength = :lifeLength, mass = :mass, name = :name, userID = :userID, time = NOW(), mask = :mask';
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':id', $row->id, PDO::PARAM_STR);
			$stmt->bindValue(':signatureID', $row->signatureID, PDO::PARAM_STR);
			$stmt->bindValue(':system', $row->system, PDO::PARAM_STR);
			$stmt->bindValue(':systemID', $row->systemID, PDO::PARAM_STR);
			$stmt->bindValue(':type', $row->type, PDO::PARAM_STR);
			$stmt->bindValue(':class', $row->class, PDO::PARAM_STR);
			$stmt->bindValue(':classBM', $row->classBM, PDO::PARAM_STR);
			$stmt->bindValue(':typeBM', $row->typeBM, PDO::PARAM_STR);
			$stmt->bindValue(':nth', $row->nth, PDO::PARAM_STR);
			$stmt->bindValue(':sig2ID', $row->sig2ID, PDO::PARAM_STR);
			$stmt->bindValue(':sig2Type', $row->sig2Type, PDO::PARAM_STR);
			$stmt->bindValue(':class2', $row->class2, PDO::PARAM_STR);
			$stmt->bindValue(':class2BM', $row->class2BM, PDO::PARAM_STR);
			$stmt->bindValue(':type2BM', $row->type2BM, PDO::PARAM_STR);
			$stmt->bindValue(':nth2', $row->nth2, PDO::PARAM_STR);
			$stmt->bindValue(':connection', $row->connection, PDO::PARAM_STR);
			$stmt->bindValue(':connectionID', $row->connectionID, PDO::PARAM_STR);
			$stmt->bindValue(':life', $row->life, PDO::PARAM_STR);
			$stmt->bindValue(':lifeTime', $row->lifeTime, PDO::PARAM_STR);
			$stmt->bindValue(':lifeLeft', $row->lifeLeft, PDO::PARAM_STR);
			$stmt->bindValue(':lifeLength', $row->lifeLength, PDO::PARAM_STR);
			$stmt->bindValue(':mass', $row->mass, PDO::PARAM_STR);
			$stmt->bindValue(':name', $row->name, PDO::PARAM_STR);
			$stmt->bindValue(':userID', $row->userID, PDO::PARAM_STR);
			$stmt->bindValue(':mask', $row->mask, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = NULL';
			$stmt = $mysql->prepare($query);
			$stmt->execute();
		}
	}

} else if (isset($_REQUEST['redo'])) {
	$query = "SELECT * FROM _history_signatures WHERE status IN ('undo:add', 'undo:update', 'undo:delete') AND userID = :userID AND mask = :mask AND (systemID = :systemID OR connectionID = :systemID) AND time = (SELECT time FROM _history_signatures WHERE status IN ('undo:add', 'undo:update', 'undo:delete') AND userID = :userID AND mask = :mask AND (systemID = :systemID OR connectionID = :systemID) AND DATE_ADD(time, INTERVAL 4 HOUR) > NOW() ORDER BY time DESC LIMIT 1)";
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':userID', $userID, PDO::PARAM_STR);
	$stmt->bindValue(':mask', $maskID, PDO::PARAM_STR);
	$stmt->bindValue(':systemID', $_REQUEST['systemID'], PDO::PARAM_STR);
	$stmt->execute();

	foreach ($stmt->fetchAll(PDO::FETCH_OBJ) AS $row) {
		if ($row->status == 'undo:add') {
			$query = "UPDATE _history_signatures SET status = 'add', time = now() WHERE historyID = :historyID";
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':historyID', $row->historyID, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = 1';
			$stmt = $mysql->prepare($query);
			$stmt->execute();

			$query = 'INSERT INTO signatures SET id = :id, signatureID = :signatureID, system = :system, systemID = :systemID, type = :type, class = :class, classBM = :classBM, typeBM = :typeBM, nth = :nth, sig2ID = :sig2ID, sig2Type = :sig2Type, class2 = :class2, class2BM = :class2BM, type2BM = :type2BM, nth2 = :nth2, connection = :connection, connectionID = :connectionID, life = :life, lifeTime = :lifeTime, lifeLeft = :lifeLeft, lifeLength = :lifeLength, mass = :mass, name = :name, userID = :userID, time = NOW(), mask = :mask';
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':id', $row->id, PDO::PARAM_STR);
			$stmt->bindValue(':signatureID', $row->signatureID, PDO::PARAM_STR);
			$stmt->bindValue(':system', $row->system, PDO::PARAM_STR);
			$stmt->bindValue(':systemID', $row->systemID, PDO::PARAM_STR);
			$stmt->bindValue(':type', $row->type, PDO::PARAM_STR);
			$stmt->bindValue(':class', $row->class, PDO::PARAM_STR);
			$stmt->bindValue(':classBM', $row->classBM, PDO::PARAM_STR);
			$stmt->bindValue(':typeBM', $row->typeBM, PDO::PARAM_STR);
			$stmt->bindValue(':nth', $row->nth, PDO::PARAM_STR);
			$stmt->bindValue(':sig2ID', $row->sig2ID, PDO::PARAM_STR);
			$stmt->bindValue(':sig2Type', $row->sig2Type, PDO::PARAM_STR);
			$stmt->bindValue(':class2', $row->class2, PDO::PARAM_STR);
			$stmt->bindValue(':class2BM', $row->class2BM, PDO::PARAM_STR);
			$stmt->bindValue(':type2BM', $row->type2BM, PDO::PARAM_STR);
			$stmt->bindValue(':nth2', $row->nth2, PDO::PARAM_STR);
			$stmt->bindValue(':connection', $row->connection, PDO::PARAM_STR);
			$stmt->bindValue(':connectionID', $row->connectionID, PDO::PARAM_STR);
			$stmt->bindValue(':life', $row->life, PDO::PARAM_STR);
			$stmt->bindValue(':lifeTime', $row->lifeTime, PDO::PARAM_STR);
			$stmt->bindValue(':lifeLeft', $row->lifeLeft, PDO::PARAM_STR);
			$stmt->bindValue(':lifeLength', $row->lifeLength, PDO::PARAM_STR);
			$stmt->bindValue(':mass', $row->mass, PDO::PARAM_STR);
			$stmt->bindValue(':name', $row->name, PDO::PARAM_STR);
			$stmt->bindValue(':userID', $row->userID, PDO::PARAM_STR);
			$stmt->bindValue(':mask', $row->mask, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = NULL';
			$stmt = $mysql->prepare($query);
			$stmt->execute();
		} else if ($row->status == 'undo:update') {
			$query = "UPDATE _history_signatures SET status = 'update', time = NOW() WHERE historyID = :historyID";
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':historyID', $row->historyID, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = 1';
			$stmt = $mysql->prepare($query);
			$stmt->execute();

			$query = 'UPDATE signatures SET signatureID = :signatureID, system = :system, systemID = :systemID, type = :type, class = :class, classBM = :classBM, typeBM = :typeBM, nth = :nth, sig2ID = :sig2ID, sig2Type = :sig2Type, class2 = :class2, class2BM = :class2BM, type2BM = :type2BM, nth2 = :nth2, connection = :connection, connectionID = :connectionID, life = :life, lifeTime = :lifeTime, lifeLeft = :lifeLeft, lifeLength = :lifeLength, mass = :mass, name = :name, userID = :userID, time = NOW() WHERE id = :id';
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':id', $row->id, PDO::PARAM_STR);
			$stmt->bindValue(':signatureID', $row->signatureID, PDO::PARAM_STR);
			$stmt->bindValue(':system', $row->system, PDO::PARAM_STR);
			$stmt->bindValue(':systemID', $row->systemID, PDO::PARAM_STR);
			$stmt->bindValue(':type', $row->type, PDO::PARAM_STR);
			$stmt->bindValue(':class', $row->class, PDO::PARAM_STR);
			$stmt->bindValue(':classBM', $row->classBM, PDO::PARAM_STR);
			$stmt->bindValue(':typeBM', $row->typeBM, PDO::PARAM_STR);
			$stmt->bindValue(':nth', $row->nth, PDO::PARAM_STR);
			$stmt->bindValue(':sig2ID', $row->sig2ID, PDO::PARAM_STR);
			$stmt->bindValue(':sig2Type', $row->sig2Type, PDO::PARAM_STR);
			$stmt->bindValue(':class2', $row->class2, PDO::PARAM_STR);
			$stmt->bindValue(':class2BM', $row->class2BM, PDO::PARAM_STR);
			$stmt->bindValue(':type2BM', $row->type2BM, PDO::PARAM_STR);
			$stmt->bindValue(':nth2', $row->nth2, PDO::PARAM_STR);
			$stmt->bindValue(':connection', $row->connection, PDO::PARAM_STR);
			$stmt->bindValue(':connectionID', $row->connectionID, PDO::PARAM_STR);
			$stmt->bindValue(':life', $row->life, PDO::PARAM_STR);
			$stmt->bindValue(':lifeTime', $row->lifeTime, PDO::PARAM_STR);
			$stmt->bindValue(':lifeLeft', $row->lifeLeft, PDO::PARAM_STR);
			$stmt->bindValue(':lifeLength', $row->lifeLength, PDO::PARAM_STR);
			$stmt->bindValue(':mass', $row->mass, PDO::PARAM_STR);
			$stmt->bindValue(':name', $row->name, PDO::PARAM_STR);
			$stmt->bindValue(':userID', $row->userID, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = NULL';
			$stmt = $mysql->prepare($query);
			$stmt->execute();
		} else if ($row->status == 'undo:delete') {
			$query = "UPDATE _history_signatures SET status = 'delete', time = NOW() WHERE historyID = :historyID";
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':historyID', $row->historyID, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = 1';
			$stmt = $mysql->prepare($query);
			$stmt->execute();

			$query = 'DELETE FROM signatures WHERE id = :id AND userID = :userID AND mask = :mask';
			$stmt = $mysql->prepare($query);
			$stmt->bindValue(':id', $row->id, PDO::PARAM_STR);
			$stmt->bindValue(':userID', $userID, PDO::PARAM_STR);
			$stmt->bindValue(':mask', $maskID, PDO::PARAM_STR);
			$stmt->execute();

			$query = 'SET @disable_trigger = NULL';
			$stmt = $mysql->prepare($query);
			$stmt->execute();
		}
	}
}

// Check if Undo/Redo is available
$query = "SELECT * FROM _history_signatures WHERE status NOT IN ('undo:add', 'undo:update', 'undo:delete') AND userID = :userID AND mask = :mask AND (systemID = :systemID OR connectionID = :systemID) AND time = (SELECT time FROM _history_signatures WHERE status NOT IN ('undo:add', 'undo:update', 'undo:delete') AND userID = :userID AND mask = :mask AND (systemID = :systemID OR connectionID = :systemID) AND DATE_ADD(time, INTERVAL 4 HOUR) > NOW() ORDER BY time DESC LIMIT 1)";
$stmt = $mysql->prepare($query);
$stmt->bindValue(':userID', $userID, PDO::PARAM_STR);
$stmt->bindValue(':mask', $maskID, PDO::PARAM_STR);
$stmt->bindValue(':systemID', $_REQUEST['systemID'], PDO::PARAM_STR);
$stmt->execute();
$stmt->rowCount() ? $output['undo'] = true : null;

$query = "SELECT * FROM _history_signatures WHERE status IN ('undo:add', 'undo:update', 'undo:delete') AND userID = :userID AND mask = :mask AND (systemID = :systemID OR connectionID = :systemID) AND time = (SELECT time FROM _history_signatures WHERE status IN ('undo:add', 'undo:update', 'undo:delete') AND userID = :userID AND mask = :mask AND (systemID = :systemID OR connectionID = :systemID) AND DATE_ADD(time, INTERVAL 4 HOUR) > NOW() ORDER BY time DESC LIMIT 1)";
$stmt = $mysql->prepare($query);
$stmt->bindValue(':userID', $userID, PDO::PARAM_STR);
$stmt->bindValue(':mask', $maskID, PDO::PARAM_STR);
$stmt->bindValue(':systemID', $_REQUEST['systemID'], PDO::PARAM_STR);
$stmt->execute();
$stmt->rowCount() ? $output['redo'] = true : null;

if (isset($_REQUEST['mode']) && $_REQUEST['mode'] == 'init') {
	$output['signatures'] = Array();
	$systemID = $_REQUEST['systemID'];

	$query = 'SELECT * FROM signatures WHERE (systemID = :systemID OR connectionID = :systemID) AND mask = :mask';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':systemID', $systemID, PDO::PARAM_INT);
	$stmt->bindValue(':mask', $maskID, PDO::PARAM_INT);
	$stmt->execute();

	while ($row = $stmt->fetchObject()) {
		$row->lifeTime = date('m/d/Y H:i:s e', strtotime($row->lifeTime));
		$row->lifeLeft = date('m/d/Y H:i:s e', strtotime($row->lifeLeft));
		$row->time = date('m/d/Y H:i:s e', strtotime($row->time));

		$output['signatures'][$row->id] = $row;
	}

	// Send server time for time sync
	$now = new DateTime();
	//$now->sub(new DateInterval('PT300S')); // Set clock 300 secounds behind
	$output['sync'] = $now->format("m/d/Y H:i:s e");

	// Grab chain map data
	$query = "SELECT DISTINCT signatures.id, signatureID, system, systemID, connection, connectionID, sig2ID, type, nth, sig2Type, nth2, lifeLength, life, mass, time, typeBM, type2BM, classBM, class2BM, mask FROM signatures WHERE life IS NOT NULL AND (mask = :mask OR ((signatures.systemID = 31000005 OR signatures.connectionID = 31000005) AND mask = 273)) ORDER BY id ASC";
	#$query = "SELECT DISTINCT signatures.id, signatureID, system, CASE WHEN signatures.systemID = 0 THEN signatures.id ELSE signatures.systemID END AS systemID, connection, CASE WHEN connectionID IS NULL OR connectionID = 0 THEN signatures.id ELSE connectionID END AS connectionID, sig2ID, type, nth, sig2Type, nth2, class1.class, class2.class AS class2, (SELECT security FROM $eve_dump.mapSolarSystems WHERE solarSystemID = signatures.systemID) AS security, (SELECT security FROM $eve_dump.mapSolarSystems WHERE solarSystemID = connectionID) AS security2, lifeLength, life, mass, time, typeBM, type2BM, classBM, class2BM FROM signatures LEFT JOIN systems class1 ON class1.systemID = signatures.systemID LEFT JOIN systems class2 ON class2.systemID = connectionID WHERE life IS NOT NULL AND mask = :mask";
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':mask', $maskID, PDO::PARAM_INT);
	$stmt->execute();

	$output['chain']['map'] = $stmt->fetchAll(PDO::FETCH_CLASS);

	// System activity indicators
	$query = 'SELECT DISTINCT api.systemID, shipJumps, podKills, shipKills, npcKills, mask FROM signatures sigs INNER JOIN eve_api.recentActivity api ON connectionID = api.systemID OR sigs.systemID = api.systemID WHERE life IS NOT NULL AND (mask = :mask OR ((sigs.systemID = 31000005 OR sigs.connectionID = 31000005) AND mask = 273))';
	#$query = 'SELECT DISTINCT api.systemID, shipJumps, podKills, shipKills, npcKills FROM signatures sigs INNER JOIN eve_api.recentActivity api ON connectionID = api.systemID OR sigs.systemID = api.systemID WHERE life IS NOT NULL AND mask = :mask';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':mask', $maskID, PDO::PARAM_INT);
	$stmt->execute();

	$output['chain']['activity'] = $stmt->fetchAll(PDO::FETCH_CLASS);

	// Chain last modified
	$query = 'SELECT MAX(time) AS last_modified FROM signatures WHERE life IS NOT NULL AND (mask = :mask OR ((signatures.systemID = 31000005 OR signatures.connectionID = 31000005) AND mask = 273))';
	#$query = 'SELECT MAX(time) AS last_modified FROM signatures WHERE life IS NOT NULL AND mask = :mask';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':mask', $maskID, PDO::PARAM_STR);
	$stmt->execute();
	$output['chain']['last_modified'] = $stmt->rowCount() ? $stmt->fetchColumn() : date('Y-m-d H:i:s', time());

	// Get occupied systems
	$query = 'SELECT systemID, COUNT(DISTINCT characterID) AS count FROM active WHERE maskID = :maskID AND systemID IS NOT NULL GROUP BY systemID';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
	$stmt->execute();
	$output['chain']['occupied'] = $stmt->fetchAll(PDO::FETCH_CLASS);

	// Get flares
	$query = 'SELECT systemID, flare, time FROM flares WHERE maskID = :maskID';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':maskID', $maskID, PDO::PARAM_INT);
	$stmt->execute();
	$result = $stmt->fetchAll(PDO::FETCH_CLASS);
	$output['chain']['flares']['flares'] = $result;
	$output['chain']['flares']['last_modified'] = date('m/d/Y H:i:s e', $result ? strtotime($result[0]->time) : time());

	// Get Comments
	$query = 'SELECT id, comment, created AS createdDate, c.characterName AS createdBy, modified AS modifiedDate, m.characterName AS modifiedBy, systemID FROM comments LEFT JOIN characters c ON createdBy = c.characterID LEFT JOIN characters m ON modifiedBy = m.characterID WHERE (systemID = :systemID OR systemID = 0) AND maskID = :maskID ORDER BY systemID ASC, modified ASC';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':systemID', $systemID, PDO::PARAM_INT);
	$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
	$stmt->execute();
	while ($row = $stmt->fetchObject()) {
		$output['comments'][] = array('id' => $row->id, 'comment' => $row->comment, 'created' => $row->createdDate, 'createdBy' => $row->createdBy, 'modified' => $row->modifiedDate, 'modifiedBy' => $row->modifiedBy, 'sticky' => $row->systemID == 0 ? true : false);
	}
} else if ((isset($_REQUEST['mode']) && ($_REQUEST['mode'] == 'refresh') || $refresh['sigUpdate'] == true || $refresh['chainUpdate'] == true)) {
	$sigCount 		= isset($_REQUEST['sigCount']) ? $_REQUEST['sigCount'] : null;
	$sigTime 		= isset($_REQUEST['sigTime']) ? $_REQUEST['sigTime'] : null;
	$chainCount = isset($_REQUEST['chainCount'])?$_REQUEST['chainCount']:null;
	$chainTime = isset($_REQUEST['chainTime'])?$_REQUEST['chainTime']:null;
	$flareCount = isset($_REQUEST['flareCount'])?$_REQUEST['flareCount']:null;
	$flareTime = isset($_REQUEST['flareTime'])?$_REQUEST['flareTime']:null;
	$commentCount = isset($_REQUEST['commentCount'])?$_REQUEST['commentCount']:null;
	$commentTime = isset($_REQUEST['commentTime'])?$_REQUEST['commentTime']:null;
	$systemID = isset($_REQUEST['systemID'])?$_REQUEST['systemID']:$data->systemID;

	// Check if signatures changed....
	$query = 'SELECT COUNT(id) AS count, MAX(time) AS modified FROM signatures WHERE (systemID = :systemID OR connectionID = :systemID) AND mask = :mask';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':systemID', $systemID, PDO::PARAM_INT);
	$stmt->bindValue(':mask', $maskID, PDO::PARAM_INT);
	$stmt->execute();

	$row = $stmt->fetchObject();
	if ($sigCount != (int)$row->count || strtotime($sigTime) < strtotime($row->modified)) {
		$refresh['sigUpdate'] = true;
	}

	if ($refresh['sigUpdate'] == true) {
		$output['signatures'] = Array();

		$query = 'SELECT * FROM signatures WHERE (systemID = :systemID OR connectionID = :systemID) AND mask = :mask';
		$stmt = $mysql->prepare($query);
		$stmt->bindValue(':systemID', $systemID, PDO::PARAM_INT);
		$stmt->bindValue(':mask', $maskID, PDO::PARAM_INT);
		$stmt->execute();

		while ($row = $stmt->fetchObject()) {
			$row->lifeTime = date('m/d/Y H:i:s e', strtotime($row->lifeTime));
			$row->lifeLeft = date('m/d/Y H:i:s e', strtotime($row->lifeLeft));
			$row->time = date('m/d/Y H:i:s e', strtotime($row->time));

			$output['signatures'][$row->id] = $row;
		}
	}

	// Check if chain changed....
	if ($chainCount !== null && $chainTime !== null) {
		$query = 'SELECT COUNT(id) AS chainCount, MAX(time) as chainTime FROM signatures WHERE life IS NOT NULL AND (mask = :mask OR ((signatures.systemID = 31000005 OR signatures.connectionID = 31000005) AND mask = 273))';
		$stmt = $mysql->prepare($query);
		$stmt->bindValue(':mask', $maskID, PDO::PARAM_INT);
		$stmt->execute();
		$row = $stmt->fetchObject();

		if ($row && $row->chainCount != $chainCount) {
			$refresh['chainUpdate'] = true;
		} else if ($row && $row->chainTime && $row->chainTime != $chainTime) {
			$refresh['chainUpdate'] = true;
		}
	}

	if ($refresh['chainUpdate'] == true) {
		$output['chain']['map'] = Array();

		$query = "SELECT DISTINCT signatures.id, signatureID, system, systemID, connection, connectionID, sig2ID, type, nth, sig2Type, nth2, lifeLength, life, mass, time, typeBM, type2BM, classBM, class2BM, mask FROM signatures WHERE life IS NOT NULL AND (mask = :mask OR ((signatures.systemID = 31000005 OR signatures.connectionID = 31000005) AND mask = 273)) ORDER BY id ASC";
		$stmt = $mysql->prepare($query);
		$stmt->bindValue(':mask', $maskID, PDO::PARAM_STR);
		$stmt->execute();

		$output['chain']['map'] = $stmt->fetchAll(PDO::FETCH_CLASS);

		// System activity indicators
		$query = 'SELECT DISTINCT api.systemID, shipJumps, podKills, shipKills, npcKills, mask FROM signatures sigs INNER JOIN eve_api.recentActivity api ON connectionID = api.systemID OR sigs.systemID = api.systemID WHERE life IS NOT NULL AND (mask = :mask OR ((sigs.systemID = 31000005 OR sigs.connectionID = 31000005) AND mask = 273))';
		$stmt = $mysql->prepare($query);
		$stmt->bindValue(':mask', $maskID, PDO::PARAM_INT);
		$stmt->execute();

		$output['chain']['activity'] = $stmt->fetchAll(PDO::FETCH_CLASS);

		$query = 'SELECT MAX(time) AS last_modified FROM signatures WHERE life IS NOT NULL AND (mask = :mask OR ((signatures.systemID = 31000005 OR signatures.connectionID = 31000005) AND mask = 273))';
		$stmt = $mysql->prepare($query);
		$stmt->bindValue(':mask', $maskID, PDO::PARAM_STR);
		$stmt->execute();

		$output['chain']['last_modified'] = $stmt->fetchColumn();
	}

	// Get flares
	if (isset($output['chain']) || ($flareCount != null && $flareTime != null)) {
		$query = 'SELECT systemID, flare, time FROM flares WHERE maskID = :maskID ORDER BY time DESC';
		$stmt = $mysql->prepare($query);
		$stmt->bindValue(':maskID', $maskID, PDO::PARAM_INT);
		$stmt->execute();
		$result = $stmt->fetchAll(PDO::FETCH_CLASS);
		if (isset($output['chain']) || (count($result) != $flareCount || ($result && strtotime($result[0]->time) < strtotime($flareTime)))) {
			$output['chain']['flares']['flares'] = $result;
			$output['chain']['flares']['last_modified'] = date('m/d/Y H:i:s e', $result ? strtotime($result[0]->time) : time());
		}
	}

	// Get occupied systems
	$query = 'SELECT systemID, COUNT(DISTINCT characterID) AS count FROM active WHERE maskID = :maskID AND systemID IS NOT NULL GROUP BY systemID';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
	$stmt->execute();
	if ($result = $stmt->fetchAll(PDO::FETCH_CLASS)) {
		$output['chain']['occupied'] = $result;
	}

	// Check Comments
	$query = 'SELECT COUNT(id) AS count, MAX(modified) AS modified FROM comments WHERE (systemID = :systemID OR systemID = 0) AND maskID = :maskID';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':systemID', $systemID, PDO::PARAM_INT);
	$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
	$stmt->execute();
	$row = $stmt->fetch(PDO::FETCH_OBJ);
	if ($commentCount != (int)$row->count || strtotime($commentTime) < strtotime($row->modified)) {
		$output['comments'] = array();
		// Get Comments
		$query = 'SELECT id, comment, created AS createdDate, c.characterName AS createdBy, modified AS modifiedDate, m.characterName AS modifiedBy, systemID FROM comments LEFT JOIN characters c ON createdBy = c.characterID LEFT JOIN characters m ON modifiedBy = m.characterID WHERE (systemID = :systemID OR systemID = 0) AND maskID = :maskID ORDER BY systemID ASC, modified ASC';
		$stmt = $mysql->prepare($query);
		$stmt->bindValue(':systemID', $systemID, PDO::PARAM_INT);
		$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
		$stmt->execute();
		while ($row = $stmt->fetchObject()) {
			$output['comments'][] = array('id' => $row->id, 'comment' => $row->comment, 'created' => $row->createdDate, 'createdBy' => $row->createdBy, 'modified' => $row->modifiedDate, 'modifiedBy' => $row->modifiedBy, 'sticky' => $row->systemID == 0 ? true : false);
		}
	}
}

/*
========
========
!!ALTS!!
========
========
*/


if(isset($_SESSION['altIDs'])){
  $curaltIDs = json_decode($_SESSION['altIDs']);
  for($i = 0; $i < count(json_decode($_SESSION['altIDs'],true)); $i++){
    //Check and refresh token if needed.
    $curAlt = json_decode($curaltIDs->$i);


    $query = 'SELECT accessToken, refreshToken, tokenExpire FROM crest WHERE characterID = :characterID';
    $stmt = $mysql->prepare($query);
    $stmt->bindValue(':characterID', $curAlt->charID, PDO::PARAM_INT);
    $stmt->execute();
    if ($row = $stmt->fetchObject()) {
      if (strtotime($row->tokenExpire) < time('-1 minute')) {
        // Get a new access token
        $crestAlt = new CREST();

        if ($crestAlt->refresh($row->refreshToken)) {
          $query = 'UPDATE crest SET accessToken = :accessToken, refreshToken = :refreshToken, tokenExpire = :tokenExpire WHERE characterID = :characterID';
          $stmt = $mysql->prepare($query);
          $stmt->bindValue(':accessToken', $crestAlt->accessToken, PDO::PARAM_STR);
          $stmt->bindValue(':refreshToken', $crestAlt->refreshToken, PDO::PARAM_STR);
          $stmt->bindValue(':tokenExpire', $crestAlt->tokenExpire, PDO::PARAM_STR);
          $stmt->bindValue(':characterID', $curAlt->charID, PDO::PARAM_STR);
          $stmt->execute();

          $curAlt->accessToken = $crestAlt->accessToken;
        }
        else {
          $query = 'DELETE FROM crest WHERE characterID = :characterID';
          $stmt = $mysql->prepare($query);
          $stmt->bindValue(':characterID', $curAlt->charID, PDO::PARAM_INT);
          $stmt->execute();
          $curAlt->accessToken = null;
        }
      }
    }

    $ipAlt         = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : die();
    $instanceAlt     = isset($_REQUEST['instance']) ? $_REQUEST['instance'] : 0;
    $versionAlt     = isset($_SERVER['SERVER_NAME'])? explode('.', $_SERVER['SERVER_NAME'])[0] : die();
    $userIDAlt       = isset($_SESSION['userID']) ? $_SESSION['userID'] : die();
    $maskIDAlt       = isset($_SESSION['mask']) ? $_SESSION['mask'] : die();
    $characterIDAlt    = isset($curAlt->charID) ? $curAlt->charID : null;
    $characterNameAlt    = isset($curAlt->charName) ? $curAlt->charName : null;
    $systemIDAlt      = isset($curAlt->systemID) ? $curAlt->systemID : null;
    $systemNameAlt    = isset($curAlt->systemName) ? $curAlt->systemName : null;
    $shipIDAlt      = isset($curAlt->shipID) ? $curAlt->shipID : null;
    $shipNameAlt      = isset($curAlt->shipName) ? $curAlt->shipName : null;
    $shipTypeIDAlt    = isset($curAlt->shipTypeID) ? $curAlt->shipTypeID : null;
    $shipTypeNameAlt    = isset($curAlt->shipTypeName) ? $curAlt->shipTypeName : null;
    $stationIDAlt      = isset($curAlt->stationID) ? $curAlt->stationID : null;
    $stationNameAlt    = isset($curAlt->stationName) ? $curAlt->stationName : null;
    $activityAlt     = isset($_REQUEST['activity']) ? json_encode($_REQUEST['activity']) : null;

    $output['Alts'][] = $curAlt;
    //Place Alt Info


    $query = 'INSERT INTO active (ip, instance, session, userID, maskID, characterID, characterName, systemID, systemName, shipID, shipName, shipTypeID, shipTypeName, stationID, stationName, activity, version)
        VALUES (:ip, :instance, :session, :userID, :maskID, :characterID, :characterName, :systemID, :systemName, :shipID, :shipName, :shipTypeID, :shipTypeName, :stationID, :stationName, :activity, :version)
        ON DUPLICATE KEY UPDATE
        maskID = :maskID, characterID = :characterID, characterName = :characterName, systemID = :systemID, systemName = :systemName, shipID = :shipID, shipName = :shipName, shipTypeID = :shipTypeID, shipTypeName = :shipTypeName, stationID = :stationID, stationName = :stationName, activity = :activity, version = :version, time = NOW(), notify = NULL';
    $stmt = $mysql->prepare($query);
    $stmt->bindValue(':ip', $ipAlt , PDO::PARAM_STR);
    $stmt->bindValue(':instance', $instanceAlt , PDO::PARAM_STR);
    $stmt->bindValue(':session', session_id(), PDO::PARAM_STR);
    $stmt->bindValue(':userID', $userIDAlt , PDO::PARAM_INT);
    $stmt->bindValue(':maskID', $maskIDAlt , PDO::PARAM_STR);
    $stmt->bindValue(':characterID', $characterIDAlt , PDO::PARAM_INT);
    $stmt->bindValue(':characterName', $characterNameAlt , PDO::PARAM_STR);
    $stmt->bindValue(':systemID', $systemIDAlt , PDO::PARAM_INT);
    $stmt->bindValue(':systemName', $systemNameAlt , PDO::PARAM_STR);
    $stmt->bindValue(':shipID', $shipIDAlt , PDO::PARAM_INT);
    $stmt->bindValue(':shipName', $shipNameAlt , PDO::PARAM_STR);
    $stmt->bindValue(':shipTypeID', $shipTypeIDAlt , PDO::PARAM_INT);
    $stmt->bindValue(':shipTypeName', $shipTypeNameAlt , PDO::PARAM_STR);
    $stmt->bindValue(':stationID', $stationIDAlt , PDO::PARAM_INT);
    $stmt->bindValue(':stationName', $stationNameAlt , PDO::PARAM_STR);
    $stmt->bindValue(':activity', $activityAlt , PDO::PARAM_STR);
    $stmt->bindValue(':version', $versionAlt , PDO::PARAM_STR);
    $stmt->execute();

    $curaltIDs->$i = json_encode($curAlt,JSON_FORCE_OBJECT);
  }
  $_SESSION['altIDs'] = json_encode($curaltIDs,JSON_FORCE_OBJECT);
}

$output['proccessTime'] = sprintf('%.4f', microtime(true) - $startTime);
echo json_encode($output);
?>

<?php
//***********************************************************
//	File: 		comments.php
//	Author: 	Daimian
//	Created: 	12/08/2014
//	Modified: 	12/12/2014 - Daimian
//
//	Purpose:	Handles saving/editing/deleting comments.
//
//	ToDo:
//
//***********************************************************
if (!session_id()) session_start();
session_write_close();

if(!isset($_SESSION['username'])) {
	exit();
}

$startTime = microtime(true);

require('db.inc.php');
require_once('HTMLPurifier.auto.php');

header('Content-Type: application/json');

$maskID = 		$_SESSION['mask'];
$characterID = 	$_SESSION['characterID'];
$systemID = 	isset($_REQUEST['systemID']) ? $_REQUEST['systemID'] : null;
$commentID = 	isset($_REQUEST['commentID']) ? $_REQUEST['commentID'] : null;
$mode = 		isset($_REQUEST['mode']) ? $_REQUEST['mode'] : null;
$output = 		null;

// HTML Purify
if (isset($_REQUEST['comment'])) {
	$config = HTMLPurifier_Config::createDefault();
	$purifier = new HTMLPurifier($config);
	$comment = $purifier->purify($_REQUEST['comment']);
} else {
	$comment = null;
}

// Check if comment exists
$possible_modes = array("save", "delete", "sticky");
if ($commentID && in_array($mode, $possible_modes))
{
	$query = 'SELECT systemID, comment, created, createdBy, modified, modifiedBy FROM comments WHERE id = :commentID AND maskID = :maskID';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':commentID', $commentID, PDO::PARAM_INT);
	$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
	$stmt->execute();
	$row = $stmt->fetchObject();
	if ($row)
	{
		// Comment exists, proceed to log the current comment before modification request
		$query = 'INSERT INTO _history_comments (id, systemID, comment, created, createdBy, modified, modifiedBy, maskID, requested, requestedBy, mode)
					VALUES (:commentID, :systemID, :comment, :created, :createdBy, :modified, :modifiedBy, :maskID, NOW(), :requestedBy, :mode)';
		$stmt2 = $mysql->prepare($query);
		$stmt2->bindValue(':commentID', $commentID, PDO::PARAM_INT);
		$stmt2->bindValue(':systemID', $row->systemID, PDO::PARAM_INT);
		$stmt2->bindValue(':comment', $row->comment, PDO::PARAM_STR);
		$stmt2->bindValue(':created', $row->created, PDO::PARAM_STR);
		$stmt2->bindValue(':createdBy', $row->createdBy, PDO::PARAM_INT);
		$stmt2->bindValue(':modified', $row->modified, PDO::PARAM_STR);
		$stmt2->bindValue(':modifiedBy', $row->modifiedBy, PDO::PARAM_INT);
		$stmt2->bindValue(':maskID', $maskID, PDO::PARAM_STR);
		$stmt2->bindValue(':requestedBy', $characterID, PDO::PARAM_INT);
		$stmt2->bindValue(':mode', $mode, PDO::PARAM_STR);
		$stmt2->execute();
	}
}

if ($mode == 'save') {
	$query = 'INSERT INTO comments (id, systemID, comment, created, createdBy, modifiedBy, maskID)
				VALUES (:commentID, :systemID, :comment, NOW(), :createdBy, :modifiedBy, :maskID)
				ON DUPLICATE KEY UPDATE
				systemID = :systemID, comment = :comment, modifiedBy = :modifiedBy, modified = NOW()';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':commentID', $commentID, PDO::PARAM_INT);
	$stmt->bindValue(':systemID', $systemID, PDO::PARAM_INT);
	$stmt->bindValue(':comment', $comment, PDO::PARAM_STR);
	$stmt->bindValue(':createdBy', $characterID, PDO::PARAM_INT);
	$stmt->bindValue(':modifiedBy', $characterID, PDO::PARAM_INT);
	$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
	$output['result'] = $stmt->execute();

	if ($output['result']) {
		$query = 'SELECT id, created AS createdDate, c.characterName AS createdBy, modified AS modifiedDate, m.characterName AS modifiedBy FROM comments LEFT JOIN characters c ON createdBy = c.characterID LEFT JOIN characters m ON modifiedBy = m.characterID WHERE id = :commentID AND maskID = :maskID';
		$stmt = $mysql->prepare($query);
		$stmt->bindValue(':commentID', ($commentID ? $commentID : $mysql->lastInsertId()), PDO::PARAM_INT);
		$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
		$stmt->execute();
		$output['comment'] = $stmt->fetchObject();
	}
} else if ($mode == 'delete' && $commentID) {
	$query = 'DELETE FROM comments WHERE id = :commentID AND maskID = :maskID';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':commentID', $commentID, PDO::PARAM_INT);
	$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
	$output['result'] = $stmt->execute();
} else if ($mode == 'sticky' && $commentID) {
	$query = 'UPDATE comments SET systemID = :systemID WHERE id = :commentID AND maskID = :maskID';
	$stmt = $mysql->prepare($query);
	$stmt->bindValue(':commentID', $commentID, PDO::PARAM_INT);
	$stmt->bindValue(':systemID', $systemID, PDO::PARAM_INT);
	$stmt->bindValue(':maskID', $maskID, PDO::PARAM_STR);
	$output['result'] = $stmt->execute();
}


$output['proccessTime'] = sprintf('%.4f', microtime(true) - $startTime);

echo json_encode($output);
?>

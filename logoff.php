<?php
if (!session_id()) session_start();

  if(isset($_REQUEST['altNum'])){
    $altNum = $_REQUEST['altNum'];
    $curaltIDs = json_decode($_SESSION['altIDs'],true);
    array_splice($curaltIDs,$altNum,1);
    $_SESSION['altIDs'] = json_encode($curaltIDs,JSON_FORCE_OBJECT);
    header('Location: ./?system='.$_SESSION['altIDs']);
    exit();
  } 
  header('Location: ./?system=Failed');
  exit();

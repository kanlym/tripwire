<?php

// EVE SDE table name
$eve_dump = 'eve_sde';

// Set php timezone to EVE time
date_default_timezone_set('UTC');

// CREST info
$crestClient = 'clientID';
$crestSecret = 'secret';
$crestUrl = 'http://localhost/login.php?mode=sso';

// Login management
$apiLoginEnabled = True;

try {
    $mysql = new PDO(
        'mysql:host=localhost;dbname=tripwire_database;charset=utf8',
        'username',
        'password',
        Array(
            PDO::ATTR_PERSISTENT     => true,
            PDO::MYSQL_ATTR_LOCAL_INFILE => true
        )
    );
    // Set MySQL timezone to EVE time
    $mysql->exec("SET time_zone='+00:00';");
} catch (PDOException $error) {
    echo 'DB error';//$error;
}

?>

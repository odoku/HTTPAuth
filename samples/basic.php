<?php

require_once '../HTTPAuth.php';

function getPassword($id) {
	if (strcmp($id, 'foo') === 0) {
		return 'bar';
	} else {
		return false;
	}
}

$realm = 'Please input your account & password';

if (!HTTPAuth::basic($realm, 'getPassword')) {
	$message = 'Unauthorized';
} else {
	$message = 'Authorized';
};

?><!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
	"http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
	<meta http-equiv="Content-type" content="text/html; charset=utf-8">
	<title>HTTP Auth for PHP5 Sample</title>
</head>
<body>
	<h1>HTTP Auth for PHP5 Sample</h1>
	<p><?php echo htmlspecialchars($message); ?></p>
</body>
</html>

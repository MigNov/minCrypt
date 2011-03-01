<?php
	function bail($msg, $error_code = 1)
	{
		printf("[Error $error_code] $msg\n");
		exit($error_code);
	}

	function success($name = false) {
		if ($name == false)
			bail("Invalid test name!");

		printf("Test $name has been completed successfully\n");
		exit(0);
	}

	if (!extension_loaded('mincrypt')) {
		if (!dl('../php/mincrypt-php.so'))
			bail('Cannot load mincrypt-php extension. Please install mincrypt-php first (using `make install`)');
	}
?>
